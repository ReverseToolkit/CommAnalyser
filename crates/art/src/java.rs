//! Minimal Java reflection/call layer on top of JNI.
//!
//! This is the foundation for `Java.use`: it discovers methods and
//! constructors, keeps global references, and marshals the common
//! int/long/boolean/String/object signatures.  Hooking lives in `lib.rs`.

use std::ptr;
use std::rc::Rc;
use std::sync::OnceLock;

use jni::ids::{JFieldID, JMethodID, JStaticFieldID, JStaticMethodID};
use jni::objects::{Global, JClass, JObject, JObjectArray, JString};
use jni::refs::Reference as _;
use jni::signature::{JavaType, Primitive, RuntimeMethodSignature};
use jni::strings::JNIString;
use jni::sys::{jint, jsize, jvalue, JavaVM as RawJavaVM};
use jni::JValue;
use jni::{Env, JavaVM};

use runtime::{Error, Result};

type GetCreatedJavaVms = unsafe extern "C" fn(*mut *mut RawJavaVM, jsize, *mut jsize) -> jint;

/// Process-wide JavaVM handle.
pub struct JavaVm {
    raw: *mut RawJavaVM,
}

// The JavaVM outlives every attachment and JNI says it is shareable.
unsafe impl Send for JavaVm {}
unsafe impl Sync for JavaVm {}

impl JavaVm {
    pub fn get() -> Result<&'static Self> {
        static VM: OnceLock<JavaVm> = OnceLock::new();
        if let Some(vm) = VM.get() {
            return Ok(vm);
        }
        let raw = created_java_vm()?;
        let _ = VM.set(JavaVm { raw });
        Ok(VM.get().expect("JavaVm was just initialized"))
    }

    pub fn with_env<T>(&self, f: impl FnOnce(&mut Env<'_>) -> jni::errors::Result<T>) -> Result<T> {
        // SAFETY: the raw pointer came from JNI_GetCreatedJavaVMs and remains
        // valid for the process lifetime.
        let vm = unsafe { JavaVM::from_raw(self.raw) };
        vm.attach_current_thread(f)
            .map_err(|err| Error::Parse(format!("JNI: {err}")))
    }
}

#[derive(Clone, Debug)]
pub enum Kind {
    Void,
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object(String),
    Array(String),
}

#[derive(Clone, Copy)]
pub enum MethodId {
    Instance(JMethodID),
    Static(JStaticMethodID),
}

impl MethodId {
    pub fn raw(self) -> usize {
        match self {
            Self::Instance(id) => id.into_raw() as usize,
            Self::Static(id) => id.into_raw() as usize,
        }
    }
}

#[derive(Clone)]
pub struct MethodInfo {
    pub name: String,
    pub signature: String,
    pub id: MethodId,
    pub is_static: bool,
    pub params: Vec<Kind>,
    pub ret: Kind,
}

#[derive(Clone, Copy)]
pub enum FieldId {
    Instance(JFieldID),
    Static(JStaticFieldID),
}

#[derive(Clone)]
pub struct FieldInfo {
    pub name: String,
    pub id: FieldId,
    pub kind: Kind,
    pub is_static: bool,
    pub is_public: bool,
}

#[derive(Clone)]
pub struct CtorInfo {
    pub id: JMethodID,
    pub params: Vec<Kind>,
    pub signature: String,
    pub is_public: bool,
}

pub struct ClassInfo {
    pub name: String,
    pub methods: Vec<MethodInfo>,
    pub ctors: Vec<CtorInfo>,
    pub fields: Vec<FieldInfo>,
}

pub struct JavaClass {
    pub info: Rc<ClassInfo>,
    class: Global<JClass<'static>>,
}

pub struct JavaObject {
    pub info: Rc<ClassInfo>,
    object: Global<JObject<'static>>,
}

pub enum JavaArg {
    Boolean(bool),
    Int(i32),
    Long(i64),
    String(String),
    Object(Rc<JavaObject>),
    Null,
}

pub enum JavaValue {
    Void,
    Boolean(bool),
    Int(i32),
    Long(i64),
    String(String),
    Object(Global<JObject<'static>>),
}

impl JavaClass {
    pub fn find(name: &str) -> Result<Rc<Self>> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let slash_name = JNIString::new(name.replace('.', "/"));
            let local = match env.find_class(&*slash_name) {
                Ok(local) => local,
                Err(error) => {
                    // FindClass on a native-attached thread only sees the boot
                    // class loader.  Fall back to the app's ClassLoader.
                    env.exception_clear();
                    let _ = error;
                    find_via_app_loader(env, name)?
                }
            };
            let global = env.new_global_ref(&local)?;
            let info = reflect(env, &local, name)?;
            Ok(Rc::new(Self {
                info: Rc::new(info),
                class: global,
            }))
        })
    }

    pub fn new_object(&self, args: &[JavaArg]) -> Result<JavaObject> {
        let ctor = self
            .info
            .ctors
            .iter()
            .find(|ctor| ctor.params.len() == args.len())
            .ok_or_else(|| Error::NotFound("matching Java constructor".into()))?;
        self.new_object_with(ctor, args)
    }

    /// Construct using an already-selected constructor.  The JS `$new`
    /// overload selection must be preserved; re-selecting by arity alone picks
    /// `(I)V` for `StringBuilder("abc")`.
    pub fn new_object_with(&self, ctor: &CtorInfo, args: &[JavaArg]) -> Result<JavaObject> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let signature = RuntimeMethodSignature::from_str(&ctor.signature)?;
            let object = new_object_with_values(
                env,
                &self.class,
                signature.method_signature(),
                &ctor.params,
                args,
            )?;
            let global = env.new_global_ref(&object)?;
            Ok(JavaObject {
                info: self.info.clone(),
                object: global,
            })
        })
    }

    pub fn get_static_field(&self, field: &FieldInfo) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let FieldId::Static(id) = field.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            // SAFETY: the field id came from this class and the return type
            // matches the reflected field type.
            let value = unsafe {
                env.get_static_field_unchecked(&self.class, id, return_type(&field.kind))?
            };
            convert(env, &field.kind, value)
        })
    }

    pub fn call_static(&self, method: &MethodInfo, args: &[JavaArg]) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let (raw, _strings) = marshal(env, &method.params, args)?;
            // SAFETY: method.id came from this class and the return type is
            // the one declared by the method.
            let MethodId::Static(id) = method.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            let value = unsafe {
                env.call_static_method_unchecked(&self.class, id, return_type(&method.ret), &raw)?
            };
            convert(env, &method.ret, value)
        })
    }
}

impl JavaObject {
    pub fn from_global(info: Rc<ClassInfo>, object: Global<JObject<'static>>) -> Self {
        Self { info, object }
    }

    pub fn as_obj(&self) -> &JObject<'static> {
        self.object.as_obj()
    }

    pub fn call(&self, method: &MethodInfo, args: &[JavaArg]) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let (raw, _strings) = marshal(env, &method.params, args)?;
            // SAFETY: method.id came from the object's class and the return
            // type is the one declared by the method.
            let MethodId::Instance(id) = method.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            let value = unsafe {
                env.call_method_unchecked(&self.object, id, return_type(&method.ret), &raw)?
            };
            convert(env, &method.ret, value)
        })
    }
}

enum ArgSlot {
    Boolean(bool),
    Byte(i8),
    Char(u16),
    Short(i16),
    Int(i32),
    Long(i64),
    Object(usize),
}

fn new_object_with_values<'a>(
    env: &mut Env<'a>,
    class: &JClass<'a>,
    signature: jni::signature::MethodSignature<'_, '_>,
    params: &[Kind],
    args: &[JavaArg],
) -> jni::errors::Result<JObject<'a>> {
    if params.len() != args.len() {
        return Err(jni::errors::Error::JniCall(
            jni::errors::JniError::InvalidArguments,
        ));
    }
    let mut objects: Vec<JObject<'a>> = Vec::new();
    let mut slots = Vec::with_capacity(args.len());
    for (kind, arg) in params.iter().zip(args) {
        let slot = match (kind, arg) {
            (Kind::Boolean, JavaArg::Boolean(value)) => ArgSlot::Boolean(*value),
            (Kind::Byte, JavaArg::Int(value)) => ArgSlot::Byte(*value as i8),
            (Kind::Char, JavaArg::Int(value)) => ArgSlot::Char(*value as u16),
            (Kind::Short, JavaArg::Int(value)) => ArgSlot::Short(*value as i16),
            (Kind::Int, JavaArg::Int(value)) => ArgSlot::Int(*value),
            (Kind::Long, JavaArg::Long(value)) => ArgSlot::Long(*value),
            (Kind::Object(_), JavaArg::String(value)) => {
                let string = env.new_string(value)?;
                objects.push(JObject::from(string));
                ArgSlot::Object(objects.len() - 1)
            }
            (Kind::Object(_), JavaArg::Object(object)) => {
                // SAFETY: the global reference is valid for this call.
                let local = unsafe { JObject::from_raw(env, object.as_obj().as_raw()) };
                objects.push(local);
                ArgSlot::Object(objects.len() - 1)
            }
            (Kind::Object(_), JavaArg::Null) => {
                // SAFETY: a null object reference is valid for a reference
                // parameter.
                let local = unsafe { JObject::from_raw(env, ptr::null_mut()) };
                objects.push(local);
                ArgSlot::Object(objects.len() - 1)
            }
            _ => {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ))
            }
        };
        slots.push(slot);
    }
    let values: Vec<JValue<'_>> = slots
        .iter()
        .map(|slot| match slot {
            ArgSlot::Boolean(value) => JValue::Bool(*value),
            ArgSlot::Byte(value) => JValue::Byte(*value),
            ArgSlot::Char(value) => JValue::Char(*value),
            ArgSlot::Short(value) => JValue::Short(*value),
            ArgSlot::Int(value) => JValue::Int(*value),
            ArgSlot::Long(value) => JValue::Long(*value),
            ArgSlot::Object(index) => JValue::Object(&objects[*index]),
        })
        .collect();
    env.new_object(class, signature, &values)
}

fn created_java_vm() -> Result<*mut RawJavaVM> {
    // SAFETY: dlsym returns the JNI entrypoint exported by libart.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"JNI_GetCreatedJavaVMs".as_ptr()) };
    if symbol.is_null() {
        return Err(Error::NotFound("JNI_GetCreatedJavaVMs".into()));
    }
    // SAFETY: signature matches JNIInvokeInterface.
    let get: GetCreatedJavaVms = unsafe { std::mem::transmute(symbol) };
    let mut vm: *mut RawJavaVM = ptr::null_mut();
    let mut count: jsize = 0;
    // SAFETY: pointers are valid stack slots.
    let rc = unsafe { get(&mut vm, 1, &mut count) };
    if rc != 0 || count == 0 || vm.is_null() {
        return Err(Error::NotFound("no created JavaVM".into()));
    }
    Ok(vm)
}

fn find_via_app_loader<'a>(env: &mut Env<'a>, name: &str) -> jni::errors::Result<JClass<'a>> {
    let loader = app_class_loader(env)?;
    let class_name = env.new_string(name)?;
    let class_name = JObject::from(class_name);
    let signature = RuntimeMethodSignature::from_str("(Ljava/lang/String;)Ljava/lang/Class;")?;
    let name = JNIString::new("loadClass");
    let value = env.call_method(
        &loader,
        &*name,
        signature.method_signature(),
        &[JValue::Object(&class_name)],
    )?;
    let class = value.l()?;
    if class.is_null() {
        return Err(jni::errors::Error::NullPtr("loadClass returned null"));
    }
    // SAFETY: loadClass returns java.lang.Class.
    Ok(unsafe { JClass::from_raw(env, class.as_raw()) })
}

fn app_class_loader<'a>(env: &mut Env<'a>) -> jni::errors::Result<JObject<'a>> {
    let activity_thread = env.find_class(&*JNIString::new("android/app/ActivityThread"))?;
    let current_app_sig = RuntimeMethodSignature::from_str("()Landroid/app/Application;")?;
    let current_app = JNIString::new("currentApplication");
    let app = env
        .call_static_method(
            &activity_thread,
            &*current_app,
            current_app_sig.method_signature(),
            &[],
        )?
        .l()?;
    let loader_sig = RuntimeMethodSignature::from_str("()Ljava/lang/ClassLoader;")?;
    let get_loader = JNIString::new("getClassLoader");
    if !app.is_null() {
        return env
            .call_method(&app, &*get_loader, loader_sig.method_signature(), &[])?
            .l();
    }
    let thread = env.find_class(&*JNIString::new("java/lang/Thread"))?;
    let current_thread_sig = RuntimeMethodSignature::from_str("()Ljava/lang/Thread;")?;
    let current_thread = JNIString::new("currentThread");
    let thread = env
        .call_static_method(
            &thread,
            &*current_thread,
            current_thread_sig.method_signature(),
            &[],
        )?
        .l()?;
    let context_loader = JNIString::new("getContextClassLoader");
    env.call_method(
        &thread,
        &*context_loader,
        loader_sig.method_signature(),
        &[],
    )?
    .l()
}

fn reflect(
    env: &mut Env<'_>,
    class: &JClass<'_>,
    fallback_name: &str,
) -> jni::errors::Result<ClassInfo> {
    let name = string_call(env, class, "getName")?.unwrap_or_else(|| fallback_name.to_owned());
    let mut methods = Vec::new();
    let methods_array = object_call(
        env,
        class,
        "getDeclaredMethods",
        "()[Ljava/lang/reflect/Method;",
    )?;
    for method in array_elements(env, &methods_array)? {
        let method_name = string_call(env, &method, "getName")?.unwrap_or_default();
        let param_types = object_call(env, &method, "getParameterTypes", "()[Ljava/lang/Class;")?;
        let params = array_elements(env, &param_types)?
            .iter()
            .map(|class_obj| class_kind(env, class_obj))
            .collect::<jni::errors::Result<Vec<_>>>()?;
        let ret_obj = object_call(env, &method, "getReturnType", "()Ljava/lang/Class;")?;
        let ret = class_kind(env, &ret_obj)?;
        let modifiers = int_call(env, &method, "getModifiers")?;
        let is_static = modifiers & 0x0008 != 0;
        let signature = format!("({}){}", descriptors(&params), descriptor(&ret));
        let name_c = JNIString::new(&method_name);
        let signature_c = RuntimeMethodSignature::from_str(&signature)?;
        let id = if is_static {
            MethodId::Static(env.get_static_method_id(
                class,
                &*name_c,
                signature_c.method_signature(),
            )?)
        } else {
            MethodId::Instance(env.get_method_id(
                class,
                &*name_c,
                signature_c.method_signature(),
            )?)
        };
        methods.push(MethodInfo {
            name: method_name,
            signature,
            id,
            is_static,
            params,
            ret,
        });
    }

    let mut ctors = Vec::new();
    let ctors_array = object_call(
        env,
        class,
        "getDeclaredConstructors",
        "()[Ljava/lang/reflect/Constructor;",
    )?;
    for ctor in array_elements(env, &ctors_array)? {
        let param_types = object_call(env, &ctor, "getParameterTypes", "()[Ljava/lang/Class;")?;
        let params = array_elements(env, &param_types)?
            .iter()
            .map(|class_obj| class_kind(env, class_obj))
            .collect::<jni::errors::Result<Vec<_>>>()?;
        let modifiers = int_call(env, &ctor, "getModifiers")?;
        let is_public = modifiers & 0x0001 != 0;
        let signature = format!("({})V", descriptors(&params));
        let init = JNIString::new("<init>");
        let signature_c = RuntimeMethodSignature::from_str(&signature)?;
        let id = env.get_method_id(class, &*init, signature_c.method_signature())?;
        ctors.push(CtorInfo {
            id,
            params,
            signature,
            is_public,
        });
    }

    let mut fields = Vec::new();
    let fields_array = object_call(
        env,
        class,
        "getDeclaredFields",
        "()[Ljava/lang/reflect/Field;",
    )?;
    for field in array_elements(env, &fields_array)? {
        let field_name = string_call(env, &field, "getName")?.unwrap_or_default();
        let type_obj = object_call(env, &field, "getType", "()Ljava/lang/Class;")?;
        let kind = class_kind(env, &type_obj)?;
        let modifiers = int_call(env, &field, "getModifiers")?;
        let is_static = modifiers & 0x0008 != 0;
        let is_public = modifiers & 0x0001 != 0;
        let signature = descriptor(&kind);
        let name_c = JNIString::new(&field_name);
        let signature_c = jni::signature::RuntimeFieldSignature::from_str(&signature)?;
        let id = if is_static {
            FieldId::Static(env.get_static_field_id(
                class,
                &*name_c,
                signature_c.field_signature(),
            )?)
        } else {
            FieldId::Instance(env.get_field_id(class, &*name_c, signature_c.field_signature())?)
        };
        fields.push(FieldInfo {
            name: field_name,
            id,
            kind,
            is_static,
            is_public,
        });
    }

    Ok(ClassInfo {
        name,
        methods,
        ctors,
        fields,
    })
}

fn array_elements<'a>(
    env: &mut Env<'a>,
    array: &JObject<'_>,
) -> jni::errors::Result<Vec<JObject<'a>>> {
    // SAFETY: the caller obtained this object from a JNI call that returns an
    // object array (methods/parameter types).
    let array = unsafe { JObjectArray::<JObject>::from_raw(env, array.as_raw()) };
    let len = array.len(env)?;
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        out.push(array.get_element(env, index)?);
    }
    Ok(out)
}

fn object_call<'a>(
    env: &mut Env<'a>,
    object: &JObject<'_>,
    name: &str,
    signature: &str,
) -> jni::errors::Result<JObject<'a>> {
    let signature = RuntimeMethodSignature::from_str(signature)?;
    let name = JNIString::new(name);
    let value = env.call_method(object, &*name, signature.method_signature(), &[])?;
    let object = value.l()?;
    Ok(object)
}

fn string_call(
    env: &mut Env<'_>,
    object: &JObject<'_>,
    name: &str,
) -> jni::errors::Result<Option<String>> {
    let signature = RuntimeMethodSignature::from_str("()Ljava/lang/String;")?;
    let name = JNIString::new(name);
    let value = env.call_method(object, &*name, signature.method_signature(), &[])?;
    let object = value.l()?;
    if object.is_null() {
        return Ok(None);
    }
    // SAFETY: the method signature guarantees a java.lang.String.
    let string = unsafe { JString::from_raw(env, object.as_raw()) };
    Ok(Some(jstring_to_string(env, &string)?))
}

fn int_call(env: &mut Env<'_>, object: &JObject<'_>, name: &str) -> jni::errors::Result<i32> {
    let signature = RuntimeMethodSignature::from_str("()I")?;
    let name = JNIString::new(name);
    env.call_method(object, &*name, signature.method_signature(), &[])?
        .i()
}

fn class_kind(env: &mut Env<'_>, class_obj: &JObject<'_>) -> jni::errors::Result<Kind> {
    let Some(name) = string_call(env, class_obj, "getName")? else {
        return Ok(Kind::Object("java.lang.Object".to_owned()));
    };
    Ok(match name.as_str() {
        "void" => Kind::Void,
        "boolean" => Kind::Boolean,
        "byte" => Kind::Byte,
        "char" => Kind::Char,
        "short" => Kind::Short,
        "int" => Kind::Int,
        "long" => Kind::Long,
        "float" => Kind::Float,
        "double" => Kind::Double,
        _ if name.starts_with('[') => Kind::Array(name.replace('.', "/")),
        _ => Kind::Object(name),
    })
}

fn descriptor(kind: &Kind) -> String {
    match kind {
        Kind::Void => "V".into(),
        Kind::Boolean => "Z".into(),
        Kind::Byte => "B".into(),
        Kind::Char => "C".into(),
        Kind::Short => "S".into(),
        Kind::Int => "I".into(),
        Kind::Long => "J".into(),
        Kind::Float => "F".into(),
        Kind::Double => "D".into(),
        Kind::Array(desc) => desc.clone(),
        Kind::Object(name) => format!("L{};", name.replace('.', "/")),
    }
}

fn descriptors(kinds: &[Kind]) -> String {
    kinds.iter().map(descriptor).collect()
}

fn return_type(kind: &Kind) -> JavaType {
    match kind {
        Kind::Void => JavaType::Primitive(Primitive::Void),
        Kind::Boolean => JavaType::Primitive(Primitive::Boolean),
        Kind::Byte => JavaType::Primitive(Primitive::Byte),
        Kind::Char => JavaType::Primitive(Primitive::Char),
        Kind::Short => JavaType::Primitive(Primitive::Short),
        Kind::Int => JavaType::Primitive(Primitive::Int),
        Kind::Long => JavaType::Primitive(Primitive::Long),
        Kind::Float => JavaType::Primitive(Primitive::Float),
        Kind::Double => JavaType::Primitive(Primitive::Double),
        Kind::Object(_) | Kind::Array(_) => JavaType::Object,
    }
}

fn marshal<'a>(
    env: &mut Env<'a>,
    params: &[Kind],
    args: &[JavaArg],
) -> jni::errors::Result<(Vec<jvalue>, Vec<JString<'a>>)> {
    if params.len() != args.len() {
        return Err(jni::errors::Error::JniCall(
            jni::errors::JniError::InvalidArguments,
        ));
    }
    let mut raw = Vec::with_capacity(args.len());
    let mut strings = Vec::new();
    for (kind, arg) in params.iter().zip(args) {
        let value = match (kind, arg) {
            (Kind::Boolean, JavaArg::Boolean(value)) => jvalue { z: *value },
            (Kind::Int, JavaArg::Int(value)) => jvalue { i: *value },
            (Kind::Byte, JavaArg::Int(value)) => jvalue { b: *value as i8 },
            (Kind::Char, JavaArg::Int(value)) => jvalue { c: *value as u16 },
            (Kind::Short, JavaArg::Int(value)) => jvalue { s: *value as i16 },
            (Kind::Long, JavaArg::Long(value)) => jvalue { j: *value },
            (Kind::Object(_), JavaArg::String(value)) => {
                let string = env.new_string(value)?;
                let raw = string.as_raw();
                strings.push(string);
                jvalue { l: raw }
            }
            (Kind::Object(_), JavaArg::Object(object)) => jvalue {
                l: object.as_obj().as_raw(),
            },
            (_, JavaArg::Null) => jvalue { l: ptr::null_mut() },
            (_, _) => {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ))
            }
        };
        raw.push(value);
    }
    Ok((raw, strings))
}

#[allow(deprecated)] // jni 0.22 deprecates Env::get_string, but JString::to_string
                     // depends on the crate's global JavaVM singleton which we do
                     // not initialize (we attach through our own raw JavaVM).
fn jstring_to_string(env: &mut Env<'_>, string: &JString<'_>) -> jni::errors::Result<String> {
    Ok(env.get_string(string)?.to_string())
}

fn convert<'a>(
    env: &mut Env<'a>,
    kind: &Kind,
    value: jni::JValueOwned<'a>,
) -> jni::errors::Result<JavaValue> {
    Ok(match kind {
        Kind::Void => JavaValue::Void,
        Kind::Boolean => JavaValue::Boolean(value.z()?),
        Kind::Int => JavaValue::Int(value.i()?),
        Kind::Byte => JavaValue::Int(i32::from(value.b()?)),
        Kind::Char => JavaValue::Int(i32::from(value.c()?)),
        Kind::Short => JavaValue::Int(i32::from(value.s()?)),
        Kind::Long => JavaValue::Long(value.j()?),
        Kind::Object(_) | Kind::Array(_) => {
            let object = value.l()?;
            if object.is_null() {
                return Ok(JavaValue::Object(env.new_global_ref(&object)?));
            }
            match kind {
                Kind::Object(name) if name == "java.lang.String" => {
                    // SAFETY: the declared return type is java.lang.String.
                    let string = unsafe { JString::from_raw(env, object.as_raw()) };
                    JavaValue::String(jstring_to_string(env, &string)?)
                }
                _ => JavaValue::Object(env.new_global_ref(&object)?),
            }
        }
        Kind::Float | Kind::Double => {
            return Err(jni::errors::Error::JniCall(
                jni::errors::JniError::InvalidArguments,
            ))
        }
    })
}

/// Test helper used by the agent to invoke `StringBuilder.length()` from a
/// non-JS thread while a JS `implementation` hook is installed.
pub fn call_length() -> Result<i64> {
    let class = JavaClass::find("java.lang.StringBuilder")?;
    let object = class.new_object(&[])?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "length" && method.params.is_empty())
        .ok_or_else(|| Error::NotFound("StringBuilder.length".into()))?;
    match object.call(method, &[])? {
        JavaValue::Int(value) => Ok(i64::from(value)),
        _ => Err(Error::Parse("StringBuilder.length returned non-int".into())),
    }
}

/// Diagnostic: current quick entrypoint of `StringBuilder.length`.
pub fn length_entrypoint() -> Result<usize> {
    let class = JavaClass::find("java.lang.StringBuilder")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "length" && method.params.is_empty())
        .ok_or_else(|| Error::NotFound("StringBuilder.length".into()))?;
    let address = method.id.raw() + 24;
    // SAFETY: ArtMethod layout on Android 15 has the entrypoint at offset 24.
    Ok(unsafe { ptr::read_unaligned(address as *const usize) })
}

extern "C" fn test_dispatcher(_id: usize) -> u64 {
    77
}

/// Isolated test: install a Rust-only hook, call through JNI, then restore.
pub fn hook_install_test() -> Result<String> {
    let class = JavaClass::find("java.lang.StringBuilder")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "length" && method.params.is_empty())
        .ok_or_else(|| Error::NotFound("StringBuilder.length".into()))?;
    let entry = method.id.raw() + 24;
    // SAFETY: Android 15 ArtMethod entrypoint offset.
    let original = unsafe { ptr::read_unaligned(entry as *const usize) };
    let mut hook = crate::hook::install(method.id, test_dispatcher as *const () as usize, 0)?;
    // SAFETY: same layout assumption.
    let patched = unsafe { ptr::read_unaligned(entry as *const usize) };
    let object = class.new_object(&[])?;
    let value = match object.call(method, &[])? {
        JavaValue::Int(value) => value,
        _ => -1,
    };
    hook.detach()?;
    // SAFETY: same layout assumption.
    let restored = unsafe { ptr::read_unaligned(entry as *const usize) };
    Ok(serde_json::json!({
        "ok": true,
        "original": format!("{original:#x}"),
        "patched": format!("{patched:#x}"),
        "restored": format!("{restored:#x}"),
        "value": value,
    })
    .to_string())
}

/// Wrap a raw JNI object pointer as a `JavaObject` with the given class info.
pub fn object_from_raw(info: Rc<ClassInfo>, raw: usize) -> Result<JavaObject> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: the caller received this raw reference as a Java hook
        // argument, so it is valid for the current native frame.
        let object = unsafe { JObject::from_raw(env, raw as jni::sys::jobject) };
        let global = env.new_global_ref(&object)?;
        Ok(JavaObject::from_global(info, global))
    })
}

/// Read a raw `java.lang.String` argument.
pub fn string_from_raw(raw: usize) -> Result<Option<String>> {
    if raw == 0 {
        return Ok(None);
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: the caller received this raw reference as a Java hook
        // argument, so it is valid for the current native frame.
        let object = unsafe { JString::from_raw(env, raw as jni::sys::jstring) };
        Ok(Some(jstring_to_string(env, &object)?))
    })
}

/// Test helper: `new StringBuilder("A").charAt(0)`.
pub fn call_char_at() -> Result<i64> {
    let class = JavaClass::find("java.lang.StringBuilder")?;
    let object = class.new_object(&[])?;
    let append = class
        .info
        .methods
        .iter()
        .find(|method| {
            method.name == "append"
                && method.signature == "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
        })
        .ok_or_else(|| Error::NotFound("StringBuilder.append(String)".into()))?;
    let _ = object.call(append, &[JavaArg::String("A".into())])?;
    let char_at = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "charAt" && method.params.len() == 1)
        .ok_or_else(|| Error::NotFound("StringBuilder.charAt(int)".into()))?;
    match object.call(char_at, &[JavaArg::Int(0)])? {
        JavaValue::Int(value) => Ok(i64::from(value)),
        _ => Err(Error::Parse("StringBuilder.charAt returned non-int".into())),
    }
}

/// Test helper: `Integer.bitCount(5)`.
pub fn call_bit_count() -> Result<i64> {
    let class = JavaClass::find("java.lang.Integer")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "bitCount" && method.params.len() == 1 && method.is_static)
        .ok_or_else(|| Error::NotFound("Integer.bitCount(int)".into()))?;
    match class.call_static(method, &[JavaArg::Int(5)])? {
        JavaValue::Int(value) => Ok(i64::from(value)),
        _ => Err(Error::Parse("Integer.bitCount returned non-int".into())),
    }
}

/// Diagnostic: list StringBuilder constructors and their parameter kinds.
pub fn ctor_list() -> Result<String> {
    let class = JavaClass::find("java.lang.StringBuilder")?;
    let ctors: Vec<_> = class
        .info
        .ctors
        .iter()
        .map(|ctor| {
            serde_json::json!({
                "signature": ctor.signature,
                "id": format!("{:#x}", ctor.id.into_raw() as usize),
                "entry": format!(
                    "{:#x}",
                    unsafe { ptr::read_unaligned((ctor.id.into_raw() as usize + 24) as *const usize) }
                ),
                "public": ctor.is_public,
                "params": format!("{:?}", ctor.params),
            })
        })
        .collect();
    Ok(serde_json::json!({"ok": true, "ctors": ctors}).to_string())
}

/// Diagnostic: construct StringBuilder("abc") through the high-level
/// `Env::new_object` path (which re-resolves the constructor by signature).
pub fn high_level_ctor() -> Result<String> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let class = env.find_class(&*JNIString::new("java/lang/StringBuilder"))?;
        let text = env.new_string("abc")?;
        let text = JObject::from(text);
        let sig = RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?;
        let object = env.new_object(&class, sig.method_signature(), &[JValue::Object(&text)])?;
        let method_name = JNIString::new("length");
        let method_sig = RuntimeMethodSignature::from_str("()I")?;
        let length = env
            .call_method(&object, &*method_name, method_sig.method_signature(), &[])?
            .i()?;
        Ok(format!("ok length={length}"))
    })
}

/// Diagnostic: call the same helper used by `new_object` with an explicit
/// `(String)V` constructor.
pub fn helper_ctor() -> Result<String> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let class = env.find_class(&*JNIString::new("java/lang/StringBuilder"))?;
        let sig = RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?;
        let params = [Kind::Object("java.lang.String".to_owned())];
        let args = [JavaArg::String("abc".to_owned())];
        let object = new_object_with_values(env, &class, sig.method_signature(), &params, &args)?;
        let name = JNIString::new("length");
        let len_sig = RuntimeMethodSignature::from_str("()I")?;
        let length = env
            .call_method(&object, &*name, len_sig.method_signature(), &[])?
            .i()?;
        Ok(format!("ok length={length}"))
    })
}
