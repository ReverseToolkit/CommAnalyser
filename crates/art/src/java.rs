//! Minimal Java reflection/call layer on top of JNI.
//!
//! This is the foundation for `Java.use`: it discovers methods and
//! constructors, keeps global references, and marshals the common
//! int/long/boolean/String/object signatures.  Hooking lives in `lib.rs`.

use std::ffi::c_void;
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

    pub fn vm_raw(&self) -> *mut RawJavaVM {
        self.raw
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
    pub super_name: Option<String>,
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

impl JavaObject {
    pub fn clone_global_handle(&self) -> Result<usize> {
        clone_global_handle(self.object.as_raw() as usize)
    }

    pub fn recast(&self, info: Rc<ClassInfo>) -> Result<JavaObject> {
        cast_global_handle(info, self.object.as_raw() as usize)
    }
}

pub fn new_string_global(value: &str) -> Result<usize> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let string = env.new_string(value)?;
        Ok(env.new_global_ref(&string)?.into_raw() as usize)
    })
}

pub enum JavaArg {
    Boolean(bool),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(String),
    Object(Rc<JavaObject>),
    Null,
}

pub enum JavaValue {
    Void,
    Boolean(bool),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(String),
    Object(Global<JObject<'static>>),
}

impl JavaClass {
    pub fn is_instance(&self, object: &JavaObject) -> Result<bool> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| env.is_instance_of(&object.object, &self.class))
    }

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

    pub fn set_static_field(&self, field: &FieldInfo, arg: &JavaArg) -> Result<()> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let FieldId::Static(id) = field.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            with_jvalue(env, &field.kind, arg, |env, value| {
                // SAFETY: the field id and JValue type match the reflected
                // field.
                unsafe { env.set_static_field_unchecked(&self.class, id, value) }
            })
        })
    }

    pub fn call_super(
        &self,
        object: &JavaObject,
        method: &MethodInfo,
        args: &[JavaArg],
    ) -> Result<JavaValue> {
        let MethodId::Instance(id) = method.id else {
            return Err(Error::Parse("super method is not instance".into()));
        };
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let (raw, _strings) = marshal(env, &method.params, args)?;
            // SAFETY: nonvirtual call with the declaring super class.
            let value = unsafe {
                env.call_nonvirtual_method_unchecked(
                    &object.object,
                    &self.class,
                    id,
                    return_type(&method.ret),
                    &raw,
                )?
            };
            convert(env, &method.ret, value)
        })
    }

    pub fn call_static(&self, method: &MethodInfo, args: &[JavaArg]) -> Result<JavaValue> {
        let MethodId::Static(id) = method.id else {
            return Err(Error::Parse("method is not static".into()));
        };
        self.call_static_with_id(method, id, args)
    }

    pub fn call_static_with_id(
        &self,
        method: &MethodInfo,
        id: JStaticMethodID,
        args: &[JavaArg],
    ) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let (raw, _strings) = marshal(env, &method.params, args)?;
            // SAFETY: the id points at this method (or a clone with the same
            // declaring class), and the return type is the declared one.
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

    pub fn get_field(&self, field: &FieldInfo) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let FieldId::Instance(id) = field.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            // SAFETY: the field id came from the object's class and the
            // return type matches the reflected field type.
            let value =
                unsafe { env.get_field_unchecked(&self.object, id, return_type(&field.kind))? };
            convert(env, &field.kind, value)
        })
    }

    pub fn set_field(&self, field: &FieldInfo, arg: &JavaArg) -> Result<()> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let FieldId::Instance(id) = field.id else {
                return Err(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ));
            };
            with_jvalue(env, &field.kind, arg, |env, value| {
                // SAFETY: the field id and JValue type match the reflected
                // field.
                unsafe { env.set_field_unchecked(&self.object, id, value) }
            })
        })
    }

    pub fn call(&self, method: &MethodInfo, args: &[JavaArg]) -> Result<JavaValue> {
        let MethodId::Instance(id) = method.id else {
            return Err(Error::Parse("method is not an instance method".into()));
        };
        self.call_with_id(method, id, args)
    }

    pub fn call_with_id(
        &self,
        method: &MethodInfo,
        id: JMethodID,
        args: &[JavaArg],
    ) -> Result<JavaValue> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let (raw, _strings) = marshal(env, &method.params, args)?;
            // SAFETY: the id points at this method (or a clone with the same
            // declaring class), and the return type is the declared one.
            let value = unsafe {
                env.call_method_unchecked(&self.object, id, return_type(&method.ret), &raw)?
            };
            convert(env, &method.ret, value)
        })
    }
}

fn with_jvalue<'a, T>(
    env: &mut Env<'a>,
    kind: &Kind,
    arg: &JavaArg,
    set: impl FnOnce(&mut Env<'a>, JValue<'_>) -> jni::errors::Result<T>,
) -> jni::errors::Result<T> {
    match (kind, arg) {
        (Kind::Boolean, JavaArg::Boolean(value)) => set(env, JValue::Bool(*value)),
        (Kind::Byte, JavaArg::Int(value)) => set(env, JValue::Byte(*value as i8)),
        (Kind::Char, JavaArg::Int(value)) => set(env, JValue::Char(*value as u16)),
        (Kind::Short, JavaArg::Int(value)) => set(env, JValue::Short(*value as i16)),
        (Kind::Int, JavaArg::Int(value)) => set(env, JValue::Int(*value)),
        (Kind::Long, JavaArg::Long(value)) => set(env, JValue::Long(*value)),
        (Kind::Object(_), JavaArg::String(value)) => {
            let string = env.new_string(value)?;
            let object = JObject::from(string);
            set(env, JValue::Object(&object))
        }
        (Kind::Object(_), JavaArg::Object(object)) => {
            // SAFETY: the global reference is valid for this call.
            let local = unsafe { JObject::from_raw(env, object.as_obj().as_raw()) };
            set(env, JValue::Object(&local))
        }
        (Kind::Object(_), JavaArg::Null) => {
            // SAFETY: a null object reference is valid for a reference field.
            let local = unsafe { JObject::from_raw(env, ptr::null_mut()) };
            set(env, JValue::Object(&local))
        }
        _ => Err(jni::errors::Error::JniCall(
            jni::errors::JniError::InvalidArguments,
        )),
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

fn superclass_name(env: &mut Env<'_>, class: &JClass<'_>) -> jni::errors::Result<Option<String>> {
    let Some(super_class) = env.get_superclass(class)? else {
        return Ok(None);
    };
    let method_name = JNIString::from("getName");
    let signature = RuntimeMethodSignature::from_str("()Ljava/lang/String;")?;
    let name = env.call_method(
        &super_class,
        &*method_name,
        signature.method_signature(),
        &[],
    )?;
    let object = name.l()?;
    // SAFETY: getName is declared to return java.lang.String.
    let string = unsafe { JString::from_raw(env, object.as_raw()) };
    Ok(Some(jstring_to_string(env, &string)?))
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
        super_name: superclass_name(env, class)?,
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
            (Kind::Float, JavaArg::Float(value)) => jvalue { f: *value },
            (Kind::Double, JavaArg::Double(value)) => jvalue { d: *value },
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
        Kind::Float => JavaValue::Float(value.f()?),
        Kind::Double => JavaValue::Double(value.d()?),
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

/// Quick-compiled Java frames pass raw `mirror::Object*` references, while JNI
/// APIs expect an indirect reference handle.  ART's `JNIEnvExt::NewLocalRef`
/// performs that conversion.
fn raw_object_to_local<'a>(env: &mut Env<'a>, raw: usize) -> jni::errors::Result<JObject<'a>> {
    // The quick ABI passes object references that ART also accepts as jobject
    // handles for the common case.  A full raw mirror::Object* -> local-ref
    // conversion needs ART's thread-local reference table and is not enabled
    // yet; see docs/18-m3j.md.
    // SAFETY: the caller passes a reference from the current Java frame.
    Ok(unsafe { JObject::from_raw(env, raw as jni::sys::jobject) })
}

/// Wrap a raw JNI object pointer as a `JavaObject` with the given class info.
pub fn object_from_raw(info: Rc<ClassInfo>, raw: usize) -> Result<JavaObject> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let object = raw_object_to_local(env, raw)?;
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
        let object = raw_object_to_local(env, raw)?;
        // SAFETY: the caller passed a raw java.lang.String reference.
        let object = unsafe { JString::from_raw(env, object.as_raw()) };
        Ok(Some(jstring_to_string(env, &object)?))
    })
}

pub fn string_from_global_handle(handle: usize) -> Result<Option<String>> {
    if handle == 0 {
        return Ok(None);
    }
    let cloned = clone_global_handle(handle)?;
    if cloned == 0 {
        return Ok(None);
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: cloned is a fresh global reference owned by this function.
        let global = unsafe { env.global_from_raw::<JString>(cloned as jni::sys::jstring) };
        Ok(Some(jstring_to_string(env, &global)?))
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

/// Diagnostic for raw-object reference resolution.
pub fn ref_debug() -> Result<String> {
    let base = crate::libart_base()?;
    let path = "/apex/com.android.art/lib64/libart.so";
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|err| Error::Parse(format!("libart ELF: {err}")))?;
    let name = "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE";
    let symbol = elf
        .dynsyms
        .iter()
        .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(name));
    Ok(serde_json::json!({
        "ok": true,
        "base": format!("{base:#x}"),
        "file_size": bytes.len(),
        "dynsym_count": elf.dynsyms.len(),
        "symbol": symbol.map(|symbol| format!("{:#x}", symbol.st_value)),
    })
    .to_string())
}

fn clone_global_handle(handle: usize) -> Result<usize> {
    if handle == 0 {
        return Ok(0);
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: handle is a borrowed global reference; the new global is
        // owned by the caller.
        let object = unsafe { JObject::from_raw(env, handle as jni::sys::jobject) };
        Ok(env.new_global_ref(&object)?.into_raw() as usize)
    })
}

pub fn object_from_global_handle(info: Rc<ClassInfo>, handle: usize) -> Result<JavaObject> {
    let cloned = clone_global_handle(handle)?;
    if cloned == 0 {
        return Err(Error::Parse("null Java global reference".into()));
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: cloned is a fresh global reference owned by this object.
        let global = unsafe { env.global_from_raw::<JObject>(cloned as jni::sys::jobject) };
        Ok(JavaObject::from_global(info, global))
    })
}

/// Test helper: `new StringBuilder("abc").indexOf("bc")`.
pub fn call_index_of() -> Result<i64> {
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
    let _ = object.call(append, &[JavaArg::String("abc".into())])?;
    let index_of = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "indexOf" && method.signature == "(Ljava/lang/String;)I")
        .ok_or_else(|| Error::NotFound("StringBuilder.indexOf(String)".into()))?;
    match object.call(index_of, &[JavaArg::String("bc".into())])? {
        JavaValue::Int(value) => Ok(i64::from(value)),
        _ => Err(Error::Parse(
            "StringBuilder.indexOf returned non-int".into(),
        )),
    }
}

/// Test helper: `new StringBuilder("abc").toString()`.
pub fn call_to_string() -> Result<String> {
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
    let _ = object.call(append, &[JavaArg::String("abc".into())])?;
    let to_string = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "toString" && method.params.is_empty())
        .ok_or_else(|| Error::NotFound("StringBuilder.toString".into()))?;
    match object.call(to_string, &[])? {
        JavaValue::String(value) => Ok(value),
        JavaValue::Object(_) => Ok("<object>".into()),
        _ => Err(Error::Parse(
            "StringBuilder.toString returned non-string".into(),
        )),
    }
}

/// Test helper: `Math.abs(-2.5f)`.
pub fn call_math_abs_float() -> Result<f32> {
    let class = JavaClass::find("java.lang.Math")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "abs" && method.signature == "(F)F")
        .ok_or_else(|| Error::NotFound("Math.abs(float)".into()))?;
    match class.call_static(method, &[JavaArg::Float(-2.5)])? {
        JavaValue::Float(value) => Ok(value),
        _ => Err(Error::Parse("Math.abs float returned non-float".into())),
    }
}

/// Test helper: `Float.intBitsToFloat(0x40200000)`.
pub fn call_float_from_bits() -> Result<f32> {
    let class = JavaClass::find("java.lang.Float")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "intBitsToFloat" && method.signature == "(I)F")
        .ok_or_else(|| Error::NotFound("Float.intBitsToFloat".into()))?;
    match class.call_static(method, &[JavaArg::Int(0x4020_0000)])? {
        JavaValue::Float(value) => Ok(value),
        _ => Err(Error::Parse("intBitsToFloat returned non-float".into())),
    }
}

/// Test helper: `Float.floatToRawIntBits(2.5f)`.
pub fn call_float_to_bits() -> Result<i64> {
    let class = JavaClass::find("java.lang.Float")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "floatToRawIntBits" && method.signature == "(F)I")
        .ok_or_else(|| Error::NotFound("Float.floatToRawIntBits".into()))?;
    match class.call_static(method, &[JavaArg::Float(2.5)])? {
        JavaValue::Int(value) => Ok(i64::from(value)),
        _ => Err(Error::Parse("floatToRawIntBits returned non-int".into())),
    }
}

/// Test helper: `Double.longBitsToDouble(0x4004000000000000L)`.
pub fn call_double_from_bits() -> Result<f64> {
    let class = JavaClass::find("java.lang.Double")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "longBitsToDouble" && method.signature == "(J)D")
        .ok_or_else(|| Error::NotFound("Double.longBitsToDouble".into()))?;
    match class.call_static(method, &[JavaArg::Long(0x4004_0000_0000_0000)])? {
        JavaValue::Double(value) => Ok(value),
        _ => Err(Error::Parse("longBitsToDouble returned non-double".into())),
    }
}

/// Test helper: `Double.doubleToRawLongBits(2.5)`.
pub fn call_double_to_bits() -> Result<i64> {
    let class = JavaClass::find("java.lang.Double")?;
    let method = class
        .info
        .methods
        .iter()
        .find(|method| method.name == "doubleToRawLongBits" && method.signature == "(D)J")
        .ok_or_else(|| Error::NotFound("Double.doubleToRawLongBits".into()))?;
    match class.call_static(method, &[JavaArg::Double(2.5)])? {
        JavaValue::Long(value) => Ok(value),
        _ => Err(Error::Parse("doubleToRawLongBits returned non-long".into())),
    }
}

fn resolve_libart_symbol(name: &str) -> Option<usize> {
    let base = crate::libart_base().ok()?;
    for path in [
        "/apex/com.android.art/lib64/libart.so",
        "/system/lib64/libart.so",
    ] {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(elf) = goblin::elf::Elf::parse(&bytes) else {
            continue;
        };
        let Some(symbol) = elf
            .dynsyms
            .iter()
            .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(name))
        else {
            continue;
        };
        if symbol.st_value != 0 {
            return Some(base + symbol.st_value as usize);
        }
    }
    None
}

static JNI_ENV_OFFSET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RUNTIME_EXCEPTION_CLASS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static THROW_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static THROW_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn throw_state() -> (usize, Option<String>) {
    (
        THROW_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        THROW_ERROR.lock().ok().and_then(|slot| slot.clone()),
    )
}

fn discover_env_offset(env: *mut jni::sys::JNIEnv) -> Option<usize> {
    use std::sync::atomic::Ordering;
    if JNI_ENV_OFFSET.load(Ordering::Relaxed) != 0 {
        return Some(JNI_ENV_OFFSET.load(Ordering::Relaxed));
    }
    // SAFETY: JNIEnvExt embeds Thread* at +8.
    let thread = unsafe { ptr::read_unaligned((env as usize + 8) as *const usize) };
    if thread < 0x1000 {
        return None;
    }
    for offset in (0..0x400).step_by(8) {
        // SAFETY: reading within the ART Thread TLS block.
        let value = unsafe { ptr::read_unaligned((thread + offset) as *const usize) };
        if value == env as usize {
            JNI_ENV_OFFSET.store(offset, Ordering::Relaxed);
            return Some(offset);
        }
    }
    None
}

pub fn cache_exception_class() -> Result<()> {
    use std::sync::atomic::Ordering;
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        discover_env_offset(env.get_raw());
        if RUNTIME_EXCEPTION_CLASS.load(Ordering::Relaxed) != 0 {
            return Ok(());
        }
        let name = jni::strings::JNIString::from("java/lang/RuntimeException");
        let class = env.find_class(name)?;
        let global = env.new_global_ref(&class)?;
        RUNTIME_EXCEPTION_CLASS.store(global.into_raw() as usize, Ordering::Relaxed);
        Ok(())
    })
}

fn current_thread() -> Option<usize> {
    let address = resolve_libart_symbol("_ZN3art6Thread14CurrentFromGdbEv")?;
    type Current = unsafe extern "C" fn() -> *mut c_void;
    // SAFETY: address comes from libart's dynamic symbol table.
    let current: Current = unsafe { std::mem::transmute(address) };
    let thread = unsafe { current() };
    (!thread.is_null()).then_some(thread as usize)
}

pub fn throw_runtime_exception(message: &str) -> Result<()> {
    use std::sync::atomic::Ordering;
    THROW_CALLS.fetch_add(1, Ordering::Relaxed);
    let result = (|| {
        cache_exception_class()?;
        let offset = JNI_ENV_OFFSET.load(Ordering::Relaxed);
        if offset == 0 {
            return Err(Error::NotFound("Thread::jni_env offset".into()));
        }
        let class_handle = RUNTIME_EXCEPTION_CLASS.load(Ordering::Relaxed);
        if class_handle == 0 {
            return Err(Error::NotFound("RuntimeException class".into()));
        }
        let thread = current_thread().ok_or_else(|| Error::NotFound("ART thread".into()))?;
        // SAFETY: offset was measured from a live JNIEnv/Thread pair.
        let env = unsafe { ptr::read_unaligned((thread + offset) as *const usize) };
        // SAFETY: check the JNIEnvExt back-pointer.
        let self_ptr = unsafe { ptr::read_unaligned((env + 8) as *const usize) };
        if env < 0x1000 || self_ptr != thread {
            return Err(Error::Parse("invalid Thread::jni_env".into()));
        }
        let message = std::ffi::CString::new(message)
            .map_err(|_| Error::Parse("exception message contains NUL".into()))?;
        // SAFETY: env is the JNIEnvExt for this thread; ThrowNew is entry 14.
        let table = unsafe { *(env as *mut *const usize) };
        let throw_new: unsafe extern "C" fn(
            *mut jni::sys::JNIEnv,
            jni::sys::jclass,
            *const std::os::raw::c_char,
        ) -> jni::sys::jint = unsafe { std::mem::transmute(*table.add(14)) };
        let status = unsafe {
            throw_new(
                env as *mut jni::sys::JNIEnv,
                class_handle as jni::sys::jclass,
                message.as_ptr(),
            )
        };
        if status != 0 {
            return Err(Error::Parse(format!("ThrowNew failed: {status}")));
        }
        Ok(())
    })();
    if let Err(error) = &result {
        if let Ok(mut slot) = THROW_ERROR.lock() {
            *slot = Some(error.to_string());
        }
    }
    result
}

/// Create a Java `int[]` and wrap it as a JavaObject.
pub fn new_int_array(values: &[i32]) -> Result<JavaObject> {
    let class = JavaClass::find("[I")?;
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let array = env.new_int_array(values.len())?;
        array.set_region(env, 0, values)?;
        let object: &JObject<'_> = array.as_ref();
        let global = env.new_global_ref(object)?;
        Ok(JavaObject::from_global(class.info.clone(), global))
    })
}

/// Reinterpret an existing global reference as another declared class.
pub fn cast_global_handle(info: Rc<ClassInfo>, handle: usize) -> Result<JavaObject> {
    let cloned = clone_global_handle(handle)?;
    if cloned == 0 {
        return Err(Error::Parse("null Java global reference".into()));
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: cloned is a fresh global reference owned by this object.
        let global = unsafe { env.global_from_raw::<JObject>(cloned as jni::sys::jobject) };
        Ok(JavaObject::from_global(info, global))
    })
}

/// Create a primitive array from `f64` values, narrowing per `kind`.
pub fn new_primitive_array(kind: &str, values: &[f64]) -> Result<JavaObject> {
    macro_rules! build {
        ($desc:literal, $new:ident, $ty:ty, $convert:expr) => {{
            let class = JavaClass::find($desc)?;
            let converted: Vec<$ty> = values.iter().map($convert).collect();
            let vm = JavaVm::get()?;
            vm.with_env(|env| {
                let array = env.$new(converted.len())?;
                array.set_region(env, 0, &converted)?;
                let object: &JObject<'_> = array.as_ref();
                let global = env.new_global_ref(object)?;
                Ok(JavaObject::from_global(class.info.clone(), global))
            })
        }};
    }
    match kind {
        "int" => build!("[I", new_int_array, i32, |value| *value as i32),
        "byte" => build!("[B", new_byte_array, i8, |value| *value as i8),
        "char" => build!("[C", new_char_array, u16, |value| *value as u16),
        "short" => build!("[S", new_short_array, i16, |value| *value as i16),
        "long" => build!("[J", new_long_array, i64, |value| *value as i64),
        "float" => build!("[F", new_float_array, f32, |value| *value as f32),
        "double" => build!("[D", new_double_array, f64, |value| *value),
        "boolean" => build!("[Z", new_boolean_array, bool, |value| *value != 0.0),
        _ => Err(Error::Parse(format!("Java.array type {kind}"))),
    }
}

pub fn new_string_array(values: &[String]) -> Result<JavaObject> {
    let class = JavaClass::find("[Ljava/lang/String;")?;
    let len = i32::try_from(values.len()).map_err(|_| Error::Parse("String[] too large".into()))?;
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let element_class = jni::strings::JNIString::from("java/lang/String");
        let array = env.new_object_array(len, element_class, JObject::null())?;
        for (index, value) in values.iter().enumerate() {
            let string = env.new_string(value)?;
            array.set_element(env, index, &string)?;
        }
        let object: &JObject<'_> = array.as_ref();
        let global = env.new_global_ref(object)?;
        Ok(JavaObject::from_global(class.info.clone(), global))
    })
}

pub fn exception_pending() -> Result<bool> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| Ok(env.exception_check()))
}

pub fn clear_pending_exception() -> Result<()> {
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        if env.exception_check() {
            env.exception_clear();
        }
        Ok(())
    })
}

pub fn object_from_jni_handle(info: Rc<ClassInfo>, handle: usize) -> Result<JavaObject> {
    if handle == 0 {
        return Err(Error::Parse("null JNI object".into()));
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: handle is a borrowed local/global reference.
        let object = unsafe { JObject::from_raw(env, handle as jni::sys::jobject) };
        let global = env.new_global_ref(&object)?;
        Ok(JavaObject::from_global(info, global))
    })
}

pub fn string_from_jni_handle(handle: usize) -> Result<Option<String>> {
    if handle == 0 {
        return Ok(None);
    }
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: handle is a borrowed local/global string reference.
        let string = unsafe { JString::from_raw(env, handle as jni::sys::jstring) };
        Ok(Some(jstring_to_string(env, &string)?))
    })
}

pub fn jni_new_global(env: usize, handle: usize) -> Result<usize> {
    if env == 0 || handle == 0 {
        return Ok(0);
    }
    // SAFETY: env is the JNIEnv passed to the native hook callback; NewGlobalRef
    // is entry 21 in the standard JNI function table.
    let table = unsafe { *(env as *mut *const usize) };
    let new_global: unsafe extern "C" fn(
        *mut jni::sys::JNIEnv,
        jni::sys::jobject,
    ) -> jni::sys::jobject = unsafe { std::mem::transmute(*table.add(21)) };
    let global = unsafe { new_global(env as *mut jni::sys::JNIEnv, handle as jni::sys::jobject) };
    if global.is_null() {
        return Err(Error::Parse("NewGlobalRef returned null".into()));
    }
    Ok(global as usize)
}

/// Create an object array `[L<class>;` from existing JavaObject handles.
pub fn new_object_array_from_objects(
    class_name: &str,
    values: &[Rc<JavaObject>],
) -> Result<JavaObject> {
    let element_name = class_name.replace('.', "/");
    let array_descriptor = format!("[L{element_name};");
    let array_class = JavaClass::find(&array_descriptor)?;
    let len =
        i32::try_from(values.len()).map_err(|_| Error::Parse("object array too large".into()))?;
    let vm = JavaVm::get()?;
    vm.with_env(|env| {
        let element_class = jni::strings::JNIString::from(element_name.as_str());
        let array = env.new_object_array(len, element_class, JObject::null())?;
        for (index, value) in values.iter().enumerate() {
            array.set_element(env, index, &value.object)?;
        }
        let object: &JObject<'_> = array.as_ref();
        let global = env.new_global_ref(object)?;
        Ok(JavaObject::from_global(array_class.info.clone(), global))
    })
}
