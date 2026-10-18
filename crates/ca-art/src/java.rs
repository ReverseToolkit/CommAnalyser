//! Minimal Java reflection/call layer on top of JNI.
//!
//! This is the foundation for `Java.use`: it discovers methods and
//! constructors, keeps global references, and marshals the common
//! int/long/boolean/String/object signatures.  Hooking lives in `lib.rs`.

use std::ptr;
use std::rc::Rc;
use std::sync::OnceLock;

use jni::ids::{JMethodID, JStaticMethodID};
use jni::objects::{Global, JClass, JObject, JObjectArray, JString};
use jni::refs::Reference as _;
use jni::signature::{JavaType, Primitive, RuntimeMethodSignature};
use jni::strings::JNIString;
use jni::sys::{jint, jsize, jvalue, JavaVM as RawJavaVM};
use jni::{Env, JavaVM};

use ca_core::{Error, Result};

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

#[derive(Clone)]
pub struct MethodInfo {
    pub name: String,
    pub signature: String,
    pub id: MethodId,
    pub is_static: bool,
    pub params: Vec<Kind>,
    pub ret: Kind,
}

#[derive(Clone)]
pub struct CtorInfo {
    pub id: JMethodID,
    pub params: Vec<Kind>,
    pub signature: String,
}

pub struct ClassInfo {
    pub name: String,
    pub methods: Vec<MethodInfo>,
    pub ctors: Vec<CtorInfo>,
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
            let local = env.find_class(&*slash_name)?;
            let global = env.new_global_ref(&local)?;
            let info = reflect(env, &local, name)?;
            Ok(Rc::new(Self {
                info: Rc::new(info),
                class: global,
            }))
        })
    }

    pub fn new_object(&self, args: &[JavaArg]) -> Result<JavaObject> {
        let vm = JavaVm::get()?;
        vm.with_env(|env| {
            let ctor = self
                .info
                .ctors
                .iter()
                .find(|ctor| ctor.params.len() == args.len())
                .ok_or(jni::errors::Error::JniCall(
                    jni::errors::JniError::InvalidArguments,
                ))?;
            let (raw, _strings) = marshal(env, &ctor.params, args)?;
            // SAFETY: the constructor ID and the argument kinds were obtained
            // from the same class and match the supplied values.
            let object = unsafe { env.new_object_unchecked(&self.class, ctor.id, &raw)? };
            let global = env.new_global_ref(&object)?;
            Ok(JavaObject {
                info: self.info.clone(),
                object: global,
            })
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
        let signature = format!("({})V", descriptors(&params));
        let init = JNIString::new("<init>");
        let signature_c = RuntimeMethodSignature::from_str(&signature)?;
        let id = env.get_method_id(class, &*init, signature_c.method_signature())?;
        ctors.push(CtorInfo {
            id,
            params,
            signature,
        });
    }

    Ok(ClassInfo {
        name,
        methods,
        ctors,
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
            (Kind::Int | Kind::Byte | Kind::Char | Kind::Short, JavaArg::Int(value)) => {
                jvalue { i: *value }
            }
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
        Kind::Int | Kind::Byte | Kind::Char | Kind::Short => JavaValue::Int(value.i()?),
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
