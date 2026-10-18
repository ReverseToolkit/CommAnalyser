//! Frida-style `Java` object: `Java.perform` and `Java.use`.
//!
//! The class/instance wrappers are plain JS objects with dynamically created
//! method properties.  JNI object references are kept in a thread-local table
//! and referenced from JS via a hidden `__analyserJavaId` property.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use rquickjs::function::Rest;
use rquickjs::prelude::Func;
use rquickjs::{Array, Ctx, Function, IntoJs, Object, Persistent, Result as JsResult, Value};

use crate::worker::{java_dispatch, JavaHookEntry, JavaHookTable};
use art::java::{
    ClassInfo, CtorInfo, FieldInfo, JavaArg, JavaClass, JavaObject, JavaValue, Kind, MethodInfo,
};

thread_local! {
    static OBJECTS: RefCell<Vec<Rc<JavaObject>>> = const { RefCell::new(Vec::new()) };
}

const HANDLE: &str = "__analyserJavaId";

struct HookMeta {
    is_static: bool,
    params: Vec<Kind>,
    ret: Kind,
}

static HOOK_META: OnceLock<Mutex<HashMap<usize, HookMeta>>> = OnceLock::new();

fn hook_meta() -> &'static Mutex<HashMap<usize, HookMeta>> {
    HOOK_META.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn hook_meta_for(id: usize) -> Option<(bool, Vec<Kind>)> {
    let meta = hook_meta().lock().ok()?;
    let entry = meta.get(&id)?;
    Some((entry.is_static, entry.params.clone()))
}

pub(crate) fn hook_returns_object(id: usize) -> bool {
    let Ok(meta) = hook_meta().lock() else {
        return false;
    };
    meta.get(&id)
        .is_some_and(|entry| matches!(entry.ret, Kind::Object(_) | Kind::Array(_)))
}

fn register_hook(id: usize, method: &MethodInfo) {
    if let Ok(mut meta) = hook_meta().lock() {
        meta.insert(
            id,
            HookMeta {
                is_static: method.is_static,
                params: method.params.clone(),
                ret: method.ret.clone(),
            },
        );
    }
}

fn unregister_hook(id: usize) {
    if let Ok(mut meta) = hook_meta().lock() {
        meta.remove(&id);
    }
}

pub(crate) fn install<'js>(ctx: &Ctx<'js>, java_hooks: Rc<RefCell<JavaHookTable>>) -> JsResult<()> {
    let set_hooks = java_hooks.clone();
    ctx.globals().set(
        "__analyser_java_set_impl",
        Func::from(
            move |ctx: Ctx<'js>,
                  class_name: String,
                  method_name: String,
                  signature: String,
                  is_static: bool,
                  callback: Function<'js>|
                  -> JsResult<()> {
                let class = JavaClass::find(&class_name).map_err(to_js_error)?;
                let method = class
                    .info
                    .methods
                    .iter()
                    .find(|method| {
                        method.name == method_name
                            && method.signature == signature
                            && method.is_static == is_static
                    })
                    .cloned()
                    .ok_or_else(|| js_error("Java method not found"))?;
                let mut table = set_hooks.borrow_mut();
                let id = table.entries.len();
                let hook = art::hook::install(method.id, java_dispatch as *const () as usize, id)
                    .map_err(to_js_error)?;
                register_hook(id, &method);
                table.entries.push(Some(JavaHookEntry {
                    function: Persistent::save(&ctx, callback),
                    class,
                    method,
                    hook: Rc::new(RefCell::new(hook)),
                }));
                Ok(())
            },
        ),
    )?;
    let detach_hooks = java_hooks.clone();
    ctx.globals().set(
        "__analyser_java_detach",
        Func::from(
            move |class_name: String,
                  method_name: String,
                  signature: String,
                  is_static: bool|
                  -> JsResult<()> {
                let mut table = detach_hooks.borrow_mut();
                if let Some((id, slot)) = table.entries.iter_mut().enumerate().find(|(_, slot)| {
                    slot.as_ref().is_some_and(|entry| {
                        entry.class.info.name == class_name
                            && entry.method.name == method_name
                            && entry.method.signature == signature
                            && entry.method.is_static == is_static
                    })
                }) {
                    *slot = None;
                    unregister_hook(id);
                }
                Ok(())
            },
        ),
    )?;
    ctx.eval::<(), _>(
        r#"
        globalThis.__analyser_call_impl = function (fn, thisObj, args) {
            return fn.apply(thisObj, args);
        };
        globalThis.__analyser_make_java_field = function (getter, setter) {
            const field = {};
            Object.defineProperty(field, 'value', {
                enumerable: true,
                get: getter,
                set: setter
            });
            return field;
        };
        globalThis.__analyser_make_java_method = function (fn, className, methodName, signature, isStatic) {
            Object.defineProperty(fn, 'implementation', {
                configurable: true,
                get() { return fn.__impl || null; },
                set(cb) {
                    fn.__impl = cb;
                    if (cb === null || cb === undefined) {
                        __analyser_java_detach(className, methodName, signature, isStatic);
                    } else {
                        __analyser_java_set_impl(className, methodName, signature, isStatic, cb);
                    }
                }
            });
            fn.overload = function (signature) {
                const bound = function () { return fn.apply(this, arguments); };
                Object.defineProperty(bound, 'implementation', {
                    configurable: true,
                    get() { return bound.__impl || null; },
                    set(cb) {
                        bound.__impl = cb;
                        if (cb === null || cb === undefined) {
                            __analyser_java_detach(className, methodName, signature, isStatic);
                        } else {
                            __analyser_java_set_impl(className, methodName, signature, isStatic, cb);
                        }
                    }
                });
                return bound;
            };
            return fn;
        };
        "#,
    )?;

    let java = Object::new(ctx.clone())?;
    java.set("available", true)?;
    java.set("perform", Func::from(perform))?;
    java.set("use", Func::from(use_class))?;
    java.set("array", Func::from(make_array))?;
    java.set("cast", Func::from(cast))?;
    ctx.globals().set("Java", java)?;
    Ok(())
}

fn perform<'js>(_ctx: Ctx<'js>, function: Function<'js>) -> JsResult<Value<'js>> {
    function.call::<_, Value<'js>>(())
}

fn use_class<'js>(ctx: Ctx<'js>, name: String) -> JsResult<Object<'js>> {
    let class = JavaClass::find(&name).map_err(to_js_error)?;
    class_object(ctx, class)
}

fn class_object<'js>(ctx: Ctx<'js>, class: Rc<JavaClass>) -> JsResult<Object<'js>> {
    let wrapper = Object::new(ctx.clone())?;
    wrapper.set("$className", class.info.name.clone())?;

    let ctor_class = class.clone();
    let ctor_ctx = ctx.clone();
    wrapper.set(
        "$new",
        Function::new(
            ctx.clone(),
            move |args: Rest<Value<'js>>| -> JsResult<Value<'js>> {
                let ctor = choose_ctor(&ctor_class, &args.0)?;
                let java_args = convert_args(&args.0, &ctor.params)?;
                let object = ctor_class
                    .new_object_with(ctor, &java_args)
                    .map_err(to_js_error)?;
                let id = register(object);
                Ok(instance_object(ctor_ctx.clone(), ctor_class.clone(), id)?.into_value())
            },
        ),
    )?;

    for (name, methods) in method_groups(&class.info) {
        let target = if methods[0].is_static {
            Target::Static
        } else {
            Target::Prototype
        };
        let function = method_function(ctx.clone(), class.clone(), target, methods)?;
        wrapper.set(name, function)?;
    }
    for field in class
        .info
        .fields
        .iter()
        .filter(|field| field.is_static && field.is_public)
    {
        wrapper.set(
            field.name.clone(),
            field_object(
                ctx.clone(),
                class.clone(),
                FieldTarget::Static,
                field.clone(),
            )?,
        )?;
    }
    Ok(wrapper)
}

fn instance_object<'js>(ctx: Ctx<'js>, class: Rc<JavaClass>, id: u32) -> JsResult<Object<'js>> {
    let wrapper = Object::new(ctx.clone())?;
    wrapper.set(HANDLE, id)?;
    wrapper.set("$className", class.info.name.clone())?;

    let object = get_object(id).ok_or_else(|| js_error("invalid Java object handle"))?;
    for (name, methods) in method_groups(&class.info) {
        if methods[0].is_static {
            continue;
        }
        let function = method_function(
            ctx.clone(),
            class.clone(),
            Target::Instance(object.clone()),
            methods,
        )?;
        wrapper.set(name, function)?;
    }
    for field in class
        .info
        .fields
        .iter()
        .filter(|field| !field.is_static && field.is_public)
    {
        wrapper.set(
            field.name.clone(),
            field_object(
                ctx.clone(),
                class.clone(),
                FieldTarget::Instance(object.clone()),
                field.clone(),
            )?,
        )?;
    }
    Ok(wrapper)
}

enum FieldTarget {
    Static,
    Instance(Rc<JavaObject>),
}

impl FieldTarget {
    fn get(&self, class: &JavaClass, field: &FieldInfo) -> runtime::Result<JavaValue> {
        match self {
            Self::Static => class.get_static_field(field),
            Self::Instance(object) => object.get_field(field),
        }
    }

    fn set(&self, class: &JavaClass, field: &FieldInfo, arg: &JavaArg) -> runtime::Result<()> {
        match self {
            Self::Static => class.set_static_field(field, arg),
            Self::Instance(object) => object.set_field(field, arg),
        }
    }
}

fn field_object<'js>(
    ctx: Ctx<'js>,
    class: Rc<JavaClass>,
    target: FieldTarget,
    field: FieldInfo,
) -> JsResult<Object<'js>> {
    let get_ctx = ctx.clone();
    let get_class = class.clone();
    let get_target = match &target {
        FieldTarget::Static => FieldTarget::Static,
        FieldTarget::Instance(object) => FieldTarget::Instance(object.clone()),
    };
    let get_field = field.clone();
    let getter = Function::new(ctx.clone(), move || -> JsResult<Value<'js>> {
        let value = get_target
            .get(&get_class, &get_field)
            .map_err(to_js_error)?;
        value_to_js(get_ctx.clone(), get_class.clone(), value)
    })?;

    let set_class = class.clone();
    let set_target = target;
    let set_field = field;
    let setter = Function::new(
        ctx.clone(),
        move |_ctx: Ctx<'js>, value: Value<'js>| -> JsResult<()> {
            let arg = to_arg(&value, &set_field.kind)?;
            set_target
                .set(&set_class, &set_field, &arg)
                .map_err(to_js_error)
        },
    )?;
    let wrap: Function<'js> = ctx.globals().get("__analyser_make_java_field")?;
    wrap.call((getter, setter))
}

fn method_groups(info: &ClassInfo) -> BTreeMap<String, Vec<MethodInfo>> {
    let mut groups: BTreeMap<String, Vec<MethodInfo>> = BTreeMap::new();
    for method in &info.methods {
        groups
            .entry(method.name.clone())
            .or_default()
            .push(method.clone());
    }
    groups
}

enum Target {
    Static,
    Instance(Rc<JavaObject>),
    Prototype,
}

fn method_function<'js>(
    ctx: Ctx<'js>,
    class: Rc<JavaClass>,
    target: Target,
    methods: Vec<MethodInfo>,
) -> JsResult<Function<'js>> {
    let first = methods
        .first()
        .ok_or_else(|| js_error("empty Java method group"))?
        .clone();
    let call_ctx = ctx.clone();
    let call_class = class.clone();
    let function = Function::new(
        ctx.clone(),
        move |args: Rest<Value<'js>>| -> JsResult<Value<'js>> {
            let method = choose_method(&methods, &args.0)?;
            let java_args = convert_args(&args.0, &method.params)?;
            let value = match &target {
                Target::Static => call_class.call_static(method, &java_args),
                Target::Instance(object) => object.call(method, &java_args),
                Target::Prototype => {
                    return Err(js_error(
                        "instance method called on the class object; call it on an instance",
                    ))
                }
            }
            .map_err(to_js_error)?;
            value_to_js(call_ctx.clone(), call_class.clone(), value)
        },
    )?;
    let wrap: Function<'js> = ctx.globals().get("__analyser_make_java_method")?;
    wrap.call((
        function,
        class.info.name.clone(),
        first.name,
        first.signature,
        first.is_static,
    ))
}

fn choose_method<'a>(methods: &'a [MethodInfo], args: &[Value<'_>]) -> JsResult<&'a MethodInfo> {
    methods
        .iter()
        .find(|method| {
            method.params.len() == args.len()
                && method
                    .params
                    .iter()
                    .zip(args)
                    .all(|(kind, value)| matches_kind(kind, value))
        })
        .or_else(|| {
            methods
                .iter()
                .find(|method| method.params.len() == args.len())
        })
        .ok_or_else(|| js_error("no matching Java overload"))
}

fn choose_ctor<'a>(class: &'a JavaClass, args: &[Value<'_>]) -> JsResult<&'a CtorInfo> {
    class
        .info
        .ctors
        .iter()
        .find(|ctor| {
            ctor.is_public
                && ctor.params.len() == args.len()
                && ctor
                    .params
                    .iter()
                    .zip(args)
                    .all(|(kind, value)| strong_match(kind, value))
        })
        .or_else(|| {
            class.info.ctors.iter().find(|ctor| {
                ctor.is_public
                    && ctor.params.len() == args.len()
                    && ctor
                        .params
                        .iter()
                        .zip(args)
                        .all(|(kind, value)| matches_kind(kind, value))
            })
        })
        .or_else(|| {
            class
                .info
                .ctors
                .iter()
                .find(|ctor| ctor.is_public && ctor.params.len() == args.len())
        })
        .or_else(|| {
            class
                .info
                .ctors
                .iter()
                .find(|ctor| ctor.params.len() == args.len())
        })
        .ok_or_else(|| js_error("no matching Java constructor"))
}

fn strong_match(kind: &Kind, value: &Value<'_>) -> bool {
    if value.is_string() {
        return matches!(kind, Kind::Object(name) if name == "java.lang.String");
    }
    matches_kind(kind, value)
}

fn matches_kind(kind: &Kind, value: &Value<'_>) -> bool {
    match kind {
        Kind::Boolean => value.is_bool(),
        Kind::Byte | Kind::Char | Kind::Short | Kind::Int | Kind::Long => value.is_number(),
        Kind::Object(name) if name == "java.lang.String" => {
            value.is_string() || java_id(value).is_some()
        }
        Kind::Object(_) => value.is_string() || value.is_null() || java_id(value).is_some(),
        Kind::Array(_) | Kind::Void | Kind::Float | Kind::Double => false,
    }
}

fn convert_args(args: &[Value<'_>], params: &[Kind]) -> JsResult<Vec<JavaArg>> {
    if args.len() != params.len() {
        return Err(js_error("argument count mismatch"));
    }
    args.iter()
        .zip(params)
        .map(|(value, kind)| to_arg(value, kind))
        .collect()
}

fn to_arg(value: &Value<'_>, kind: &Kind) -> JsResult<JavaArg> {
    match kind {
        Kind::Boolean => Ok(JavaArg::Boolean(value.get()?)),
        Kind::Byte | Kind::Char | Kind::Short | Kind::Int => Ok(JavaArg::Int(value.get()?)),
        Kind::Long => Ok(JavaArg::Long(value.get()?)),
        Kind::Object(_) => {
            if value.is_null() || value.is_undefined() {
                return Ok(JavaArg::Null);
            }
            if let Some(id) = java_id(value) {
                let object =
                    get_object(id).ok_or_else(|| js_error("invalid Java object handle"))?;
                return Ok(JavaArg::Object(object));
            }
            if value.is_string() {
                return Ok(JavaArg::String(value.get()?));
            }
            Err(js_error("expected a Java object or string"))
        }
        Kind::Array(_) | Kind::Void | Kind::Float | Kind::Double => {
            Err(js_error("unsupported Java parameter type"))
        }
    }
}

pub(crate) struct HookCall {
    pub(crate) args: [u64; 8],
    pub(crate) fargs: [u64; 8],
    pub(crate) globals: u8,
    pub(crate) hook: Option<Rc<RefCell<art::hook::JavaHook>>>,
}

struct OriginalCall {
    this_id: u32,
    raw: [u64; 8],
    fargs: [u64; 8],
    globals: u8,
}

pub(crate) fn invoke_impl<'js>(
    ctx: &Ctx<'js>,
    function: Function<'js>,
    class: Rc<JavaClass>,
    method: &MethodInfo,
    call: HookCall,
) -> JsResult<(u64, u64)> {
    let HookCall {
        args,
        fargs,
        globals,
        hook,
    } = call;
    let start = if method.is_static { 1 } else { 2 };
    let this_value: Value<'js> = if method.is_static {
        let this = class_object(ctx.clone(), class.clone())?;
        if let Some(hook) = hook.clone() {
            let method_function: Function<'js> = this.get(method.name.clone())?;
            method_function.set(
                "original",
                original_function(
                    ctx.clone(),
                    class.clone(),
                    method.clone(),
                    hook,
                    OriginalCall {
                        this_id: 0,
                        raw: args,
                        fargs,
                        globals,
                    },
                )?,
            )?;
        }
        this.into_value()
    } else {
        let object = if globals & (1 << 1) != 0 {
            art::java::object_from_global_handle(class.info.clone(), args[1] as usize)
        } else {
            art::java::object_from_raw(class.info.clone(), args[1] as usize)
        }
        .map_err(to_js_error)?;
        let id = register(object);
        let this = instance_object(ctx.clone(), class.clone(), id)?;
        if let Some(hook) = hook {
            let method_function: Function<'js> = this.get(method.name.clone())?;
            method_function.set(
                "original",
                original_function(
                    ctx.clone(),
                    class.clone(),
                    method.clone(),
                    hook,
                    OriginalCall {
                        this_id: id,
                        raw: args,
                        fargs,
                        globals,
                    },
                )?,
            )?;
        }
        this.into_value()
    };

    let call_args = Array::new(ctx.clone())?;
    let mut fp_index = 0;
    for (slot, kind) in method.params.iter().enumerate() {
        let raw = args[start + slot];
        let value: Value<'js> = match kind {
            Kind::Boolean => (raw as u8 != 0).into_js(ctx)?,
            Kind::Byte | Kind::Char | Kind::Short | Kind::Int => (raw as i32).into_js(ctx)?,
            Kind::Long => (raw as i64).into_js(ctx)?,
            Kind::Object(name) if name == "java.lang.String" => {
                let value = if globals & (1 << (start + slot)) != 0 {
                    art::java::string_from_global_handle(raw as usize)
                } else {
                    art::java::string_from_raw(raw as usize)
                }
                .map_err(to_js_error)?;
                match value {
                    Some(value) => value.into_js(ctx)?,
                    None => Value::new_null(ctx.clone()),
                }
            }
            Kind::Object(name) => {
                let (info, global) = if globals & (1 << (start + slot)) != 0 {
                    let param_class = JavaClass::find(name).map_err(to_js_error)?;
                    (param_class.info.clone(), true)
                } else {
                    (class.info.clone(), false)
                };
                let object = if global {
                    art::java::object_from_global_handle(info, raw as usize)
                } else {
                    art::java::object_from_raw(info, raw as usize)
                }
                .map_err(to_js_error)?;
                let id = register(object);
                instance_object(ctx.clone(), class.clone(), id)?.into_value()
            }
            Kind::Float => {
                let value = f32::from_bits(fargs[fp_index] as u32);
                fp_index += 1;
                value.into_js(ctx)?
            }
            Kind::Double => {
                let value = f64::from_bits(fargs[fp_index]);
                fp_index += 1;
                value.into_js(ctx)?
            }
            Kind::Array(_) | Kind::Void => {
                return Err(js_error("unsupported Java hook argument type"))
            }
        };
        call_args.set(slot, value)?;
    }

    let call: Function<'js> = ctx.globals().get("__analyser_call_impl")?;
    let result: Value<'js> = call.call((function, this_value, call_args))?;
    match &method.ret {
        Kind::Void => Ok((0, 0)),
        Kind::Boolean => Ok((u64::from(result.get::<bool>()?), 0)),
        Kind::Byte | Kind::Char | Kind::Short | Kind::Int => Ok((result.get::<i64>()? as u64, 0)),
        Kind::Long => Ok((result.get::<i64>()? as u64, 0)),
        Kind::Float => {
            let value = result.get::<f64>()? as f32;
            Ok((0, u64::from(value.to_bits())))
        }
        Kind::Double => Ok((0, result.get::<f64>()?.to_bits())),
        Kind::Object(name) | Kind::Array(name) => {
            if result.is_null() {
                return Ok((0, 0));
            }
            if result.is_string() {
                let value: String = result.get()?;
                return art::java::new_string_global(&value)
                    .map(|handle| (handle as u64, 0))
                    .map_err(to_js_error);
            }
            if let Some(id) = java_id(&result) {
                let object =
                    get_object(id).ok_or_else(|| js_error("invalid Java object handle"))?;
                return object
                    .clone_global_handle()
                    .map(|handle| (handle as u64, 0))
                    .map_err(to_js_error);
            }
            let _ = name;
            Err(js_error("unsupported Java hook return value"))
        }
    }
}

fn original_function<'js>(
    ctx: Ctx<'js>,
    class: Rc<JavaClass>,
    method: MethodInfo,
    hook: Rc<RefCell<art::hook::JavaHook>>,
    call: OriginalCall,
) -> JsResult<Function<'js>> {
    let OriginalCall {
        this_id,
        raw,
        fargs,
        globals,
    } = call;
    let call_ctx = ctx.clone();
    Function::new(ctx, move || -> JsResult<Value<'js>> {
        let args = original_args(&method, &raw, &fargs, globals)?;
        hook.borrow().suspend();
        let result = if method.is_static {
            class.call_static(&method, &args)
        } else {
            let object =
                get_object(this_id).ok_or_else(|| js_error("invalid Java object handle"))?;
            object.call(&method, &args)
        };
        hook.borrow().resume();
        value_to_js(
            call_ctx.clone(),
            class.clone(),
            result.map_err(to_js_error)?,
        )
    })
}

fn original_args(
    method: &MethodInfo,
    raw: &[u64; 8],
    fargs: &[u64; 8],
    globals: u8,
) -> JsResult<Vec<JavaArg>> {
    let start = if method.is_static { 1 } else { 2 };
    let mut fp_index = 0;
    method
        .params
        .iter()
        .enumerate()
        .map(|(slot, kind)| {
            let register = start + slot;
            let is_global = globals & (1 << register) != 0;
            Ok(match kind {
                Kind::Boolean => JavaArg::Boolean(raw[register] != 0),
                Kind::Byte | Kind::Char | Kind::Short | Kind::Int => {
                    JavaArg::Int(raw[register] as i32)
                }
                Kind::Long => JavaArg::Long(raw[register] as i64),
                Kind::Float => {
                    let value = f32::from_bits(fargs[fp_index] as u32);
                    fp_index += 1;
                    JavaArg::Float(value)
                }
                Kind::Double => {
                    let value = f64::from_bits(fargs[fp_index]);
                    fp_index += 1;
                    JavaArg::Double(value)
                }
                Kind::Object(name) if name == "java.lang.String" && is_global => {
                    match art::java::string_from_global_handle(raw[register] as usize)
                        .map_err(to_js_error)?
                    {
                        Some(value) => JavaArg::String(value),
                        None => JavaArg::Null,
                    }
                }
                Kind::Object(name) if is_global => {
                    let param_class = JavaClass::find(name).map_err(to_js_error)?;
                    let object = art::java::object_from_global_handle(
                        param_class.info.clone(),
                        raw[register] as usize,
                    )
                    .map_err(to_js_error)?;
                    JavaArg::Object(Rc::new(object))
                }
                Kind::Object(_) | Kind::Array(_) | Kind::Void => JavaArg::Null,
            })
        })
        .collect()
}

fn make_array<'js>(ctx: Ctx<'js>, type_name: String, values: Array<'js>) -> JsResult<Value<'js>> {
    if type_name != "int" {
        return Err(js_error("Java.array currently supports only 'int'"));
    }
    let mut ints = Vec::with_capacity(values.len());
    for index in 0..values.len() {
        let value: Value<'js> = values.get(index)?;
        ints.push(value.get::<i32>()?);
    }
    let object = art::java::new_int_array(&ints).map_err(to_js_error)?;
    let class = JavaClass::find("[I").map_err(to_js_error)?;
    let id = register(object);
    Ok(instance_object(ctx, class, id)?.into_value())
}

fn cast<'js>(ctx: Ctx<'js>, value: Value<'js>, class_name: String) -> JsResult<Value<'js>> {
    let id = java_id(&value).ok_or_else(|| js_error("Java.cast expects a Java object"))?;
    let object = get_object(id).ok_or_else(|| js_error("invalid Java object handle"))?;
    let class = JavaClass::find(&class_name).map_err(to_js_error)?;
    let casted = object.recast(class.info.clone()).map_err(to_js_error)?;
    let id = register(casted);
    Ok(instance_object(ctx, class, id)?.into_value())
}

fn value_to_js<'js>(ctx: Ctx<'js>, class: Rc<JavaClass>, value: JavaValue) -> JsResult<Value<'js>> {
    match value {
        JavaValue::Void => Ok(Value::new_undefined(ctx)),
        JavaValue::Boolean(value) => value.into_js(&ctx),
        JavaValue::Int(value) => value.into_js(&ctx),
        JavaValue::Long(value) => value.into_js(&ctx),
        JavaValue::Float(value) => value.into_js(&ctx),
        JavaValue::Double(value) => value.into_js(&ctx),
        JavaValue::String(value) => value.into_js(&ctx),
        JavaValue::Object(global) => {
            let object = JavaObject::from_global(class.info.clone(), global);
            let id = register(object);
            Ok(instance_object(ctx, class, id)?.into_value())
        }
    }
}

fn java_id(value: &Value<'_>) -> Option<u32> {
    if !value.is_object() {
        return None;
    }
    let object = value.as_object()?;
    object.get::<&str, u32>(HANDLE).ok()
}

fn register(object: JavaObject) -> u32 {
    OBJECTS.with(|objects| {
        let mut objects = objects.borrow_mut();
        objects.push(Rc::new(object));
        (objects.len() - 1) as u32
    })
}

fn get_object(id: u32) -> Option<Rc<JavaObject>> {
    OBJECTS.with(|objects| objects.borrow().get(id as usize).cloned())
}

fn to_js_error(error: runtime::Error) -> rquickjs::Error {
    js_error(error.to_string())
}

fn js_error(message: impl Into<String>) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("comm-analyser", "java", message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rquickjs::{Context, Runtime};

    #[test]
    fn js_string_matches_java_string() {
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        context.with(|ctx| {
            let value: Value = "abc".into_js(&ctx).unwrap();
            assert!(matches_kind(
                &Kind::Object("java.lang.String".into()),
                &value
            ));
        });
    }
}
