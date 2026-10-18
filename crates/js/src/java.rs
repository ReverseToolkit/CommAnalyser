//! Frida-style `Java` object: `Java.perform` and `Java.use`.
//!
//! The class/instance wrappers are plain JS objects with dynamically created
//! method properties.  JNI object references are kept in a thread-local table
//! and referenced from JS via a hidden `__analyserJavaId` property.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use rquickjs::function::Rest;
use rquickjs::prelude::Func;
use rquickjs::{Ctx, Function, IntoJs, Object, Result as JsResult, Value};

use art::java::{ClassInfo, CtorInfo, JavaArg, JavaClass, JavaObject, JavaValue, Kind, MethodInfo};

thread_local! {
    static OBJECTS: RefCell<Vec<Rc<JavaObject>>> = const { RefCell::new(Vec::new()) };
}

const HANDLE: &str = "__analyserJavaId";

pub(crate) fn install(ctx: &Ctx<'_>) -> JsResult<()> {
    let java = Object::new(ctx.clone())?;
    java.set("available", true)?;
    java.set("perform", Func::from(perform))?;
    java.set("use", Func::from(use_class))?;
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
                let object = ctor_class.new_object(&java_args).map_err(to_js_error)?;
                let id = register(object);
                Ok(instance_object(ctor_ctx.clone(), ctor_class.clone(), id)?.into_value())
            },
        ),
    )?;

    for (name, methods) in method_groups(&class.info, true) {
        let function = method_function(ctx.clone(), class.clone(), None, methods)?;
        wrapper.set(name, function)?;
    }
    Ok(wrapper)
}

fn instance_object<'js>(ctx: Ctx<'js>, class: Rc<JavaClass>, id: u32) -> JsResult<Object<'js>> {
    let wrapper = Object::new(ctx.clone())?;
    wrapper.set(HANDLE, id)?;
    wrapper.set("$className", class.info.name.clone())?;

    let object = get_object(id).ok_or_else(|| js_error("invalid Java object handle"))?;
    for (name, methods) in method_groups(&class.info, false) {
        let function = method_function(ctx.clone(), class.clone(), Some(object.clone()), methods)?;
        wrapper.set(name, function)?;
    }
    Ok(wrapper)
}

fn method_groups(info: &ClassInfo, static_methods: bool) -> BTreeMap<String, Vec<MethodInfo>> {
    let mut groups: BTreeMap<String, Vec<MethodInfo>> = BTreeMap::new();
    for method in &info.methods {
        if method.is_static == static_methods {
            groups
                .entry(method.name.clone())
                .or_default()
                .push(method.clone());
        }
    }
    groups
}

fn method_function<'js>(
    ctx: Ctx<'js>,
    class: Rc<JavaClass>,
    object: Option<Rc<JavaObject>>,
    methods: Vec<MethodInfo>,
) -> JsResult<Function<'js>> {
    let call_ctx = ctx.clone();
    Function::new(ctx, move |args: Rest<Value<'js>>| -> JsResult<Value<'js>> {
        let method = choose_method(&methods, &args.0)?;
        let java_args = convert_args(&args.0, &method.params)?;
        let value = match &object {
            Some(object) => object.call(method, &java_args),
            None => class.call_static(method, &java_args),
        }
        .map_err(to_js_error)?;
        value_to_js(call_ctx.clone(), class.clone(), value)
    })
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
            ctor.params.len() == args.len()
                && ctor
                    .params
                    .iter()
                    .zip(args)
                    .all(|(kind, value)| matches_kind(kind, value))
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

fn value_to_js<'js>(ctx: Ctx<'js>, class: Rc<JavaClass>, value: JavaValue) -> JsResult<Value<'js>> {
    match value {
        JavaValue::Void => Ok(Value::new_undefined(ctx)),
        JavaValue::Boolean(value) => value.into_js(&ctx),
        JavaValue::Int(value) => value.into_js(&ctx),
        JavaValue::Long(value) => value.into_js(&ctx),
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
