//! Script objects for `Il2Cpp.*`.
//!
//! Getters, invoke, replacement, tracing and filters are methods on these
//! objects. QuickJS only holds them.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use rquickjs::class::Trace;
use rquickjs::function::{Args, Opt, Rest, This};
use rquickjs::prelude::Func;
use rquickjs::{
    Array, Class, Ctx, Function, IntoJs, JsLifetime, Object, Persistent, Result as JsResult, Value,
};

use crate::api::{js_error, to_js_error, NativePointer};

fn session() -> JsResult<il2cpp::Runtime> {
    il2cpp::Runtime::session().map_err(to_js_error)
}

fn truthy(value: &Value<'_>) -> bool {
    if value.is_null() || value.is_undefined() {
        return false;
    }
    if let Some(flag) = value.as_bool() {
        return flag;
    }
    if let Some(number) = value.as_number() {
        return number != 0.0 && !number.is_nan();
    }
    if value.is_string() {
        return value
            .get::<String>()
            .ok()
            .is_some_and(|text| !text.is_empty());
    }
    true
}

fn value_handle(value: &Value<'_>) -> JsResult<u64> {
    if value.is_null() || value.is_undefined() {
        return Ok(0);
    }
    if let Some(object) = value.as_object() {
        if let Ok(handle) = object.get::<_, Value>("handle") {
            if !handle.is_undefined() && !handle.is_null() {
                return crate::api::parse_pointer(&handle);
            }
        }
    }
    crate::api::parse_pointer(value)
}

fn optional_handle(value: Opt<Value<'_>>) -> JsResult<u64> {
    match value.0 {
        Some(value) => value_handle(&value),
        None => Ok(0),
    }
}

fn read_u64(addr: u64) -> JsResult<u64> {
    let bytes = gum::memory::read(addr as usize, 8).map_err(to_js_error)?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| js_error("short memory read"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u64(addr: u64, value: u64) -> JsResult<()> {
    gum::memory::write(addr as usize, &value.to_le_bytes()).map_err(to_js_error)
}

fn frida_type(name: &str) -> &'static str {
    match name {
        "System.Void" => "void",
        "System.Boolean" => "bool",
        "System.Single" => "float",
        "System.Double" => "double",
        "System.Int64" | "System.IntPtr" => "int64",
        "System.UInt64" | "System.UIntPtr" => "uint64",
        "System.Int32" | "System.UInt32" | "System.Int16" | "System.UInt16" | "System.Byte"
        | "System.SByte" | "System.Char" => "int",
        _ => "pointer",
    }
}

fn argc_of(value: Opt<Value<'_>>) -> i32 {
    match value.0 {
        Some(value) if !value.is_null() && !value.is_undefined() => value.as_int().unwrap_or(-1),
        _ => -1,
    }
}

fn pointer<'js>(ctx: &Ctx<'js>, value: u64) -> JsResult<Value<'js>> {
    Ok(NativePointer::instance(ctx.clone(), value)?.into_value())
}

fn class_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    if handle == 0 {
        return Ok(Value::new_null(ctx.clone()));
    }
    Ok(Class::instance(ctx.clone(), ClassObject { handle })?.into_value())
}

fn method_value<'js>(ctx: &Ctx<'js>, handle: u64, receiver: Option<u64>) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), MethodObject { handle, receiver })?.into_value())
}

fn field_value<'js>(ctx: &Ctx<'js>, handle: u64, instance: Option<u64>) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), FieldObject { handle, instance })?.into_value())
}

fn type_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), TypeObject { handle })?.into_value())
}

fn object_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    if handle == 0 {
        return Ok(Value::new_null(ctx.clone()));
    }
    Ok(Class::instance(ctx.clone(), ObjectObject { handle })?.into_value())
}

fn string_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    if handle == 0 {
        return Ok(Value::new_null(ctx.clone()));
    }
    Ok(Class::instance(ctx.clone(), StringObject { handle })?.into_value())
}

fn image_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), ImageObject { handle })?.into_value())
}

fn assembly_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), AssemblyObject { handle })?.into_value())
}

fn domain_value<'js>(ctx: &Ctx<'js>, handle: u64) -> JsResult<Value<'js>> {
    Ok(Class::instance(ctx.clone(), DomainObject { handle })?.into_value())
}

fn handles_array<'js>(
    ctx: &Ctx<'js>,
    values: Vec<u64>,
    map: fn(&Ctx<'js>, u64) -> JsResult<Value<'js>>,
) -> JsResult<Array<'js>> {
    let array = Array::new(ctx.clone())?;
    for (index, handle) in values.into_iter().enumerate() {
        array.set(index, map(ctx, handle)?)?;
    }
    Ok(array)
}

fn lookup_method(class: il2cpp::Class, name: &str, argc: i32) -> JsResult<Option<u64>> {
    let runtime = session()?;
    if argc < 0 {
        for method in class.methods(&runtime).map_err(to_js_error)? {
            if method.name(&runtime).map_err(to_js_error)? == name {
                return Ok(Some(method.0));
            }
        }
        return Ok(None);
    }
    match class.method(&runtime, name, argc) {
        Ok(method) => Ok(Some(method.0)),
        Err(runtime::Error::NotFound(_)) => Ok(None),
        Err(err) => Err(to_js_error(err)),
    }
}

fn lookup_field(class: il2cpp::Class, name: &str) -> JsResult<Option<u64>> {
    let runtime = session()?;
    match class.field(&runtime, name) {
        Ok(field) => Ok(Some(field.0)),
        Err(runtime::Error::NotFound(_)) => Ok(None),
        Err(err) => Err(to_js_error(err)),
    }
}

fn find_instance_field(class: il2cpp::Class, name: &str) -> JsResult<Option<u64>> {
    let runtime = session()?;
    let mut current = Some(class);
    while let Some(class) = current {
        if let Some(field) = lookup_field(class, name)? {
            return Ok(Some(field));
        }
        current = class.parent(&runtime).map_err(to_js_error)?;
    }
    Ok(None)
}

fn require_method<'js>(
    ctx: &Ctx<'js>,
    class: u64,
    name: &str,
    argc: i32,
    receiver: Option<u64>,
) -> JsResult<Value<'js>> {
    let runtime = session()?;
    let class = il2cpp::Class(class);
    match lookup_method(class, name, argc)? {
        Some(handle) => method_value(ctx, handle, receiver),
        None => {
            let full = class.full_name(&runtime).map_err(to_js_error)?;
            Err(js_error(format!(
                "couldn't find method {name} in class {full}"
            )))
        }
    }
}

fn to_native<'js>(ctx: &Ctx<'js>, value: Value<'js>) -> JsResult<Value<'js>> {
    if value.is_null() || value.is_undefined() {
        return pointer(ctx, 0);
    }
    if let Some(object) = value.as_object() {
        if let Ok(handle) = object.get::<_, Value>("handle") {
            if !handle.is_undefined() && !handle.is_null() && truthy(&handle) {
                return Ok(handle);
            }
        }
    }
    Ok(value)
}

fn from_native<'js>(ctx: &Ctx<'js>, value: Value<'js>, type_handle: u64) -> JsResult<Value<'js>> {
    let runtime = session()?;
    let ty = il2cpp::Type(type_handle);
    let name = ty.name(&runtime).map_err(to_js_error)?;
    match frida_type(&name) {
        "void" => Ok(Value::new_undefined(ctx.clone())),
        "bool" => i32::from(truthy(&value)).into_js(ctx),
        "pointer" => from_pointer(ctx, value, &name, type_handle),
        _ => Ok(value),
    }
}

fn from_pointer<'js>(
    ctx: &Ctx<'js>,
    value: Value<'js>,
    name: &str,
    type_handle: u64,
) -> JsResult<Value<'js>> {
    if value.is_null() || value.is_undefined() {
        return Ok(Value::new_null(ctx.clone()));
    }
    let Ok(addr) = crate::api::parse_pointer(&value) else {
        return Ok(value);
    };
    if addr == 0 {
        return Ok(Value::new_null(ctx.clone()));
    }
    if name == "System.String" {
        return string_value(ctx, addr);
    }
    let runtime = session()?;
    let class = il2cpp::Type(type_handle)
        .class(&runtime)
        .map_err(to_js_error)?;
    if class.is_value_type(&runtime).map_err(to_js_error)? {
        return Ok(value);
    }
    object_value(ctx, addr)
}

fn call_native<'js>(
    ctx: &Ctx<'js>,
    address: u64,
    ret: &str,
    types: &[String],
    values: Vec<Value<'js>>,
) -> JsResult<Value<'js>> {
    let constructor: Function = ctx.globals().get("NativeFunction")?;
    let arg_types = Array::new(ctx.clone())?;
    for (index, ty) in types.iter().enumerate() {
        arg_types.set(index, ty.clone())?;
    }
    let function: Function =
        constructor.call((pointer(ctx, address)?, ret.to_owned(), arg_types))?;
    let mut args = Args::new(ctx.clone(), values.len());
    args.push_args(values)?;
    function.call_arg(args)
}

fn invoke_method<'js>(
    method: &MethodObject,
    ctx: Ctx<'js>,
    instance: Value<'js>,
    args: Vec<Value<'js>>,
) -> JsResult<Value<'js>> {
    let runtime = session()?;
    let native = il2cpp::Method(method.handle);
    let name = native.name(&runtime).map_err(to_js_error)?;
    let count = native.param_count(&runtime).map_err(to_js_error)?;
    if args.len() != count as usize {
        return Err(js_error(format!(
            "couldn't invoke method {name} as it needs {count} parameter(s), not {}",
            args.len()
        )));
    }
    let mut types = Vec::new();
    let mut values = Vec::new();
    if native.is_instance(&runtime).map_err(to_js_error)?
        || !native.is_static(&runtime).map_err(to_js_error)?
    {
        types.push("pointer".to_owned());
        values.push(to_native(&ctx, instance)?);
    }
    for (index, arg) in args.into_iter().enumerate() {
        let param = native
            .param_type(&runtime, index as u32)
            .map_err(to_js_error)?;
        let param_name = param.name(&runtime).map_err(to_js_error)?;
        types.push(frida_type(&param_name).to_owned());
        values.push(to_native(&ctx, arg)?);
    }
    // Inflated methods take the MethodInfo pointer as a hidden last argument.
    if native.is_inflated(&runtime).map_err(to_js_error)? {
        types.push("pointer".to_owned());
        values.push(pointer(&ctx, method.handle)?);
    }
    let ret = native.return_type(&runtime).map_err(to_js_error)?;
    let ret_name = ret.name(&runtime).map_err(to_js_error)?;
    let mut runtime = runtime;
    let address = native.virtual_address(&mut runtime).map_err(to_js_error)?;
    let result = call_native(&ctx, address, frida_type(&ret_name), &types, values)?;
    from_native(&ctx, result, ret.0)
}

fn argument_list<'js>(parameters: Opt<Value<'js>>) -> JsResult<Vec<Value<'js>>> {
    match parameters.0 {
        Some(value) if value.is_null() || value.is_undefined() => Ok(Vec::new()),
        None => Ok(Vec::new()),
        Some(value) => {
            let array: Array = value
                .get()
                .map_err(|_| js_error("parameters must be an array"))?;
            let mut args = Vec::with_capacity(array.len());
            for index in 0..array.len() {
                args.push(array.get(index)?);
            }
            Ok(args)
        }
    }
}

fn class_handles(values: &[Value<'_>]) -> JsResult<Vec<il2cpp::Class>> {
    values
        .iter()
        .map(|value| Ok(il2cpp::Class(value_handle(value)?)))
        .collect()
}

fn js_print(ctx: &Ctx<'_>, text: &str) -> JsResult<()> {
    let print: Function = ctx.globals().get("print")?;
    print.call((text.to_owned(),))
}

fn hex_i32(value: i32) -> String {
    if value < 0 {
        format!("-{:x}", value.unsigned_abs())
    } else {
        format!("{value:x}")
    }
}

fn main_module_name(ctx: &Ctx<'_>) -> JsResult<String> {
    let process: Object = ctx.globals().get("Process")?;
    let main: Value = process.get("mainModule")?;
    if main.is_null() || main.is_undefined() {
        return Ok(String::new());
    }
    let main: Object = main.get()?;
    main.get("name")
}

fn unity_string(method: &str) -> JsResult<Option<String>> {
    let runtime = session()?;
    match runtime.application_string(method).map_err(to_js_error)? {
        Some(text) if !text.is_empty() => Ok(Some(text)),
        _ => Ok(None),
    }
}

fn read_type_array<'js>(ctx: &Ctx<'js>, array: u64) -> JsResult<Array<'js>> {
    let runtime = session()?;
    let length = runtime.array_length(array).map_err(to_js_error)?;
    let out = Array::new(ctx.clone())?;
    for index in 0..length {
        // Il2CppArray on 64-bit: 16-byte header, bounds, max_length, then elements.
        let slot = read_u64(array.wrapping_add(32 + u64::from(index) * 8))?;
        let class = runtime
            .exports
            .call(runtime.exports.class_from_system_type, &[slot])
            .map_err(to_js_error)?;
        out.set(index as usize, class_value(ctx, class)?)?;
    }
    Ok(out)
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Type")]
struct TypeObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl TypeObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Type(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn class<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let class = il2cpp::Type(self.handle)
            .class(&session()?)
            .map_err(to_js_error)?;
        class_value(&ctx, class.0)
    }

    #[qjs(get, rename = "enumValue")]
    fn enum_value(&self) -> JsResult<i32> {
        il2cpp::Type(self.handle)
            .enum_value(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn object<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let object = runtime
            .exports
            .call(runtime.exports.type_get_object, &[self.handle])
            .map_err(to_js_error)?;
        object_value(&ctx, object)
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> JsResult<String> {
        self.name()
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Parameter")]
struct ParameterObject {
    method: u64,
    index: u32,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl ParameterObject {
    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Method(self.method)
            .param_name(&session()?, self.index)
            .map_err(to_js_error)
    }

    #[qjs(get, rename = "type")]
    fn type_<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let ty = il2cpp::Method(self.method)
            .param_type(&session()?, self.index)
            .map_err(to_js_error)?;
        type_value(&ctx, ty.0)
    }

    #[qjs(get)]
    fn position(&self) -> u32 {
        self.index
    }

    #[qjs(rename = "toString")]
    fn text<'js>(&self, ctx: Ctx<'js>) -> JsResult<String> {
        let ty: Object = self.type_(ctx)?.get()?;
        let type_name: String = ty.get("name")?;
        Ok(format!("{type_name} {}", self.name()?))
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Method")]
struct MethodObject {
    handle: u64,
    receiver: Option<u64>,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl MethodObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn object<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let object = runtime
            .exports
            .call(runtime.exports.method_get_object, &[self.handle, 0])
            .map_err(to_js_error)?;
        object_value(&ctx, object)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Method(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn class<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let class = il2cpp::Method(self.handle)
            .class(&session()?)
            .map_err(to_js_error)?;
        class_value(&ctx, class.0)
    }

    #[qjs(get)]
    fn is_static(&self) -> JsResult<bool> {
        il2cpp::Method(self.handle)
            .is_static(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_generic(&self) -> JsResult<bool> {
        il2cpp::Method(self.handle)
            .is_generic(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_inflated(&self) -> JsResult<bool> {
        il2cpp::Method(self.handle)
            .is_inflated(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn parameter_count(&self) -> JsResult<u32> {
        il2cpp::Method(self.handle)
            .param_count(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn return_type<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let ty = il2cpp::Method(self.handle)
            .return_type(&session()?)
            .map_err(to_js_error)?;
        type_value(&ctx, ty.0)
    }

    #[qjs(get)]
    fn virtual_address<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.virtual_address_raw()?)
    }

    #[qjs(get)]
    fn relative_virtual_address<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let base = session()?.module.base as u64;
        pointer(&ctx, self.virtual_address_raw()?.wrapping_sub(base))
    }

    #[qjs(get)]
    fn parameters<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let count = self.parameter_count()?;
        let array = Array::new(ctx.clone())?;
        for index in 0..count {
            array.set(
                index as usize,
                Class::instance(
                    ctx.clone(),
                    ParameterObject {
                        method: self.handle,
                        index,
                    },
                )?,
            )?;
        }
        Ok(array)
    }

    fn invoke<'js>(&self, ctx: Ctx<'js>, args: Rest<Value<'js>>) -> JsResult<Value<'js>> {
        if self.receiver.is_none() && !self.is_static()? {
            return Err(js_error(format!(
                "cannot invoke non-static method {} as it must be invoked throught a Il2Cpp.Object, not a Il2Cpp.Class",
                self.name()?
            )));
        }
        let instance = pointer(&ctx, self.receiver.unwrap_or(0))?;
        invoke_method(self, ctx, instance, args.0)
    }

    fn invoke_raw<'js>(
        &self,
        ctx: Ctx<'js>,
        instance: Value<'js>,
        parameters: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        invoke_method(self, ctx, instance, argument_list(parameters)?)
    }

    #[qjs(get, rename = "implementation")]
    fn get_implementation<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        // Reading the property is undefined. A getter is required so the setter
        // pairs with it; a set-only accessor miscompiles on rquickjs 0.14.
        Ok(Value::new_undefined(ctx))
    }

    #[qjs(set, rename = "implementation")]
    fn set_implementation<'js>(&self, ctx: Ctx<'js>, function: Function<'js>) -> JsResult<()> {
        let runtime = session()?;
        let native = il2cpp::Method(self.handle);
        let name = native.name(&runtime).map_err(to_js_error)?;
        let mut runtime = runtime;
        let address = native.virtual_address(&mut runtime).map_err(to_js_error)?;
        if address == 0 {
            return Err(js_error(format!(
                "couldn't set implementation for method {name} as it has a NULL virtual address"
            )));
        }
        let pass_instance = native.is_instance(&runtime).map_err(to_js_error)?
            || !native.is_static(&runtime).map_err(to_js_error)?;
        let is_static = native.is_static(&runtime).map_err(to_js_error)?;
        let class_handle = native.class(&runtime).map_err(to_js_error)?.0;
        let count = native.param_count(&runtime).map_err(to_js_error)?;
        let mut arg_types = Vec::new();
        let mut param_types = Vec::new();
        if pass_instance {
            arg_types.push("pointer".to_owned());
        }
        for index in 0..count {
            let param = native.param_type(&runtime, index).map_err(to_js_error)?;
            let param_name = param.name(&runtime).map_err(to_js_error)?;
            arg_types.push(frida_type(&param_name).to_owned());
            param_types.push(param.0);
        }
        let ret = native.return_type(&runtime).map_err(to_js_error)?;
        let ret_name = frida_type(&ret.name(&runtime).map_err(to_js_error)?).to_owned();
        let wrapper = Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, args: Rest<Value<'js>>| -> JsResult<Value<'js>> {
                let mut incoming = args.0;
                let receiver = if pass_instance && !incoming.is_empty() {
                    Some(incoming.remove(0))
                } else {
                    None
                };
                let mut converted = Vec::with_capacity(incoming.len());
                for (index, arg) in incoming.into_iter().enumerate() {
                    match param_types.get(index).copied() {
                        Some(type_handle) => converted.push(from_native(&ctx, arg, type_handle)?),
                        None => converted.push(arg),
                    }
                }
                let mut call = Args::new(ctx.clone(), converted.len());
                if pass_instance {
                    let this_value = if is_static {
                        class_value(&ctx, class_handle)?
                    } else {
                        object_value(
                            &ctx,
                            receiver
                                .as_ref()
                                .map(value_handle)
                                .transpose()?
                                .unwrap_or(0),
                        )?
                    };
                    call.this(this_value)?;
                }
                call.push_args(converted)?;
                let result: Value = function.call_arg(call)?;
                to_native(&ctx, result)
            },
        )?;
        let callback_ctor: Function = ctx.globals().get("NativeCallback")?;
        let types = Array::new(ctx.clone())?;
        for (index, ty) in arg_types.iter().enumerate() {
            types.set(index, ty.clone())?;
        }
        let callback: Value = callback_ctor.call((wrapper, ret_name, types))?;
        let interceptor: Object = ctx.globals().get("Interceptor")?;
        let replace: Function = interceptor.get("replace")?;
        if let Err(err) = replace.call::<_, Value>((pointer(&ctx, address)?, callback)) {
            let message = err.to_string();
            if message.contains("0x0") {
                return Err(js_error(format!(
                    "couldn't set implementation for method {name} as it has a NULL virtual address"
                )));
            }
            return Err(err);
        }
        Ok(())
    }

    fn revert<'js>(&self, ctx: Ctx<'js>) -> JsResult<()> {
        let address = pointer(&ctx, self.virtual_address_raw()?)?;
        let interceptor: Object = ctx.globals().get("Interceptor")?;
        let revert: Function = interceptor.get("revert")?;
        let flush: Function = interceptor.get("flush")?;
        revert.call::<_, Value>((address,))?;
        flush.call::<_, ()>(())?;
        Ok(())
    }

    fn overload<'js>(&self, ctx: Ctx<'js>, args: Rest<Value<'js>>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let native = il2cpp::Method(self.handle);
        let mut specs = Vec::with_capacity(args.0.len());
        for arg in &args.0 {
            if arg.is_string() {
                specs.push(il2cpp::OverloadSpec::Name(arg.get()?));
            } else {
                specs.push(il2cpp::OverloadSpec::Class(il2cpp::Class(value_handle(
                    arg,
                )?)));
            }
        }
        match native.overload(&runtime, &specs) {
            Ok(found) => method_value(&ctx, found.0, None),
            Err(_) => Err(js_error(format!(
                "couldn't find overloaded method {}",
                self.name()?
            ))),
        }
    }

    fn inflate<'js>(&self, ctx: Ctx<'js>, args: Rest<Value<'js>>) -> JsResult<Value<'js>> {
        let mut runtime = session()?;
        let found = il2cpp::Method(self.handle)
            .inflate(&mut runtime, &class_handles(&args.0)?)
            .map_err(to_js_error)?;
        method_value(&ctx, found.0, None)
    }

    #[qjs(rename = "toString")]
    fn text<'js>(&self, ctx: Ctx<'js>) -> JsResult<String> {
        let count = self.parameter_count()?;
        let mut rendered = Vec::with_capacity(count as usize);
        for index in 0..count {
            rendered.push(
                ParameterObject {
                    method: self.handle,
                    index,
                }
                .text(ctx.clone())?,
            );
        }
        let ret: Object = self.return_type(ctx)?.get()?;
        let ret_name: String = ret.get("name")?;
        let address = self.virtual_address_raw()?;
        let suffix = if address == 0 {
            String::new()
        } else {
            let rva = address.wrapping_sub(session()?.module.base as u64);
            format!(" // 0x{rva:x}")
        };
        let prefix = if self.is_static()? { "static " } else { "" };
        Ok(format!(
            "{prefix}{ret_name} {}({});{suffix}",
            self.name()?,
            rendered.join(", ")
        ))
    }
}

impl MethodObject {
    fn virtual_address_raw(&self) -> JsResult<u64> {
        let mut runtime = session()?;
        il2cpp::Method(self.handle)
            .virtual_address(&mut runtime)
            .map_err(to_js_error)
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Field")]
struct FieldObject {
    handle: u64,
    instance: Option<u64>,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl FieldObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Field(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn offset(&self) -> JsResult<i32> {
        il2cpp::Field(self.handle)
            .offset(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_static(&self) -> JsResult<bool> {
        il2cpp::Field(self.handle)
            .is_static(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_literal(&self) -> JsResult<bool> {
        il2cpp::Field(self.handle)
            .is_literal(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get, rename = "type")]
    fn type_<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let ty = il2cpp::Field(self.handle)
            .type_(&session()?)
            .map_err(to_js_error)?;
        type_value(&ctx, ty.0)
    }

    #[qjs(get, rename = "value")]
    fn get_value<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let field = il2cpp::Field(self.handle);
        let ty = field.type_(&runtime).map_err(to_js_error)?.0;
        let bits = if let Some(instance) = self.instance {
            let offset = field.offset(&runtime).map_err(to_js_error)?;
            read_u64(instance.wrapping_add(offset as i64 as u64))?
        } else if !field.is_static(&runtime).map_err(to_js_error)? {
            return Err(js_error(format!(
                "cannot access instance field {} from the class; use object.field",
                self.name()?
            )));
        } else {
            field.static_pointer(&runtime).map_err(to_js_error)?
        };
        from_native(&ctx, pointer(&ctx, bits)?, ty)
    }

    #[qjs(set, rename = "value")]
    fn set_value<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<()> {
        let runtime = session()?;
        let field = il2cpp::Field(self.handle);
        let native = to_native(&ctx, value)?;
        let bits = crate::api::parse_pointer(&native)?;
        if let Some(instance) = self.instance {
            let offset = field.offset(&runtime).map_err(to_js_error)?;
            return write_u64(instance.wrapping_add(offset as i64 as u64), bits);
        }
        if !field.is_static(&runtime).map_err(to_js_error)? {
            return Err(js_error(format!(
                "cannot set instance field {} from the class; use object.field",
                self.name()?
            )));
        }
        runtime
            .exports
            .call(
                runtime.exports.field_static_set_value,
                &[self.handle, &bits as *const u64 as u64],
            )
            .map_err(to_js_error)?;
        Ok(())
    }

    #[qjs(rename = "toString")]
    fn text<'js>(&self, ctx: Ctx<'js>) -> JsResult<String> {
        let ty: Object = self.type_(ctx)?.get()?;
        let type_name: String = ty.get("name")?;
        let prefix = if self.is_static()? { "static " } else { "" };
        Ok(format!(
            "{prefix}{type_name} {}; // 0x{}",
            self.name()?,
            hex_i32(self.offset()?)
        ))
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Class")]
struct ClassObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl ClassObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Class(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn namespace(&self) -> JsResult<String> {
        il2cpp::Class(self.handle)
            .namespace(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn full_name(&self) -> JsResult<String> {
        il2cpp::Class(self.handle)
            .full_name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn parent<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let parent = il2cpp::Class(self.handle)
            .parent(&session()?)
            .map_err(to_js_error)?;
        class_value(&ctx, parent.map(|class| class.0).unwrap_or(0))
    }

    #[qjs(get)]
    fn flags(&self) -> JsResult<i32> {
        il2cpp::Class(self.handle)
            .flags(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn instance_size(&self) -> JsResult<i32> {
        il2cpp::Class(self.handle)
            .instance_size(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_enum(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_enum(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_value_type(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_value_type(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_interface(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_interface(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_abstract(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_abstract(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_generic(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_generic(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn is_inflated(&self) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_inflated(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn image<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let image = runtime
            .exports
            .call(runtime.exports.class_get_image, &[self.handle])
            .map_err(to_js_error)?;
        image_value(&ctx, image)
    }

    #[qjs(get, rename = "type")]
    fn type_<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let ty = runtime
            .exports
            .call(runtime.exports.class_get_type, &[self.handle])
            .map_err(to_js_error)?;
        type_value(&ctx, ty)
    }

    #[qjs(get)]
    fn methods<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let methods = il2cpp::Class(self.handle)
            .methods(&session()?)
            .map_err(to_js_error)?;
        handles_array(
            &ctx,
            methods.into_iter().map(|method| method.0).collect(),
            |ctx, handle| method_value(ctx, handle, None),
        )
    }

    #[qjs(get)]
    fn fields<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let fields = il2cpp::Class(self.handle)
            .fields(&session()?)
            .map_err(to_js_error)?;
        handles_array(
            &ctx,
            fields.into_iter().map(|field| field.0).collect(),
            |ctx, handle| field_value(ctx, handle, None),
        )
    }

    #[qjs(get)]
    fn nested_classes<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let nested = il2cpp::Class(self.handle)
            .nested(&session()?)
            .map_err(to_js_error)?;
        handles_array(
            &ctx,
            nested.into_iter().map(|class| class.0).collect(),
            class_value,
        )
    }

    fn method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        require_method(&ctx, self.handle, &name, argc_of(argc), None)
    }

    fn try_method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        match lookup_method(il2cpp::Class(self.handle), &name, argc_of(argc))? {
            Some(handle) => method_value(&ctx, handle, None),
            None => Ok(Value::new_null(ctx)),
        }
    }

    fn field<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        match lookup_field(il2cpp::Class(self.handle), &name)? {
            Some(handle) => field_value(&ctx, handle, None),
            None => Err(js_error(format!(
                "couldn't find field {name} in class {}",
                self.full_name()?
            ))),
        }
    }

    fn try_field<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        match lookup_field(il2cpp::Class(self.handle), &name)? {
            Some(handle) => field_value(&ctx, handle, None),
            None => Ok(Value::new_null(ctx)),
        }
    }

    fn nested<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        let runtime = session()?;
        for class in il2cpp::Class(self.handle)
            .nested(&runtime)
            .map_err(to_js_error)?
        {
            if class.name(&runtime).map_err(to_js_error)? == name {
                return class_value(&ctx, class.0);
            }
        }
        Err(js_error(format!("couldn't find nested class {name}")))
    }

    fn hierarchy<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let runtime = session()?;
        let array = Array::new(ctx.clone())?;
        let mut current = Some(il2cpp::Class(self.handle));
        let mut index = 0usize;
        while let Some(class) = current {
            array.set(index, class_value(&ctx, class.0)?)?;
            index += 1;
            current = class.parent(&runtime).map_err(to_js_error)?;
        }
        Ok(array)
    }

    fn initialize<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        il2cpp::Runtime::class_init(&session()?, self.handle).map_err(to_js_error)?;
        class_value(&ctx, self.handle)
    }

    fn is_assignable_from(&self, other: Value<'_>) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_assignable_from(&session()?, il2cpp::Class(value_handle(&other)?))
            .map_err(to_js_error)
    }

    fn is_subclass_of(&self, other: Value<'_>, interfaces: Opt<bool>) -> JsResult<bool> {
        il2cpp::Class(self.handle)
            .is_subclass_of(
                &session()?,
                il2cpp::Class(value_handle(&other)?),
                interfaces.0.unwrap_or(false),
            )
            .map_err(to_js_error)
    }

    #[qjs(rename = "new")]
    fn instantiate<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let object = il2cpp::Class(self.handle)
            .new_object(&session()?)
            .map_err(to_js_error)?;
        object_value(&ctx, object)
    }

    fn alloc<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let object = il2cpp::Class(self.handle)
            .alloc(&session()?)
            .map_err(to_js_error)?;
        object_value(&ctx, object)
    }

    fn inflate<'js>(&self, ctx: Ctx<'js>, args: Rest<Value<'js>>) -> JsResult<Value<'js>> {
        let mut runtime = session()?;
        let found = il2cpp::Class(self.handle)
            .inflate(&mut runtime, &class_handles(&args.0)?)
            .map_err(to_js_error)?;
        class_value(&ctx, found.0)
    }

    #[qjs(get)]
    fn generics<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let runtime = session()?;
        let class = il2cpp::Class(self.handle);
        if !class.is_generic(&runtime).map_err(to_js_error)?
            && !class.is_inflated(&runtime).map_err(to_js_error)?
        {
            return Array::new(ctx);
        }
        let ty = runtime
            .exports
            .call(runtime.exports.class_get_type, &[self.handle])
            .map_err(to_js_error)?;
        let type_object = runtime
            .exports
            .call(runtime.exports.type_get_object, &[ty])
            .map_err(to_js_error)?;
        let owner = runtime.object_class(type_object).map_err(to_js_error)?;
        let Some(method) = lookup_method(owner, "GetGenericArguments", 0)? else {
            let full = owner.full_name(&runtime).map_err(to_js_error)?;
            return Err(js_error(format!(
                "couldn't find method GetGenericArguments in class {full}"
            )));
        };
        let value = MethodObject {
            handle: method,
            receiver: Some(type_object),
        }
        .invoke(ctx.clone(), Rest(Vec::new()))?;
        if value.is_null() || value.is_undefined() || !truthy(&value) {
            return Array::new(ctx);
        }
        read_type_array(&ctx, value_handle(&value)?)
    }

    #[qjs(get)]
    fn value_type_size(&self) -> JsResult<i32> {
        let runtime = session()?;
        let mut align = 0u32;
        let size = runtime
            .exports
            .call(
                runtime.exports.class_value_size,
                &[self.handle, &mut align as *mut u32 as u64],
            )
            .map_err(to_js_error)?;
        Ok(size as i32)
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> JsResult<String> {
        self.full_name()
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Image")]
struct ImageObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl ImageObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Image(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn assembly<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let runtime = session()?;
        let assembly = runtime
            .exports
            .call(runtime.exports.image_get_assembly, &[self.handle])
            .map_err(to_js_error)?;
        assembly_value(&ctx, assembly)
    }

    #[qjs(get)]
    fn class_count(&self) -> JsResult<u32> {
        il2cpp::Image(self.handle)
            .class_count(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(get)]
    fn classes<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let classes = il2cpp::Image(self.handle)
            .classes(&session()?)
            .map_err(to_js_error)?;
        handles_array(
            &ctx,
            classes.into_iter().map(|class| class.0).collect(),
            class_value,
        )
    }

    fn class<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        let found = self.try_class(ctx.clone(), name.clone())?;
        if found.is_null() {
            Err(js_error(format!(
                "couldn't find class {name} in assembly {}",
                self.name()?
            )))
        } else {
            Ok(found)
        }
    }

    fn try_class<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        let found = il2cpp::Image(self.handle)
            .try_class(&session()?, &name)
            .map_err(to_js_error)?;
        class_value(&ctx, found.map(|class| class.0).unwrap_or(0))
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> JsResult<String> {
        self.name()
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Assembly")]
struct AssemblyObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl AssemblyObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn image<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let image = il2cpp::Assembly(self.handle)
            .image(&session()?)
            .map_err(to_js_error)?;
        image_value(&ctx, image.0)
    }

    #[qjs(get)]
    fn name(&self) -> JsResult<String> {
        il2cpp::Assembly(self.handle)
            .name(&session()?)
            .map_err(to_js_error)
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> JsResult<String> {
        self.name()
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Domain")]
struct DomainObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl DomainObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn assemblies<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let assemblies = il2cpp::Domain(self.handle)
            .assemblies(&session()?)
            .map_err(to_js_error)?;
        handles_array(
            &ctx,
            assemblies.into_iter().map(|assembly| assembly.0).collect(),
            assembly_value,
        )
    }

    fn assembly<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        let found = self.try_assembly(ctx.clone(), name.clone())?;
        if found.is_null() {
            Err(js_error(format!("couldn't find assembly {name}")))
        } else {
            Ok(found)
        }
    }

    fn try_assembly<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        let found = il2cpp::Domain(self.handle)
            .try_assembly(&session()?, &name)
            .map_err(to_js_error)?;
        assembly_value(&ctx, found.map(|assembly| assembly.0).unwrap_or(0))
    }

    fn attach<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, session()?.thread_current().map_err(to_js_error)?)
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> String {
        "[Il2Cpp.Domain]".to_owned()
    }
}

fn object_text(handle: u64, ctx: Ctx<'_>) -> JsResult<String> {
    let runtime = session()?;
    let class = runtime.object_class(handle).map_err(to_js_error)?;
    let full = class.full_name(&runtime).map_err(to_js_error)?;
    let Some(method) = lookup_method(class, "ToString", 0)? else {
        return Ok(full);
    };
    if full == "System.Object" {
        return Ok(full);
    }
    let value = MethodObject {
        handle: method,
        receiver: Some(handle),
    }
    .invoke(ctx, Rest(Vec::new()))?;
    if let Some(object) = value.as_object() {
        if let Ok(content) = object.get::<_, String>("content") {
            if !content.is_empty() {
                return Ok(content);
            }
        }
    }
    Ok(full)
}

fn bound_method<'js>(
    handle: u64,
    ctx: Ctx<'js>,
    name: String,
    argc: Opt<Value<'js>>,
) -> JsResult<Value<'js>> {
    let class = session()?.object_class(handle).map_err(to_js_error)?;
    require_method(&ctx, class.0, &name, argc_of(argc), Some(handle))
}

fn try_bound_method<'js>(
    handle: u64,
    ctx: Ctx<'js>,
    name: String,
    argc: Opt<Value<'js>>,
) -> JsResult<Value<'js>> {
    let class = session()?.object_class(handle).map_err(to_js_error)?;
    match lookup_method(class, &name, argc_of(argc))? {
        Some(method) => method_value(&ctx, method, Some(handle)),
        None => Ok(Value::new_null(ctx)),
    }
}

fn bound_field<'js>(handle: u64, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
    let class = session()?.object_class(handle).map_err(to_js_error)?;
    match find_instance_field(class, &name)? {
        Some(field) => field_value(&ctx, field, Some(handle)),
        None => Err(js_error(format!("couldn't find non-static field {name}"))),
    }
}

fn bound_unbox<'js>(handle: u64, ctx: Ctx<'js>) -> JsResult<Object<'js>> {
    let runtime = session()?;
    let class = runtime.object_class(handle).map_err(to_js_error)?;
    let ty = runtime
        .exports
        .call(runtime.exports.class_get_type, &[class.0])
        .map_err(to_js_error)?;
    let unboxed = runtime.unbox(handle).map_err(to_js_error)?;
    let object = Object::new(ctx.clone())?;
    object.set("handle", pointer(&ctx, unboxed)?)?;
    object.set("type", type_value(&ctx, ty)?)?;
    Ok(object)
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Object")]
struct ObjectObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl ObjectObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn class<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let class = session()?.object_class(self.handle).map_err(to_js_error)?;
        class_value(&ctx, class.0)
    }

    fn method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        bound_method(self.handle, ctx, name, argc)
    }

    fn try_method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        try_bound_method(self.handle, ctx, name, argc)
    }

    fn field<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        bound_field(self.handle, ctx, name)
    }

    #[qjs(rename = "toString")]
    fn text<'js>(&self, ctx: Ctx<'js>) -> JsResult<String> {
        object_text(self.handle, ctx)
    }

    fn unbox<'js>(&self, ctx: Ctx<'js>) -> JsResult<Object<'js>> {
        bound_unbox(self.handle, ctx)
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "String")]
struct StringObject {
    handle: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl StringObject {
    #[qjs(get)]
    fn handle<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, self.handle)
    }

    #[qjs(get)]
    fn class<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        let class = session()?.object_class(self.handle).map_err(to_js_error)?;
        class_value(&ctx, class.0)
    }

    #[qjs(get)]
    fn content(&self) -> JsResult<String> {
        session()?.string_utf16(self.handle).map_err(to_js_error)
    }

    #[qjs(get)]
    fn length(&self) -> JsResult<i32> {
        session()?.string_length(self.handle).map_err(to_js_error)
    }

    fn method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        bound_method(self.handle, ctx, name, argc)
    }

    fn try_method<'js>(
        &self,
        ctx: Ctx<'js>,
        name: String,
        argc: Opt<Value<'js>>,
    ) -> JsResult<Value<'js>> {
        try_bound_method(self.handle, ctx, name, argc)
    }

    fn field<'js>(&self, ctx: Ctx<'js>, name: String) -> JsResult<Value<'js>> {
        bound_field(self.handle, ctx, name)
    }

    fn unbox<'js>(&self, ctx: Ctx<'js>) -> JsResult<Object<'js>> {
        bound_unbox(self.handle, ctx)
    }

    #[qjs(rename = "toString")]
    fn text(&self) -> JsResult<String> {
        self.content()
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "GC")]
struct GcObject {}

#[rquickjs::methods(rename_all = "camelCase")]
impl GcObject {
    #[qjs(get)]
    fn heap_size(&self) -> JsResult<u64> {
        session()?.gc_heap_size().map_err(to_js_error)
    }

    #[qjs(get)]
    fn used_size(&self) -> JsResult<u64> {
        session()?.gc_used_size().map_err(to_js_error)
    }

    fn collect(&self, generation: Opt<i32>) -> JsResult<()> {
        session()?
            .gc_collect(generation.0.unwrap_or(0))
            .map_err(to_js_error)
    }

    fn stop_world(&self) -> JsResult<()> {
        let runtime = session()?;
        runtime
            .exports
            .call(runtime.exports.stop_gc_world, &[])
            .map_err(to_js_error)?;
        Ok(())
    }

    fn start_world(&self) -> JsResult<()> {
        let runtime = session()?;
        runtime
            .exports
            .call(runtime.exports.start_gc_world, &[])
            .map_err(to_js_error)?;
        Ok(())
    }

    fn choose<'js>(&self, ctx: Ctx<'js>, klass: Value<'js>) -> JsResult<Array<'js>> {
        let found = session()?
            .choose(il2cpp::Class(value_handle(&klass)?))
            .map_err(to_js_error)?;
        handles_array(&ctx, found, object_value)
    }
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Application")]
struct ApplicationObject {}

#[rquickjs::methods(rename_all = "camelCase")]
impl ApplicationObject {
    #[qjs(get)]
    fn data_path<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        match unity_string("get_persistentDataPath")? {
            Some(text) => text.into_js(&ctx),
            None => Ok(Value::new_null(ctx)),
        }
    }

    #[qjs(get)]
    fn identifier<'js>(&self, ctx: Ctx<'js>) -> JsResult<String> {
        if let Some(text) = unity_string("get_identifier")? {
            return Ok(text);
        }
        if let Some(text) = unity_string("get_bundleIdentifier")? {
            return Ok(text);
        }
        main_module_name(&ctx)
    }

    #[qjs(get)]
    fn version(&self) -> JsResult<String> {
        Ok(unity_string("get_version")?.unwrap_or_default())
    }
}

#[derive(Default)]
struct TracerState {
    methods: Option<Vec<u64>>,
    classes: Option<Vec<u64>>,
    assemblies: Option<Vec<u64>>,
    domain: bool,
    method_filter: Option<Persistent<Function<'static>>>,
    class_filter: Option<Persistent<Function<'static>>>,
    parameter_filter: Option<Persistent<Function<'static>>>,
    targets: Vec<u64>,
    /// `verbose()` stores this flag. Attach prints the same lines either way.
    #[allow(dead_code)]
    verbose: bool,
}

fn call_filter<'js>(
    ctx: &Ctx<'js>,
    filter: &Persistent<Function<'static>>,
    arg: Value<'js>,
) -> JsResult<bool> {
    let function = filter.clone().restore(ctx)?;
    let result: Value = function.call((arg,))?;
    Ok(truthy(&result))
}

fn take_method<'js>(
    ctx: &Ctx<'js>,
    state: &Rc<RefCell<TracerState>>,
    method: u64,
    parameter_filter: Option<&Persistent<Function<'static>>>,
) -> JsResult<()> {
    if let Some(filter) = parameter_filter {
        let count = il2cpp::Method(method)
            .param_count(&session()?)
            .map_err(to_js_error)?;
        let mut matched = false;
        for index in 0..count {
            let parameter = Class::instance(ctx.clone(), ParameterObject { method, index })?;
            if call_filter(ctx, filter, parameter.into_value())? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Ok(());
        }
    }
    state.borrow_mut().targets.push(method);
    Ok(())
}

fn take_class<'js>(
    ctx: &Ctx<'js>,
    state: &Rc<RefCell<TracerState>>,
    class: u64,
    method_filter: Option<&Persistent<Function<'static>>>,
    parameter_filter: Option<&Persistent<Function<'static>>>,
) -> JsResult<()> {
    for method in il2cpp::Class(class)
        .methods(&session()?)
        .map_err(to_js_error)?
    {
        if let Some(filter) = method_filter {
            if !call_filter(ctx, filter, method_value(ctx, method.0, None)?)? {
                continue;
            }
        }
        take_method(ctx, state, method.0, parameter_filter)?;
    }
    Ok(())
}

fn take_assembly<'js>(
    ctx: &Ctx<'js>,
    state: &Rc<RefCell<TracerState>>,
    assembly: u64,
    method_filter: Option<&Persistent<Function<'static>>>,
    parameter_filter: Option<&Persistent<Function<'static>>>,
) -> JsResult<()> {
    let runtime = session()?;
    let image = il2cpp::Assembly(assembly)
        .image(&runtime)
        .map_err(to_js_error)?;
    for class in image.classes(&runtime).map_err(to_js_error)? {
        take_class(ctx, state, class.0, method_filter, parameter_filter)?;
    }
    Ok(())
}

fn tracer<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let state = Rc::new(RefCell::new(TracerState::default()));
    let object = Object::new(ctx.clone())?;

    let verbose_state = Rc::clone(&state);
    object.set(
        "verbose",
        Func::from(
            move |this: This<Object<'js>>, value: bool| -> JsResult<Object<'js>> {
                verbose_state.borrow_mut().verbose = value;
                Ok(this.0)
            },
        ),
    )?;
    let domain_state = Rc::clone(&state);
    object.set(
        "domain",
        Func::from(move |this: This<Object<'js>>| -> JsResult<Object<'js>> {
            domain_state.borrow_mut().domain = true;
            Ok(this.0)
        }),
    )?;
    let assemblies_state = Rc::clone(&state);
    object.set(
        "assemblies",
        Func::from(
            move |this: This<Object<'js>>, args: Rest<Value<'js>>| -> JsResult<Object<'js>> {
                assemblies_state.borrow_mut().assemblies =
                    Some(args.0.iter().map(value_handle).collect::<JsResult<_>>()?);
                Ok(this.0)
            },
        ),
    )?;
    let classes_state = Rc::clone(&state);
    object.set(
        "classes",
        Func::from(
            move |this: This<Object<'js>>, args: Rest<Value<'js>>| -> JsResult<Object<'js>> {
                classes_state.borrow_mut().classes =
                    Some(args.0.iter().map(value_handle).collect::<JsResult<_>>()?);
                Ok(this.0)
            },
        ),
    )?;
    let methods_state = Rc::clone(&state);
    object.set(
        "methods",
        Func::from(
            move |this: This<Object<'js>>, args: Rest<Value<'js>>| -> JsResult<Object<'js>> {
                methods_state.borrow_mut().methods =
                    Some(args.0.iter().map(value_handle).collect::<JsResult<_>>()?);
                Ok(this.0)
            },
        ),
    )?;
    let filter_methods = Rc::clone(&state);
    object.set(
        "filterMethods",
        Func::from(
            move |ctx: Ctx<'js>,
                  this: This<Object<'js>>,
                  filter: Function<'js>|
                  -> JsResult<Object<'js>> {
                filter_methods.borrow_mut().method_filter = Some(Persistent::save(&ctx, filter));
                Ok(this.0)
            },
        ),
    )?;
    let filter_classes = Rc::clone(&state);
    object.set(
        "filterClasses",
        Func::from(
            move |ctx: Ctx<'js>,
                  this: This<Object<'js>>,
                  filter: Function<'js>|
                  -> JsResult<Object<'js>> {
                filter_classes.borrow_mut().class_filter = Some(Persistent::save(&ctx, filter));
                Ok(this.0)
            },
        ),
    )?;
    let filter_parameters = Rc::clone(&state);
    object.set(
        "filterParameters",
        Func::from(
            move |ctx: Ctx<'js>,
                  this: This<Object<'js>>,
                  filter: Function<'js>|
                  -> JsResult<Object<'js>> {
                filter_parameters.borrow_mut().parameter_filter =
                    Some(Persistent::save(&ctx, filter));
                Ok(this.0)
            },
        ),
    )?;
    let and_state = Rc::clone(&state);
    object.set(
        "and",
        Func::from(
            move |ctx: Ctx<'js>, this: This<Object<'js>>| -> JsResult<Object<'js>> {
                select_targets(&ctx, &and_state)?;
                Ok(this.0)
            },
        ),
    )?;
    let attach_state = Rc::clone(&state);
    object.set(
        "attach",
        Func::from(
            move |ctx: Ctx<'js>, this: This<Object<'js>>| -> JsResult<Object<'js>> {
                attach_targets(&ctx, &attach_state)?;
                Ok(this.0)
            },
        ),
    )?;
    Ok(object)
}

fn select_targets<'js>(ctx: &Ctx<'js>, state: &Rc<RefCell<TracerState>>) -> JsResult<()> {
    let (methods, classes, assemblies, domain, method_filter, class_filter, parameter_filter) = {
        let mut state = state.borrow_mut();
        let taken = (
            state.methods.take(),
            state.classes.take(),
            state.assemblies.take(),
            state.domain,
            state.method_filter.take(),
            state.class_filter.take(),
            state.parameter_filter.take(),
        );
        state.domain = false;
        taken
    };
    if let Some(methods) = methods {
        for method in methods {
            take_method(ctx, state, method, parameter_filter.as_ref())?;
        }
    } else if let Some(classes) = classes {
        for class in classes {
            if let Some(filter) = &class_filter {
                if !call_filter(ctx, filter, class_value(ctx, class)?)? {
                    continue;
                }
            }
            take_class(
                ctx,
                state,
                class,
                method_filter.as_ref(),
                parameter_filter.as_ref(),
            )?;
        }
    } else if let Some(assemblies) = assemblies {
        for assembly in assemblies {
            take_assembly(
                ctx,
                state,
                assembly,
                method_filter.as_ref(),
                parameter_filter.as_ref(),
            )?;
        }
    } else if domain {
        let runtime = session()?;
        let domain = runtime.domain().map_err(to_js_error)?;
        for assembly in domain.assemblies(&runtime).map_err(to_js_error)? {
            take_assembly(
                ctx,
                state,
                assembly.0,
                method_filter.as_ref(),
                parameter_filter.as_ref(),
            )?;
        }
    }
    Ok(())
}

fn attach_targets<'js>(ctx: &Ctx<'js>, state: &Rc<RefCell<TracerState>>) -> JsResult<()> {
    let targets = state.borrow().targets.clone();
    let mut seen = HashSet::new();
    for method in targets {
        let mut runtime = session()?;
        let native = il2cpp::Method(method);
        let address = native.virtual_address(&mut runtime).map_err(to_js_error)?;
        if address == 0 || !seen.insert(address) {
            continue;
        }
        let class_name = native
            .class(&runtime)
            .and_then(|class| class.full_name(&runtime))
            .map_err(to_js_error)?;
        let name = native.name(&runtime).map_err(to_js_error)?;
        let label = format!("{class_name}::{name}");
        let enter_label = label.clone();
        let leave_label = label;
        let on_enter = Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            js_print(&ctx, &format!("enter {enter_label}"))
        })?;
        let on_leave = Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            js_print(&ctx, &format!("leave {leave_label}"))
        })?;
        let callbacks = Object::new(ctx.clone())?;
        callbacks.set("onEnter", on_enter)?;
        callbacks.set("onLeave", on_leave)?;
        let interceptor: Object = ctx.globals().get("Interceptor")?;
        let attach: Function = interceptor.get("attach")?;
        let _listener: Value = attach.call((pointer(ctx, address)?, callbacks))?;
    }
    Ok(())
}

fn exception_text<'js>(ctx: &Ctx<'js>, arg: Value<'js>) -> String {
    let Ok(addr) = crate::api::parse_pointer(&arg) else {
        return "null".to_owned();
    };
    let Ok(pointer) = read_u64(addr) else {
        return format!("couldn't read {addr:#x}");
    };
    if pointer == 0 {
        return "null".to_owned();
    }
    match object_text(pointer, ctx.clone()) {
        Ok(text) => text,
        Err(err) => err.to_string(),
    }
}

fn install_exception_listener<'js>(ctx: Ctx<'js>, target: Opt<String>) -> JsResult<Object<'js>> {
    let mode = match target.0 {
        Some(text) if !text.is_empty() => text,
        _ => "current".to_owned(),
    };
    let current = session()?.thread_current().map_err(to_js_error)?;
    let throw = runtime::dlsym::resolve("__cxa_throw").unwrap_or(0) as u64;
    if throw == 0 {
        return Err(js_error("couldn't find __cxa_throw"));
    }
    let on_enter = Function::new(
        ctx.clone(),
        move |ctx: Ctx<'js>, args: Array<'js>| -> JsResult<()> {
            if mode == "current" {
                let now = session()?.thread_current().map_err(to_js_error)?;
                if now != current {
                    return Ok(());
                }
            }
            let first = match args.get::<Value>(0) {
                Ok(value) => value,
                Err(_) => Value::new_null(ctx.clone()),
            };
            js_print(&ctx, &exception_text(&ctx, first))
        },
    )?;
    let callbacks = Object::new(ctx.clone())?;
    callbacks.set("onEnter", on_enter)?;
    let interceptor: Object = ctx.globals().get("Interceptor")?;
    let attach: Function = interceptor.get("attach")?;
    attach.call((pointer(&ctx, throw)?, callbacks))
}

fn perform<'js>(_ctx: Ctx<'js>, block: Function<'js>) -> JsResult<Value<'js>> {
    session()?;
    block.call(())
}

fn new_string<'js>(ctx: Ctx<'js>, text: String) -> JsResult<Value<'js>> {
    let handle = session()?.new_string(&text).map_err(to_js_error)?;
    string_value(&ctx, handle)
}

fn trace<'js>(ctx: Ctx<'js>) -> JsResult<Object<'js>> {
    session()?;
    tracer(&ctx)
}

#[derive(Clone, Copy, Trace, JsLifetime)]
#[rquickjs::class(rename = "Il2Cpp")]
struct Root {}

#[rquickjs::methods(rename_all = "camelCase")]
impl Root {
    #[qjs(get)]
    fn module<'js>(&self, ctx: Ctx<'js>) -> JsResult<Object<'js>> {
        let runtime = session()?;
        let object = Object::new(ctx.clone())?;
        object.set("name", runtime.module.name.clone())?;
        object.set("base", pointer(&ctx, runtime.module.base as u64)?)?;
        Ok(object)
    }

    #[qjs(get)]
    fn unity_version(&self) -> JsResult<String> {
        Ok(session()?.unity_version().unwrap_or_default())
    }

    #[qjs(get)]
    fn corlib<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        image_value(&ctx, session()?.corlib().map_err(to_js_error)?.0)
    }

    #[qjs(get)]
    fn domain<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        domain_value(&ctx, session()?.domain().map_err(to_js_error)?.0)
    }

    #[qjs(get)]
    fn attached_threads<'js>(&self, ctx: Ctx<'js>) -> JsResult<Array<'js>> {
        let threads = session()?.attached_threads().map_err(to_js_error)?;
        let array = Array::new(ctx.clone())?;
        for (index, thread) in threads.into_iter().enumerate() {
            array.set(index, pointer(&ctx, thread)?)?;
        }
        Ok(array)
    }

    #[qjs(get)]
    fn current_thread<'js>(&self, ctx: Ctx<'js>) -> JsResult<Value<'js>> {
        pointer(&ctx, session()?.thread_current().map_err(to_js_error)?)
    }
}

fn class_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    class_value(&ctx, optional_handle(value)?)
}

fn method_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    method_value(&ctx, optional_handle(value)?, None)
}

fn field_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    field_value(&ctx, optional_handle(value)?, None)
}

fn object_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    object_value(&ctx, optional_handle(value)?)
}

fn string_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    string_value(&ctx, optional_handle(value)?)
}

fn image_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    image_value(&ctx, optional_handle(value)?)
}

fn assembly_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    assembly_value(&ctx, optional_handle(value)?)
}

fn domain_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    domain_value(&ctx, optional_handle(value)?)
}

fn type_factory<'js>(ctx: Ctx<'js>, value: Opt<Value<'js>>) -> JsResult<Value<'js>> {
    type_value(&ctx, optional_handle(value)?)
}

pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    let root = Class::<Root>::instance(ctx.clone(), Root {})?;
    root.set("summary", Func::from(crate::il2cpp::summary))?;
    root.set("assemblies", Func::from(crate::il2cpp::assemblies))?;
    root.set("classes", Func::from(crate::il2cpp::classes))?;
    root.set("methods", Func::from(crate::il2cpp::methods))?;
    root.set("dump", Func::from(crate::il2cpp::dump))?;
    root.set("perform", Func::from(perform))?;
    root.set("string", Func::from(new_string))?;
    root.set("trace", Func::from(trace))?;
    root.set("gc", Class::<GcObject>::instance(ctx.clone(), GcObject {})?)?;
    root.set(
        "application",
        Class::<ApplicationObject>::instance(ctx.clone(), ApplicationObject {})?,
    )?;
    root.set(
        "installExceptionListener",
        Func::from(install_exception_listener),
    )?;
    root.set("Class", Func::from(class_factory))?;
    root.set("Method", Func::from(method_factory))?;
    root.set("Field", Func::from(field_factory))?;
    root.set("Object", Func::from(object_factory))?;
    root.set("String", Func::from(string_factory))?;
    root.set("Image", Func::from(image_factory))?;
    root.set("Assembly", Func::from(assembly_factory))?;
    root.set("Domain", Func::from(domain_factory))?;
    root.set("Type", Func::from(type_factory))?;
    ctx.globals().set("Il2Cpp", root)?;
    Ok(())
}
