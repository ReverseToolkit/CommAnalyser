//! Frida-style JavaScript objects backed by `runtime` / `gum`.
//!
//! The surface is intentionally small for M2: pointers, memory, process,
//! modules and thread sleep.  Interceptor/NativeFunction are added next.

use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;
use std::sync::mpsc::Sender;

use rquickjs::class::Trace;
use rquickjs::function::{Args, Rest};
use rquickjs::prelude::Func;
use rquickjs::{
    Array, ArrayBuffer, Class, Ctx, Function, IntoJs, JsLifetime, Object, Persistent,
    Result as JsResult, Value,
};

use gum::{memory, native, process, thread, InlineHook, SavedRegs};
use runtime::module;

use crate::worker::{
    callback_dispatch, hook_enter, hook_leave, make_bridge, CallbackEntry, CallbackTable,
    HookGroup, HookTable, Job, Listener,
};

/// JavaScript `NativePointer`.
#[derive(Clone, Trace, JsLifetime)]
#[rquickjs::class(rename_all = "camelCase")]
pub struct NativePointer {
    value: u64,
}

impl NativePointer {
    fn new_value(value: u64) -> Self {
        Self { value }
    }

    fn instance<'js>(ctx: Ctx<'js>, value: u64) -> JsResult<Class<'js, Self>> {
        Class::instance(ctx, Self::new_value(value))
    }
}

#[rquickjs::methods(rename_all = "camelCase")]
impl NativePointer {
    #[qjs(constructor)]
    pub fn new(value: Value<'_>) -> JsResult<Self> {
        Ok(Self::new_value(parse_pointer(&value)?))
    }

    #[qjs(get, rename = "__addr")]
    pub fn address(&self) -> u64 {
        self.value
    }

    #[qjs(rename = "toString")]
    pub fn as_string(&self) -> String {
        format!("0x{:x}", self.value)
    }

    pub fn add<'js>(&self, ctx: Ctx<'js>, delta: u64) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_add(delta))
    }

    pub fn sub<'js>(&self, ctx: Ctx<'js>, delta: u64) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_sub(delta))
    }

    pub fn is_null(&self) -> bool {
        self.value == 0
    }

    pub fn equals(&self, other: Value<'_>) -> bool {
        parse_pointer(&other).is_ok_and(|value| value == self.value)
    }

    #[qjs(rename = "readCString")]
    pub fn read_cstring(&self) -> JsResult<String> {
        read_cstring(self.value).map_err(to_js_error)
    }

    pub fn read_utf8_string(&self) -> JsResult<String> {
        self.read_cstring()
    }

    pub fn read_u8(&self) -> JsResult<u8> {
        read_u8(self.value)
    }

    pub fn read_u16(&self) -> JsResult<u16> {
        read_bytes::<2>(self.value).map(u16::from_le_bytes)
    }

    pub fn read_u32(&self) -> JsResult<u32> {
        read_bytes::<4>(self.value).map(u32::from_le_bytes)
    }

    pub fn read_u64(&self) -> JsResult<u64> {
        read_bytes::<8>(self.value).map(u64::from_le_bytes)
    }

    pub fn write_u8(&self, value: u8) -> JsResult<()> {
        write_bytes(self.value, &[value])
    }

    pub fn write_u16(&self, value: u16) -> JsResult<()> {
        write_bytes(self.value, &value.to_le_bytes())
    }

    pub fn write_u32(&self, value: u32) -> JsResult<()> {
        write_bytes(self.value, &value.to_le_bytes())
    }

    pub fn write_u64(&self, value: u64) -> JsResult<()> {
        write_bytes(self.value, &value.to_le_bytes())
    }

    pub fn write_utf8_string(&self, value: String) -> JsResult<()> {
        let mut bytes = value.into_bytes();
        bytes.push(0);
        write_bytes(self.value, &bytes)
    }
}

/// JavaScript `retval` object passed to `onLeave`.
#[derive(Clone, Trace, JsLifetime)]
#[rquickjs::class(rename_all = "camelCase")]
pub struct Retval {
    value: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl Retval {
    #[qjs(constructor)]
    pub fn new(value: Value<'_>) -> JsResult<Self> {
        Ok(Self {
            value: parse_pointer(&value)?,
        })
    }

    #[qjs(get, rename = "__value")]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[qjs(rename = "toString")]
    pub fn as_string(&self) -> String {
        format!("0x{:x}", self.value)
    }

    pub fn replace(&mut self, value: Value<'_>) -> JsResult<()> {
        self.value = parse_pointer(&value)?;
        Ok(())
    }
}

/// Install `ptr`, `NULL`, `Memory`, `Process`, `Module`, `Thread`.
pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    let globals = ctx.globals();
    Class::<NativePointer>::define(&globals)?;
    Class::<Retval>::define(&globals)?;

    globals.set(
        "ptr",
        Func::from(
            |ctx: Ctx<'js>, value: Value<'js>| -> JsResult<Class<'js, NativePointer>> {
                NativePointer::instance(ctx, parse_pointer(&value)?)
            },
        ),
    )?;
    globals.set("NULL", NativePointer::instance(ctx.clone(), 0)?)?;

    globals.set("Memory", memory_object(ctx)?)?;
    globals.set("Process", process_object(ctx)?)?;
    globals.set("Module", module_object(ctx)?)?;
    globals.set("Thread", thread_object(ctx)?)?;
    globals.set("__analyser_make_native", Func::from(make_native_function))?;
    ctx.eval::<(), _>(
        r#"
        globalThis.NativeFunction = function (address, retType, argTypes) {
            return __analyser_make_native(address, retType, argTypes);
        };
        "#,
    )?;
    Ok(())
}

/// Install the base API plus `Interceptor` backed by the JS worker.
pub(crate) fn install_with_hooks<'js>(
    ctx: &Ctx<'js>,
    tx: Sender<Job>,
    hooks: Rc<RefCell<HookTable>>,
    callbacks: Rc<RefCell<CallbackTable>>,
    event_tx: Sender<String>,
) -> JsResult<()> {
    install(ctx)?;
    ctx.globals().set(
        "__analyser_send",
        Func::from(move |text: String| {
            let _ = event_tx.send(text);
        }),
    )?;
    ctx.eval::<(), _>(
        r#"
        globalThis.send = function (payload) {
            __analyser_send(JSON.stringify({ op: 'send', payload: payload }));
        };
        "#,
    )?;

    let interceptor = Object::new(ctx.clone())?;
    interceptor.set(
        "attach",
        Func::from(
            move |ctx: Ctx<'js>, target: Value<'js>, callbacks: Value<'js>| -> JsResult<u32> {
                let address = usize::try_from(parse_pointer(&target)?)
                    .map_err(|_| js_error("target address does not fit in usize"))?;
                let callbacks: Object<'js> = callbacks.get()?;
                let on_enter: Option<Function<'js>> = callbacks.get("onEnter")?;
                let on_leave: Option<Function<'js>> = callbacks.get("onLeave")?;
                let listener = Listener {
                    on_enter: on_enter.map(|function| Persistent::save(&ctx, function)),
                    on_leave: on_leave.map(|function| Persistent::save(&ctx, function)),
                };

                let group = {
                    let mut table = hooks.borrow_mut();
                    if let Some(index) = table.groups.iter().position(|g| g.target == address) {
                        table.groups[index].listeners.push(listener);
                        return Ok(index as u32);
                    }
                    let index = table.groups.len();
                    table.groups.push(HookGroup {
                        target: address,
                        listeners: vec![listener],
                        hook: None,
                        bridge: std::ptr::null_mut(),
                    });
                    index
                };

                let bridge = make_bridge(group, address, tx.clone());
                // SAFETY: bridge stays alive in HookGroup; callbacks only use the
                // channel, SavedRegs and a stable target address.
                let hook = unsafe {
                    InlineHook::attach_ex(
                        address,
                        hook_enter,
                        Some(hook_leave),
                        bridge as *mut c_void,
                    )
                };

                match hook {
                    Ok(hook) => {
                        let mut table = hooks.borrow_mut();
                        table.groups[group].hook = Some(hook);
                        table.groups[group].bridge = bridge;
                        Ok(group as u32)
                    }
                    Err(err) => {
                        hooks.borrow_mut().groups.pop();
                        Err(to_js_error(err))
                    }
                }
            },
        ),
    )?;
    ctx.globals().set("Interceptor", interceptor)?;

    ctx.globals().set(
        "__analyser_make_callback",
        Func::from(
            move |ctx: Ctx<'js>,
                  function: Function<'js>,
                  ret_type: String,
                  arg_types: Value<'js>|
                  -> JsResult<Class<'js, NativePointer>> {
                if matches!(ret_type.as_str(), "float" | "double") {
                    return Err(js_error(
                        "NativeCallback: float returns are not supported yet",
                    ));
                }
                let array: Array<'js> = arg_types.get()?;
                let mut types = Vec::with_capacity(array.len());
                for index in 0..array.len() {
                    types.push(array.get::<String>(index)?);
                }
                let id = {
                    let mut table = callbacks.borrow_mut();
                    table.entries.push(CallbackEntry {
                        function: Persistent::save(&ctx, function),
                        arg_types: types,
                        ret_void: ret_type == "void",
                        ret_signed: is_signed_type(&ret_type),
                        ret_pointer: ret_type == "pointer",
                    });
                    table.entries.len() - 1
                };
                let stub =
                    gum::native::make_callback_stub(callback_dispatch as *const () as usize, id)
                        .map_err(to_js_error)?;
                NativePointer::instance(ctx, stub as u64)
            },
        ),
    )?;
    ctx.eval::<(), _>(
        r#"
        globalThis.NativeCallback = function (fn, retType, argTypes) {
            return __analyser_make_callback(fn, retType, argTypes);
        };
        "#,
    )?;
    crate::java::install(ctx)?;
    Ok(())
}

/// Invoke a JS `NativeCallback` and convert its return value to x0.
pub(crate) fn invoke_callback<'js>(
    ctx: &Ctx<'js>,
    function: Persistent<Function<'static>>,
    arg_types: &[String],
    ret_void: bool,
    ret_signed: bool,
    ret_pointer: bool,
    args: [u64; 8],
) -> JsResult<u64> {
    let function = function.restore(ctx)?;
    let mut call_args = Args::new(ctx.clone(), 8);
    for (index, arg) in args.iter().enumerate() {
        let ty = arg_types
            .get(index)
            .map(String::as_str)
            .unwrap_or("pointer");
        let value: Value<'js> = if ty == "pointer" {
            NativePointer::instance(ctx.clone(), *arg)?.into_value()
        } else if is_signed_type(ty) {
            (*arg as i64).into_js(ctx)?
        } else {
            arg.into_js(ctx)?
        };
        call_args.push_arg(value)?;
    }
    let result: Value<'js> = function.call_arg(call_args)?;

    if ret_void {
        return Ok(0);
    }
    if ret_pointer {
        return parse_pointer(&result);
    }
    if ret_signed {
        result.get::<i64>().map(|value| value as u64)
    } else {
        result.get::<u64>()
    }
}

/// Invoke a saved `onEnter` function with Frida-like `this.context` and `args`.
pub(crate) fn invoke_enter<'js>(
    ctx: &Ctx<'js>,
    on_enter: Persistent<Function<'static>>,
    target: usize,
    regs: &mut SavedRegs,
) -> JsResult<()> {
    let on_enter = on_enter.restore(ctx)?;

    let args = Array::new(ctx.clone())?;
    for index in 0..8 {
        args.set(index, NativePointer::instance(ctx.clone(), regs.x[index])?)?;
    }

    let this = make_this(ctx, target, regs)?;
    let mut call_args = Args::new(ctx.clone(), 1);
    call_args.this(this)?;
    call_args.push_arg(args.clone())?;
    on_enter.call_arg::<()>(call_args)?;

    for index in 0..8 {
        if let Ok(pointer) = args.get::<Class<NativePointer>>(index) {
            regs.x[index] = pointer.borrow().value;
        }
    }
    Ok(())
}

/// Invoke a saved `onLeave` function with `retval` and `this.context`.
pub(crate) fn invoke_leave<'js>(
    ctx: &Ctx<'js>,
    on_leave: Persistent<Function<'static>>,
    target: usize,
    regs: &mut SavedRegs,
) -> JsResult<()> {
    let on_leave = on_leave.restore(ctx)?;
    let retval = Class::instance(ctx.clone(), Retval { value: regs.x[0] })?;

    let this = make_this(ctx, target, regs)?;
    let mut call_args = Args::new(ctx.clone(), 1);
    call_args.this(this)?;
    call_args.push_arg(retval.clone())?;
    on_leave.call_arg::<()>(call_args)?;

    regs.x[0] = retval.borrow().value;
    Ok(())
}

fn make_this<'js>(ctx: &Ctx<'js>, target: usize, regs: &SavedRegs) -> JsResult<Object<'js>> {
    let context = Object::new(ctx.clone())?;
    context.set("pc", NativePointer::instance(ctx.clone(), target as u64)?)?;
    context.set("sp", NativePointer::instance(ctx.clone(), 0)?)?;
    context.set("lr", NativePointer::instance(ctx.clone(), regs.lr)?)?;
    for index in 0..8 {
        let value = NativePointer::instance(ctx.clone(), regs.x[index])?;
        match index {
            0 => context.set("x0", value)?,
            1 => context.set("x1", value)?,
            2 => context.set("x2", value)?,
            3 => context.set("x3", value)?,
            4 => context.set("x4", value)?,
            5 => context.set("x5", value)?,
            6 => context.set("x6", value)?,
            _ => context.set("x7", value)?,
        }
    }

    let this = Object::new(ctx.clone())?;
    this.set("context", context)?;
    this.set(
        "returnAddress",
        NativePointer::instance(ctx.clone(), regs.lr)?,
    )?;
    this.set("threadId", thread::current_id())?;
    this.set("depth", 0u32)?;
    Ok(this)
}

fn memory_object<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;

    obj.set(
        "alloc",
        Func::from(
            |ctx: Ctx<'js>, size: usize| -> JsResult<Class<'js, NativePointer>> {
                let ptr = memory::alloc(size).map_err(to_js_error)?;
                NativePointer::instance(ctx, ptr as u64)
            },
        ),
    )?;
    obj.set(
        "allocUtf8String",
        Func::from(
            |ctx: Ctx<'js>, text: String| -> JsResult<Class<'js, NativePointer>> {
                let ptr = memory::alloc(text.len() + 1).map_err(to_js_error)?;
                let mut bytes = text.into_bytes();
                bytes.push(0);
                memory::write(ptr as usize, &bytes).map_err(to_js_error)?;
                NativePointer::instance(ctx, ptr as u64)
            },
        ),
    )?;
    obj.set(
        "readCString",
        Func::from(|value: Value<'js>| -> JsResult<String> {
            read_cstring(parse_pointer(&value)?).map_err(to_js_error)
        }),
    )?;
    obj.set(
        "readU8",
        Func::from(|value: Value<'js>| -> JsResult<u8> { read_u8(parse_pointer(&value)?) }),
    )?;
    obj.set(
        "readU64",
        Func::from(|value: Value<'js>| -> JsResult<u64> {
            read_bytes::<8>(parse_pointer(&value)?).map(u64::from_le_bytes)
        }),
    )?;
    obj.set(
        "readByteArray",
        Func::from(
            |ctx: Ctx<'js>, value: Value<'js>, len: usize| -> JsResult<ArrayBuffer<'js>> {
                let bytes =
                    memory::read(parse_pointer(&value)? as usize, len).map_err(to_js_error)?;
                ArrayBuffer::new(ctx, bytes)
            },
        ),
    )?;
    obj.set(
        "writeUtf8String",
        Func::from(|value: Value<'js>, text: String| -> JsResult<()> {
            let addr = parse_pointer(&value)?;
            let mut bytes = text.into_bytes();
            bytes.push(0);
            write_bytes(addr, &bytes)
        }),
    )?;
    obj.set(
        "protect",
        Func::from(
            |value: Value<'js>, size: usize, prot: i32| -> JsResult<()> {
                let addr = parse_pointer(&value)?;
                memory::protect(addr as usize, size, prot).map_err(to_js_error)
            },
        ),
    )?;
    Ok(obj)
}

fn process_object<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("id", process::id())?;
    obj.set("arch", process::arch())?;
    obj.set("platform", process::platform())?;
    obj.set("pageSize", process::page_size())?;
    obj.set("pointerSize", process::pointer_size())?;
    obj.set(
        "getCurrentThreadId",
        Func::from(|| -> u32 { thread::current_id() }),
    )?;

    obj.set(
        "enumerateModules",
        Func::from(|ctx: Ctx<'js>| -> JsResult<Array<'js>> {
            let modules = module::enumerate().map_err(to_js_error)?;
            let array = Array::new(ctx.clone())?;
            for (index, module) in modules.into_iter().enumerate() {
                let item = Object::new(ctx.clone())?;
                item.set("name", module.name.as_str())?;
                item.set("path", module.path.as_str())?;
                item.set(
                    "base",
                    NativePointer::instance(ctx.clone(), module.base as u64)?,
                )?;
                item.set("size", module.size())?;
                array.set(index, item)?;
            }
            Ok(array)
        }),
    )?;
    Ok(obj)
}

fn module_object<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set(
        "findBaseAddress",
        Func::from(|ctx: Ctx<'js>, name: String| -> JsResult<Value<'js>> {
            match module::find_by_name(&name).map_err(to_js_error)? {
                Some(module) => Ok(NativePointer::instance(ctx, module.base as u64)?.into_value()),
                None => Ok(Value::new_null(ctx)),
            }
        }),
    )?;

    obj.set("getExportByName", Func::from(lookup_export))?;
    obj.set("findExportByName", Func::from(lookup_export))?;
    obj.set("findGlobalExportByName", Func::from(lookup_export))?;
    Ok(obj)
}

fn thread_object<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set(
        "sleep",
        Func::from(|millis: u64| {
            std::thread::sleep(std::time::Duration::from_millis(millis));
        }),
    )?;
    Ok(obj)
}

fn parse_pointer(value: &Value<'_>) -> JsResult<u64> {
    if value.is_string() {
        let text: String = value.get()?;
        return parse_hex_or_dec(&text);
    }
    if value.is_number() {
        let number = value.as_number().unwrap_or_default();
        if number < 0.0 {
            return Err(js_error("pointer cannot be negative"));
        }
        return Ok(number as u64);
    }
    if let Ok(pointer) = Class::<NativePointer>::from_value(value) {
        return Ok(pointer.borrow().value);
    }
    Err(js_error("expected a NativePointer, string or number"))
}

fn parse_hex_or_dec(text: &str) -> JsResult<u64> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse::<u64>()
    };
    parsed.map_err(|_| js_error(format!("invalid pointer: {text}")))
}

fn read_u8(addr: u64) -> JsResult<u8> {
    let bytes = memory::read(addr as usize, 1).map_err(to_js_error)?;
    Ok(bytes[0])
}

fn read_bytes<const N: usize>(addr: u64) -> JsResult<[u8; N]> {
    let bytes = memory::read(addr as usize, N).map_err(to_js_error)?;
    bytes.try_into().map_err(|_| js_error("short memory read"))
}

fn write_bytes(addr: u64, data: &[u8]) -> JsResult<()> {
    memory::write(addr as usize, data).map_err(to_js_error)
}

fn read_cstring(addr: u64) -> runtime::Result<String> {
    let mut out = Vec::new();
    for offset in 0..4096 {
        let byte = memory::read(addr as usize + offset, 1)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.push(byte[0]);
    }
    Err(runtime::Error::Parse(
        "C string is longer than 4096 bytes".into(),
    ))
}

fn to_js_error(error: runtime::Error) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("comm-analyser", "memory", error.to_string())
}

fn js_error(message: impl Into<String>) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("comm-analyser", "pointer", message.into())
}

fn is_signed_type(ty: &str) -> bool {
    matches!(
        ty,
        "int" | "int8" | "int16" | "int32" | "int64" | "long" | "ssize_t" | "char"
    )
}

fn make_native_function<'js>(
    ctx: Ctx<'js>,
    address: Value<'js>,
    ret_type: String,
    arg_types: Value<'js>,
) -> JsResult<Function<'js>> {
    let target = usize::try_from(parse_pointer(&address)?)
        .map_err(|_| js_error("native function address does not fit in usize"))?;
    if matches!(ret_type.as_str(), "float" | "double") {
        return Err(js_error(
            "NativeFunction: float returns are not supported yet",
        ));
    }
    let returns_void = ret_type == "void";
    let returns_signed = is_signed_type(&ret_type);

    let array: Array<'js> = arg_types.get()?;
    let mut types = Vec::with_capacity(array.len());
    for index in 0..array.len() {
        types.push(array.get::<String>(index)?);
    }

    let call_ctx = ctx.clone();
    Function::new(
        ctx,
        move |values: Rest<Value<'js>>| -> JsResult<Value<'js>> {
            let mut raw = [0u64; 8];
            for (index, value) in values.0.iter().enumerate().take(8) {
                let ty = types.get(index).map(String::as_str).unwrap_or("pointer");
                raw[index] = match ty {
                    "pointer" => parse_pointer(value)?,
                    "void" => 0,
                    "float" | "double" => {
                        return Err(js_error(
                            "NativeFunction: float arguments are not supported yet",
                        ))
                    }
                    _ if is_signed_type(ty) => value.get::<i64>()? as u64,
                    _ => value.get::<u64>()?,
                };
            }
            // SAFETY: the caller supplied the function address and signature.
            let result = unsafe { native::call(target, &raw) }.map_err(to_js_error)?;
            if returns_void {
                Ok(Value::new_undefined(call_ctx.clone()))
            } else if returns_signed {
                (result as i64).into_js(&call_ctx)
            } else {
                result.into_js(&call_ctx)
            }
        },
    )
}

fn lookup_export<'js>(ctx: Ctx<'js>, module: Value<'js>, symbol: String) -> JsResult<Value<'js>> {
    let module = if module.is_null() || module.is_undefined() {
        None
    } else {
        Some(module.get::<String>()?)
    };
    match crate::elf::find_export(module.as_deref(), &symbol).map_err(to_js_error)? {
        Some((address, _)) => Ok(NativePointer::instance(ctx, address as u64)?.into_value()),
        None => Ok(Value::new_null(ctx)),
    }
}
pub(crate) fn invoke_rpc<'js>(ctx: &Ctx<'js>, name: &str, args_json: &str) -> JsResult<String> {
    let rpc: Object<'js> = ctx.globals().get("rpc")?;
    let exports: Object<'js> = rpc.get("exports")?;
    let function: Function<'js> = exports.get(name)?;

    let parse: Function<'js> = ctx.eval("JSON.parse")?;
    let args_value: Value<'js> = parse.call((args_json,))?;
    let array: Array<'js> = args_value.get()?;

    let mut call_args = Args::new(ctx.clone(), array.len());
    for index in 0..array.len() {
        let value: Value<'js> = array.get(index)?;
        call_args.push_arg(value)?;
    }
    let result: Value<'js> = function.call_arg(call_args)?;

    let stringify: Function<'js> = ctx.eval("JSON.stringify")?;
    let text: Option<String> = stringify.call((result,))?;
    Ok(text.unwrap_or_else(|| "null".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::parse_hex_or_dec;

    #[test]
    fn parses_pointers() {
        assert_eq!(parse_hex_or_dec("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_hex_or_dec("4660").unwrap(), 4660);
        assert!(parse_hex_or_dec("nope").is_err());
    }
}
