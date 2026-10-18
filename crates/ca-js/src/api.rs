//! Frida-style JavaScript objects backed by `ca-core` / `ca-gum`.
//!
//! The surface is intentionally small for M2: pointers, memory, process,
//! modules and thread sleep.  Interceptor/NativeFunction are added next.

use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;
use std::sync::mpsc::Sender;

use rquickjs::class::Trace;
use rquickjs::function::Args;
use rquickjs::prelude::Func;
use rquickjs::{
    Array, ArrayBuffer, Class, Ctx, Function, JsLifetime, Object, Persistent, Result as JsResult,
    Value,
};

use ca_core::module;
use ca_gum::{memory, process, thread, InlineHook, SavedRegs};

use crate::worker::{hook_trampoline, make_bridge, HookListener, HookTable, Job};

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

/// Install `ptr`, `NULL`, `Memory`, `Process`, `Module`, `Thread`.
pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    let globals = ctx.globals();
    Class::<NativePointer>::define(&globals)?;

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
    Ok(())
}

/// Install the base API plus `Interceptor` backed by the JS worker.
pub(crate) fn install_with_hooks<'js>(
    ctx: &Ctx<'js>,
    tx: Sender<Job>,
    hooks: Rc<RefCell<HookTable>>,
) -> JsResult<()> {
    install(ctx)?;

    let interceptor = Object::new(ctx.clone())?;
    interceptor.set(
        "attach",
        Func::from(
            move |ctx: Ctx<'js>, target: Value<'js>, callbacks: Value<'js>| -> JsResult<()> {
                let address = usize::try_from(parse_pointer(&target)?)
                    .map_err(|_| js_error("target address does not fit in usize"))?;
                let callbacks: Object<'js> = callbacks.get()?;
                let on_enter: Option<Function<'js>> = callbacks.get("onEnter")?;
                let on_enter = on_enter.map(|function| Persistent::save(&ctx, function));

                let id = {
                    let mut table = hooks.borrow_mut();
                    table.listeners.push(HookListener {
                        on_enter,
                        hook: None,
                        bridge: std::ptr::null_mut(),
                    });
                    table.listeners.len() - 1
                };

                let bridge = make_bridge(id, address, tx.clone());
                // SAFETY: bridge stays alive in HookListener; callback only uses
                // the channel and SavedRegs.
                let hook =
                    unsafe { InlineHook::attach(address, hook_trampoline, bridge as *mut c_void) }
                        .map_err(to_js_error)?;

                let mut table = hooks.borrow_mut();
                table.listeners[id].hook = Some(hook);
                table.listeners[id].bridge = bridge;
                Ok(())
            },
        ),
    )?;
    ctx.globals().set("Interceptor", interceptor)?;
    Ok(())
}

/// Invoke a saved `onEnter` function with Frida-like `this.context` and `args`.
pub(crate) fn invoke_hook<'js>(
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

fn read_cstring(addr: u64) -> ca_core::Result<String> {
    let mut out = Vec::new();
    for offset in 0..4096 {
        let byte = memory::read(addr as usize + offset, 1)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        out.push(byte[0]);
    }
    Err(ca_core::Error::Parse(
        "C string is longer than 4096 bytes".into(),
    ))
}

fn to_js_error(error: ca_core::Error) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("ca", "memory", error.to_string())
}

fn js_error(message: impl Into<String>) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("ca", "pointer", message.into())
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
