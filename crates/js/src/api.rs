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

use gum::{memory, native, process, thread, InlineHook, Interceptor, SavedRegs};
use runtime::module;

use crate::worker::{
    callback_dispatch, hook_enter, hook_leave, make_bridge, CallbackEntry, CallbackTable,
    HookGroup, HookTable, JavaHookTable, Job, Listener,
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

    pub(crate) fn instance<'js>(ctx: Ctx<'js>, value: u64) -> JsResult<Class<'js, Self>> {
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

    pub fn add<'js>(&self, ctx: Ctx<'js>, delta: Value<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_add(parse_pointer(&delta)?))
    }

    pub fn sub<'js>(&self, ctx: Ctx<'js>, delta: Value<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_sub(parse_pointer(&delta)?))
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

    pub fn read_utf16_string(&self, length: rquickjs::function::Opt<i32>) -> JsResult<String> {
        let max = length.0.unwrap_or(4096).max(0) as usize;
        let bytes =
            memory::read(self.value as usize, max.saturating_mul(2)).map_err(to_js_error)?;
        let mut units = Vec::with_capacity(max);
        for chunk in bytes.chunks_exact(2).take(max) {
            let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
            if length.0.is_none() && unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(String::from_utf16_lossy(&units))
    }

    pub fn read_utf8_string(&self, size: rquickjs::function::Opt<i32>) -> JsResult<String> {
        match size.0 {
            Some(size) if size >= 0 => {
                let bytes =
                    memory::read(self.value as usize, size as usize).map_err(to_js_error)?;
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
            _ => self.read_cstring(),
        }
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

    pub fn write_u8<'js>(&self, ctx: Ctx<'js>, value: u8) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &[value])?;
        Self::instance(ctx, self.value)
    }

    pub fn write_u16<'js>(&self, ctx: Ctx<'js>, value: u16) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &value.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn write_u32<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<Class<'js, Self>> {
        let bits = parse_u64(&value)? as u32;
        write_bytes(self.value, &bits.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn write_u64<'js>(&self, ctx: Ctx<'js>, value: u64) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &value.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn write_utf8_string<'js>(
        &self,
        ctx: Ctx<'js>,
        value: String,
    ) -> JsResult<Class<'js, Self>> {
        let mut bytes = value.into_bytes();
        bytes.push(0);
        write_bytes(self.value, &bytes)?;
        Self::instance(ctx, self.value)
    }

    pub fn read_pointer<'js>(&self, ctx: Ctx<'js>) -> JsResult<Class<'js, Self>> {
        let bytes = read_bytes::<8>(self.value)?;
        Self::instance(ctx, u64::from_le_bytes(bytes))
    }

    pub fn write_pointer<'js>(
        &self,
        ctx: Ctx<'js>,
        value: Value<'js>,
    ) -> JsResult<Class<'js, Self>> {
        let pointer = parse_pointer(&value)?;
        write_bytes(self.value, &pointer.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_s8(&self) -> JsResult<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn write_s8<'js>(&self, ctx: Ctx<'js>, value: i8) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &[value as u8])?;
        Self::instance(ctx, self.value)
    }

    pub fn read_s16(&self) -> JsResult<i16> {
        Ok(i16::from_le_bytes(read_bytes::<2>(self.value)?))
    }

    pub fn write_s16<'js>(&self, ctx: Ctx<'js>, value: i16) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &value.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_s32(&self) -> JsResult<i32> {
        Ok(i32::from_le_bytes(read_bytes::<4>(self.value)?))
    }

    pub fn write_s32<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<Class<'js, Self>> {
        let bits = parse_i64(&value)? as i32;
        write_bytes(self.value, &bits.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_s64<'js>(&self, ctx: Ctx<'js>) -> JsResult<Class<'js, Int64>> {
        let value = i64::from_le_bytes(read_bytes::<8>(self.value)?);
        Class::instance(ctx, Int64 { value })
    }

    pub fn write_s64<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &parse_i64(&value)?.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_int(&self) -> JsResult<i32> {
        self.read_s32()
    }

    pub fn write_int<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<Class<'js, Self>> {
        self.write_s32(ctx, value)
    }

    pub fn write_u_int<'js>(&self, ctx: Ctx<'js>, value: Value<'js>) -> JsResult<Class<'js, Self>> {
        self.write_u32(ctx, value)
    }

    pub fn read_float(&self) -> JsResult<f64> {
        Ok(f32::from_le_bytes(read_bytes::<4>(self.value)?) as f64)
    }

    pub fn write_float<'js>(&self, ctx: Ctx<'js>, value: f64) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &(value as f32).to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_double(&self) -> JsResult<f64> {
        Ok(f64::from_le_bytes(read_bytes::<8>(self.value)?))
    }

    pub fn write_double<'js>(&self, ctx: Ctx<'js>, value: f64) -> JsResult<Class<'js, Self>> {
        write_bytes(self.value, &value.to_le_bytes())?;
        Self::instance(ctx, self.value)
    }

    pub fn read_byte_array<'js>(&self, ctx: Ctx<'js>, len: usize) -> JsResult<ArrayBuffer<'js>> {
        let bytes = memory::read(self.value as usize, len).map_err(to_js_error)?;
        ArrayBuffer::new(ctx, bytes)
    }

    pub fn write_byte_array<'js>(
        &self,
        ctx: Ctx<'js>,
        data: ArrayBuffer<'js>,
    ) -> JsResult<Class<'js, Self>> {
        // SAFETY: the ArrayBuffer is a live JS value for the duration of this call.
        write_bytes(self.value, unsafe { data.as_bytes() }.unwrap_or(&[]))?;
        Self::instance(ctx, self.value)
    }

    pub fn and<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value & parse_pointer(&other)?)
    }

    pub fn or<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value | parse_pointer(&other)?)
    }

    pub fn xor<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value ^ parse_pointer(&other)?)
    }

    pub fn shl<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_shl(bits))
    }

    pub fn shr<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, self.value.wrapping_shr(bits))
    }

    #[qjs(rename = "not")]
    pub fn not_bits<'js>(&self, ctx: Ctx<'js>) -> JsResult<Class<'js, Self>> {
        Self::instance(ctx, !self.value)
    }

    pub fn compare(&self, other: Value<'_>) -> JsResult<i32> {
        Ok(match self.value.cmp(&parse_pointer(&other)?) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    pub fn to_int32(&self) -> i32 {
        self.value as i32
    }

    pub fn to_u_int32(&self) -> u32 {
        self.value as u32
    }

    #[qjs(rename = "valueOf")]
    pub fn value_of(&self) -> f64 {
        self.value as f64
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

/// Frida `Int64` (signed 64-bit), used by java-bridge long fields and JVMTI tags.
#[derive(Clone, Trace, JsLifetime)]
#[rquickjs::class]
pub struct Int64 {
    value: i64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl Int64 {
    #[qjs(constructor)]
    pub fn new(value: Value<'_>) -> JsResult<Self> {
        Ok(Self {
            value: parse_i64(&value)?,
        })
    }

    pub fn add<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_add(parse_i64(&other)?),
            },
        )
    }

    pub fn sub<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_sub(parse_i64(&other)?),
            },
        )
    }

    pub fn and<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value & parse_i64(&other)?,
            },
        )
    }

    pub fn or<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value | parse_i64(&other)?,
            },
        )
    }

    pub fn xor<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value ^ parse_i64(&other)?,
            },
        )
    }

    pub fn shl<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_shl(bits),
            },
        )
    }

    pub fn shr<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_shr(bits),
            },
        )
    }

    pub fn compare(&self, other: Value<'_>) -> JsResult<i32> {
        Ok(match self.value.cmp(&parse_i64(&other)?) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    pub fn equals(&self, other: Value<'_>) -> bool {
        parse_i64(&other).is_ok_and(|value| value == self.value)
    }

    pub fn to_number(&self) -> f64 {
        self.value as f64
    }

    pub fn to_int32(&self) -> i32 {
        self.value as i32
    }

    pub fn to_u_int32(&self) -> u32 {
        self.value as u32
    }

    #[qjs(rename = "toString")]
    pub fn as_string(&self, radix: rquickjs::function::Opt<i32>) -> String {
        match radix.0.unwrap_or(10) {
            16 => format!("{:x}", self.value as u64),
            2 => format!("{:b}", self.value as u64),
            8 => format!("{:o}", self.value as u64),
            _ => self.value.to_string(),
        }
    }

    #[qjs(rename = "valueOf")]
    pub fn value_of(&self) -> f64 {
        self.value as f64
    }
}

/// Frida `UInt64`.
#[derive(Clone, Trace, JsLifetime)]
#[rquickjs::class]
pub struct UInt64 {
    value: u64,
}

#[rquickjs::methods(rename_all = "camelCase")]
impl UInt64 {
    #[qjs(constructor)]
    pub fn new(value: Value<'_>) -> JsResult<Self> {
        Ok(Self {
            value: parse_u64(&value)?,
        })
    }

    pub fn add<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_add(parse_u64(&other)?),
            },
        )
    }

    pub fn sub<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_sub(parse_u64(&other)?),
            },
        )
    }

    pub fn and<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value & parse_u64(&other)?,
            },
        )
    }

    pub fn or<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value | parse_u64(&other)?,
            },
        )
    }

    pub fn xor<'js>(&self, ctx: Ctx<'js>, other: Value<'js>) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value ^ parse_u64(&other)?,
            },
        )
    }

    pub fn shl<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_shl(bits),
            },
        )
    }

    pub fn shr<'js>(&self, ctx: Ctx<'js>, bits: u32) -> JsResult<Class<'js, Self>> {
        Class::instance(
            ctx,
            Self {
                value: self.value.wrapping_shr(bits),
            },
        )
    }

    pub fn compare(&self, other: Value<'_>) -> JsResult<i32> {
        Ok(match self.value.cmp(&parse_u64(&other)?) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }

    pub fn equals(&self, other: Value<'_>) -> bool {
        parse_u64(&other).is_ok_and(|value| value == self.value)
    }

    pub fn to_number(&self) -> f64 {
        self.value as f64
    }

    pub fn to_int32(&self) -> i32 {
        self.value as i32
    }

    pub fn to_u_int32(&self) -> u32 {
        self.value as u32
    }

    #[qjs(rename = "toString")]
    pub fn as_string(&self, radix: rquickjs::function::Opt<i32>) -> String {
        match radix.0.unwrap_or(10) {
            16 => format!("{:x}", self.value),
            2 => format!("{:b}", self.value),
            8 => format!("{:o}", self.value),
            _ => self.value.to_string(),
        }
    }

    #[qjs(rename = "valueOf")]
    pub fn value_of(&self) -> f64 {
        self.value as f64
    }
}

/// Install `ptr`, `NULL`, `Memory`, `Process`, `Module`, `Thread`, and Rust `Java`.
pub fn install<'js>(ctx: &Ctx<'js>, java_hooks: Rc<RefCell<JavaHookTable>>) -> JsResult<()> {
    let globals = ctx.globals();
    Class::<NativePointer>::define(&globals)?;
    Class::<Retval>::define(&globals)?;
    Class::<Int64>::define(&globals)?;
    Class::<UInt64>::define(&globals)?;

    globals.set(
        "ptr",
        Func::from(
            |ctx: Ctx<'js>, value: Value<'js>| -> JsResult<Class<'js, NativePointer>> {
                NativePointer::instance(ctx, parse_pointer(&value)?)
            },
        ),
    )?;
    globals.set("NULL", NativePointer::instance(ctx.clone(), 0)?)?;
    ctx.eval::<(), _>(
        r#"
        globalThis.int64 = function (v) { return new Int64(v); };
        globalThis.uint64 = function (v) { return new UInt64(v); };
        globalThis.MatchPattern = function (pattern) {
            this.toString = function () { return String(pattern); };
        };
        "#,
    )?;

    globals.set("Memory", memory_object(ctx)?)?;
    globals.set("Process", process_object(ctx)?)?;
    globals.set("Module", module_object(ctx)?)?;
    globals.set("Thread", thread_object(ctx)?)?;
    globals.set("__analyser_make_native", Func::from(make_native_function))?;
    ctx.eval::<(), _>(
        r#"
        globalThis.NativeFunction = function NativeFunction(address, retType, argTypes, options) {
            const impl = __analyser_make_native(address, retType, argTypes);
            try { Object.setPrototypeOf(impl, NativeFunction.prototype); } catch (e) {}
            impl.__addr = ptr(address).__addr;
            impl.isNull = function () { return ptr(this.__addr).isNull(); };
            impl.toString = function () { return ptr(this.__addr).toString(); };
            impl.add = function (d) { return ptr(this.__addr).add(d); };
            impl.sub = function (d) { return ptr(this.__addr).sub(d); };
            impl.equals = function (o) { return ptr(this.__addr).equals(o); };
            impl.compare = function (o) { return ptr(this.__addr).compare(o); };
            impl.and = function (o) { return ptr(this.__addr).and(o); };
            impl.or = function (o) { return ptr(this.__addr).or(o); };
            impl.xor = function (o) { return ptr(this.__addr).xor(o); };
            impl.not = function () { return ptr(this.__addr).not(); };
            impl.toInt32 = function () { return ptr(this.__addr).toInt32(); };
            impl.toUInt32 = function () { return ptr(this.__addr).toUInt32(); };
            return impl;
        };
        NativeFunction.prototype = Object.create(Function.prototype);
        NativeFunction.prototype.constructor = NativeFunction;
        "#,
    )?;
    install_script_and_file(ctx)?;
    crate::writer::install(ctx)?;
    crate::artctl::install(ctx)?;
    let instruction = Object::new(ctx.clone())?;
    instruction.set("parse", Func::from(crate::instruction::parse))?;
    ctx.globals().set("Instruction", instruction)?;
    crate::java::install(ctx, java_hooks)?;
    Ok(())
}

/// Install the base API plus `Interceptor` backed by the JS worker.
pub(crate) fn install_with_hooks<'js>(
    ctx: &Ctx<'js>,
    tx: Sender<Job>,
    hooks: Rc<RefCell<HookTable>>,
    callbacks: Rc<RefCell<CallbackTable>>,
    java_hooks: Rc<RefCell<JavaHookTable>>,
    event_tx: Sender<String>,
) -> JsResult<()> {
    install(ctx, java_hooks)?;
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
        Func::from({
            let hooks = hooks.clone();
            let tx = tx.clone();
            move |ctx: Ctx<'js>,
                  target: Value<'js>,
                  callbacks: Value<'js>|
                  -> JsResult<Object<'js>> {
                let id = attach_listener(&ctx, &hooks, &tx, target, callbacks)?;
                listener_object(ctx, hooks.clone(), id)
            }
        }),
    )?;
    interceptor.set(
        "replace",
        Func::from(
            |target: Value<'js>, replacement: Value<'js>| -> JsResult<()> {
                Interceptor::replace(
                    parse_pointer(&target)? as usize,
                    parse_pointer(&replacement)? as usize,
                )
                .map_err(to_js_error)
            },
        ),
    )?;
    interceptor.set(
        "revert",
        Func::from(|target: Value<'js>| -> JsResult<()> {
            Interceptor::revert(parse_pointer(&target)? as usize).map_err(to_js_error)
        }),
    )?;
    interceptor.set(
        "flush",
        Func::from({
            let hooks = hooks.clone();
            move || {
                for group in hooks.borrow().groups.iter() {
                    if let Some(hook) = group.hook.as_ref() {
                        memory::flush_icache(hook.trampoline(), 0x1000);
                    }
                }
                Interceptor::flush();
            }
        }),
    )?;
    interceptor.set(
        "detachAll",
        Func::from({
            let hooks = hooks.clone();
            move || {
                detach_all_listeners(&hooks);
            }
        }),
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
    Ok(())
}

fn install_script_and_file<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    let script = Object::new(ctx.clone())?;
    script.set(
        "nextTick",
        Func::from(|function: Function<'js>| {
            let _ = function.call::<_, ()>(());
        }),
    )?;
    script.set(
        "bindWeak",
        Func::from(|_target: Value<'js>, _fn: Function<'js>| -> u32 { 0 }),
    )?;
    script.set("unbindWeak", Func::from(|_id: u32| {}))?;
    ctx.globals().set("Script", script)?;

    let file = Object::new(ctx.clone())?;
    file.set(
        "readAllText",
        Func::from(|path: String| -> JsResult<String> {
            std::fs::read_to_string(&path).map_err(|err| js_error(err.to_string()))
        }),
    )?;
    ctx.globals().set("File", file)?;

    let debug = Object::new(ctx.clone())?;
    debug.set(
        "fromName",
        Func::from(|ctx: Ctx<'js>, name: String| -> JsResult<Object<'js>> {
            let address = crate::elf::find_export(None, &name)
                .ok()
                .flatten()
                .map(|(addr, _)| addr)
                .unwrap_or(0);
            let obj = Object::new(ctx.clone())?;
            obj.set("address", NativePointer::instance(ctx, address as u64)?)?;
            obj.set("name", name)?;
            Ok(obj)
        }),
    )?;
    ctx.globals().set("DebugSymbol", debug)?;

    ctx.globals().set(
        "CModule",
        Func::from(
            |ctx: Ctx<'js>,
             _code: String,
             _symbols: rquickjs::function::Opt<Value<'js>>|
             -> JsResult<Object<'js>> { Object::new(ctx) },
        ),
    )?;
    ctx.eval::<(), _>(
        r#"
        globalThis.setTimeout = function (fn, ms) {
            if (typeof Script !== 'undefined' && Script.nextTick) {
                Script.nextTick(fn);
            } else if (typeof fn === 'function') {
                fn();
            }
            return 0;
        };
        "#,
    )?;
    Ok(())
}

fn listener_object<'js>(
    ctx: Ctx<'js>,
    hooks: Rc<RefCell<HookTable>>,
    id: u32,
) -> JsResult<Object<'js>> {
    let listener = Object::new(ctx.clone())?;
    listener.set(
        "detach",
        Func::from(move || {
            detach_listener(&hooks, id);
        }),
    )?;
    Ok(listener)
}

fn attach_listener<'js>(
    ctx: &Ctx<'js>,
    hooks: &Rc<RefCell<HookTable>>,
    tx: &Sender<Job>,
    target: Value<'js>,
    callbacks: Value<'js>,
) -> JsResult<u32> {
    let address = usize::try_from(parse_pointer(&target)?)
        .map_err(|_| js_error("target address does not fit in usize"))?;
    if let Ok(pointer) = Class::<NativePointer>::from_value(&callbacks) {
        let native = pointer.borrow().value as usize;
        let hook = unsafe {
            InlineHook::attach(address, std::mem::transmute(native), std::ptr::null_mut())
        };
        return match hook {
            Ok(hook) => {
                let mut table = hooks.borrow_mut();
                let group = table.groups.len();
                table.groups.push(HookGroup {
                    target: address,
                    listeners: Vec::new(),
                    hook: Some(hook),
                    bridge: std::ptr::null_mut(),
                });
                Ok(register_listener_id(&mut table, group, usize::MAX))
            }
            Err(err) => Err(to_js_error(err)),
        };
    }
    let callbacks: Object<'js> = callbacks.get()?;
    let on_enter: Option<Function<'js>> = callbacks.get("onEnter")?;
    let on_leave: Option<Function<'js>> = callbacks.get("onLeave")?;
    let listener = Listener {
        on_enter: on_enter.map(|function| Persistent::save(ctx, function)),
        on_leave: on_leave.map(|function| Persistent::save(ctx, function)),
    };

    let (group, slot, need_hook, created_group) = {
        let mut table = hooks.borrow_mut();
        if let Some(index) = table.groups.iter().position(|g| g.target == address) {
            let inactive = table.groups[index]
                .hook
                .as_ref()
                .map(|hook| !hook.is_active())
                .unwrap_or(true);
            let slot = table.groups[index].listeners.len();
            table.groups[index].listeners.push(Some(listener));
            let id = register_listener_id(&mut table, index, slot);
            (index, id, inactive, false)
        } else {
            let index = table.groups.len();
            table.groups.push(HookGroup {
                target: address,
                listeners: vec![Some(listener)],
                hook: None,
                bridge: std::ptr::null_mut(),
            });
            let id = register_listener_id(&mut table, index, 0);
            (index, id, true, true)
        }
    };

    if !need_hook {
        return Ok(slot);
    }

    if !created_group {
        let mut table = hooks.borrow_mut();
        drop(table.groups[group].hook.take());
    }

    let bridge = make_bridge(group, address, tx.clone());
    // SAFETY: bridge stays alive in HookGroup; callbacks only use the
    // channel, SavedRegs and a stable target address.
    let hook = unsafe {
        InlineHook::attach_ex(address, hook_enter, Some(hook_leave), bridge as *mut c_void)
    };

    match hook {
        Ok(hook) => {
            let mut table = hooks.borrow_mut();
            table.groups[group].hook = Some(hook);
            table.groups[group].bridge = bridge;
            Ok(slot)
        }
        Err(err) => {
            let mut table = hooks.borrow_mut();
            if let Some(last) = table.listener_ids.last_mut() {
                *last = None;
            }
            if created_group {
                table.groups.pop();
            } else if let Some(group) = table.groups.get_mut(group) {
                group.listeners.pop();
            }
            Err(to_js_error(err))
        }
    }
}

fn register_listener_id(table: &mut HookTable, group: usize, slot: usize) -> u32 {
    let id = table.listener_ids.len() as u32;
    table.listener_ids.push(Some((group, slot)));
    id
}

fn detach_listener(hooks: &Rc<RefCell<HookTable>>, id: u32) {
    let mut table = hooks.borrow_mut();
    let Some(entry) = table
        .listener_ids
        .get_mut(id as usize)
        .and_then(|slot| slot.take())
    else {
        return;
    };
    let (group, slot) = entry;
    if let Some(group) = table.groups.get_mut(group) {
        if slot == usize::MAX {
            if let Some(hook) = group.hook.as_mut() {
                let _ = hook.detach();
            }
            return;
        }
        if let Some(listener) = group.listeners.get_mut(slot) {
            *listener = None;
        }
        let empty = group.listeners.iter().all(|listener| listener.is_none());
        if empty {
            if let Some(hook) = group.hook.as_mut() {
                let _ = hook.detach();
            }
        }
    }
}

fn detach_all_listeners(hooks: &Rc<RefCell<HookTable>>) {
    let mut table = hooks.borrow_mut();
    for group in &mut table.groups {
        group.listeners.clear();
        if let Some(hook) = group.hook.as_mut() {
            let _ = hook.detach();
        }
    }
    for slot in &mut table.listener_ids {
        *slot = None;
    }
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
    let n = arg_types.len().min(8);
    let mut call_args = Args::new(ctx.clone(), n);
    for index in 0..n {
        let ty = arg_types[index].as_str();
        let arg = args[index];
        let value: Value<'js> = if ty == "pointer" {
            NativePointer::instance(ctx.clone(), arg)?.into_value()
        } else if ty == "int64" || ty == "long" {
            Class::instance(ctx.clone(), Int64 { value: arg as i64 })?.into_value()
        } else if ty == "uint64" || ty == "ulong" || ty == "size_t" {
            Class::instance(ctx.clone(), UInt64 { value: arg })?.into_value()
        } else if is_signed_type(ty) {
            (arg as i64).into_js(ctx)?
        } else if ty == "bool" {
            (arg != 0).into_js(ctx)?
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
    if let Some(flag) = result.as_bool() {
        return Ok(u64::from(flag));
    }
    if let Ok(value) = Class::<Int64>::from_value(&result) {
        return Ok(value.borrow().value as u64);
    }
    if let Ok(value) = Class::<UInt64>::from_value(&result) {
        return Ok(value.borrow().value);
    }
    if ret_signed {
        result
            .get::<i64>()
            .or_else(|_| parse_i64(&result))
            .map(|value| value as u64)
    } else {
        result.get::<u64>().or_else(|_| parse_u64(&result))
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
            |ctx: Ctx<'js>,
             size: usize,
             spec: rquickjs::function::Opt<Object<'js>>|
             -> JsResult<Class<'js, NativePointer>> {
                let ptr = if let Some(spec) = spec.0 {
                    let near: Value<'js> = spec.get("near")?;
                    if near.is_undefined() || near.is_null() {
                        memory::alloc(size).map_err(to_js_error)?
                    } else {
                        let near = parse_pointer(&near)? as usize;
                        let max: Value<'js> = spec.get("maxDistance")?;
                        let max = if max.is_undefined() {
                            0x700_0000usize
                        } else {
                            parse_pointer(&max)? as usize
                        };
                        memory::alloc_near(size, near, max).map_err(to_js_error)?
                    }
                } else {
                    memory::alloc(size).map_err(to_js_error)?
                };
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
            |value: Value<'js>, size: usize, prot: Value<'js>| -> JsResult<bool> {
                let addr = parse_pointer(&value)?;
                let flags = if prot.is_string() {
                    memory::parse_prot(&prot.get::<String>()?).map_err(to_js_error)?
                } else {
                    prot.get::<i32>()?
                };
                memory::protect(addr as usize, size, flags).map_err(to_js_error)?;
                Ok(true)
            },
        ),
    )?;
    obj.set(
        "copy",
        Func::from(
            |dst: Value<'js>, src: Value<'js>, size: usize| -> JsResult<()> {
                memory::copy(
                    parse_pointer(&dst)? as usize,
                    parse_pointer(&src)? as usize,
                    size,
                )
                .map_err(to_js_error)
            },
        ),
    )?;
    obj.set(
        "dup",
        Func::from(
            |ctx: Ctx<'js>, src: Value<'js>, size: usize| -> JsResult<Class<'js, NativePointer>> {
                let ptr = memory::dup(parse_pointer(&src)? as usize, size).map_err(to_js_error)?;
                NativePointer::instance(ctx, ptr as u64)
            },
        ),
    )?;
    obj.set(
        "patchCode",
        Func::from(
            |ctx: Ctx<'js>,
             address: Value<'js>,
             size: usize,
             apply: Function<'js>|
             -> JsResult<()> {
                let addr = parse_pointer(&address)? as usize;
                memory::with_writable(addr, size, || {
                    NativePointer::instance(ctx.clone(), addr as u64)
                        .and_then(|pointer| apply.call::<_, ()>((pointer,)))
                })
                .map_err(to_js_error)?
            },
        ),
    )?;
    obj.set(
        "scanSync",
        Func::from(
            |ctx: Ctx<'js>,
             address: Value<'js>,
             size: usize,
             pattern: String|
             -> JsResult<Array<'js>> {
                let matches = memory::scan_sync(parse_pointer(&address)? as usize, size, &pattern)
                    .map_err(to_js_error)?;
                let array = Array::new(ctx.clone())?;
                for (index, item) in matches.into_iter().enumerate() {
                    let obj = Object::new(ctx.clone())?;
                    obj.set(
                        "address",
                        NativePointer::instance(ctx.clone(), item.address as u64)?,
                    )?;
                    obj.set("size", item.size)?;
                    array.set(index, obj)?;
                }
                Ok(array)
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
    obj.set("SYSTEM_UID", 1000u32)?;
    obj.set(
        "myUid",
        Func::from(|| -> u32 {
            // SAFETY: getuid cannot fail.
            unsafe { libc::getuid() as u32 }
        }),
    )?;
    obj.set(
        "getCurrentThreadId",
        Func::from(|| -> u32 { thread::current_id() }),
    )?;
    obj.set(
        "getModuleByName",
        Func::from(|ctx: Ctx<'js>, name: String| -> JsResult<Value<'js>> {
            match runtime::module::find_by_name(&name).map_err(to_js_error)? {
                Some(module) => Ok(module_object_from(ctx, &module)?.into_value()),
                None => Err(js_error(format!("unable to find module '{name}'"))),
            }
        }),
    )?;

    obj.set(
        "enumerateModules",
        Func::from(|ctx: Ctx<'js>| -> JsResult<Array<'js>> {
            let modules = module::enumerate().map_err(to_js_error)?;
            let array = Array::new(ctx.clone())?;
            for (index, module) in modules.into_iter().enumerate() {
                array.set(index, module_object_from(ctx.clone(), &module)?)?;
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
    obj.set(
        "findGlobalExportByName",
        Func::from(|ctx: Ctx<'js>, symbol: String| -> JsResult<Value<'js>> {
            let null = Value::new_null(ctx.clone());
            lookup_export(ctx, null, symbol)
        }),
    )?;
    obj.set(
        "getGlobalExportByName",
        Func::from(|ctx: Ctx<'js>, symbol: String| -> JsResult<Value<'js>> {
            match crate::elf::find_export(None, &symbol).map_err(to_js_error)? {
                Some((address, _)) => {
                    Ok(NativePointer::instance(ctx, address as u64)?.into_value())
                }
                None => Err(js_error(format!("export not found: {symbol}"))),
            }
        }),
    )?;
    Ok(obj)
}

fn thread_object<'js>(ctx: &Ctx<'js>) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set(
        "sleep",
        Func::from(|seconds: f64| {
            let millis = (seconds * 1000.0).max(0.0) as u64;
            std::thread::sleep(std::time::Duration::from_millis(millis));
        }),
    )?;
    Ok(obj)
}

fn module_object_from<'js>(
    ctx: Ctx<'js>,
    module: &runtime::module::Module,
) -> JsResult<Object<'js>> {
    let obj = Object::new(ctx.clone())?;
    obj.set("name", module.name.as_str())?;
    obj.set("path", module.path.as_str())?;
    obj.set(
        "base",
        NativePointer::instance(ctx.clone(), module.base as u64)?,
    )?;
    obj.set("size", module.size())?;
    let path = module.path.clone();
    let base = module.base;
    let name = module.name.clone();
    obj.set(
        "findExportByName",
        Func::from({
            let path = path.clone();
            let name = name.clone();
            move |ctx: Ctx<'js>, symbol: String| -> JsResult<Value<'js>> {
                match crate::elf::callable_export(&path, base, &name, &symbol)
                    .map_err(to_js_error)?
                {
                    Some(address) => Ok(NativePointer::instance(ctx, address as u64)?.into_value()),
                    None => Ok(Value::new_null(ctx)),
                }
            }
        }),
    )?;
    obj.set(
        "getExportByName",
        Func::from({
            let path = path.clone();
            let name = name.clone();
            move |ctx: Ctx<'js>, symbol: String| -> JsResult<Class<'js, NativePointer>> {
                match crate::elf::callable_export(&path, base, &name, &symbol)
                    .map_err(to_js_error)?
                {
                    Some(address) => NativePointer::instance(ctx, address as u64),
                    None => Err(js_error(format!("export not found: {symbol}"))),
                }
            }
        }),
    )?;
    obj.set(
        "findSymbolByName",
        Func::from({
            let path = path.clone();
            move |ctx: Ctx<'js>, symbol: String| -> JsResult<Value<'js>> {
                match crate::elf::find_symbol(&path, base, &symbol).map_err(to_js_error)? {
                    Some(address) => Ok(NativePointer::instance(ctx, address as u64)?.into_value()),
                    None => Ok(Value::new_null(ctx)),
                }
            }
        }),
    )?;
    obj.set(
        "enumerateExports",
        Func::from({
            let path = path.clone();
            move |ctx: Ctx<'js>| -> JsResult<Array<'js>> {
                symbols_array(
                    ctx,
                    crate::elf::enumerate_exports(&path, base).map_err(to_js_error)?,
                )
            }
        }),
    )?;
    obj.set(
        "enumerateSymbols",
        Func::from({
            let path = path.clone();
            move |ctx: Ctx<'js>| -> JsResult<Array<'js>> {
                symbols_array(
                    ctx,
                    crate::elf::enumerate_symbols(&path, base).map_err(to_js_error)?,
                )
            }
        }),
    )?;
    obj.set(
        "enumerateImports",
        Func::from({
            let path = path;
            move |ctx: Ctx<'js>| -> JsResult<Array<'js>> {
                symbols_array(
                    ctx,
                    crate::elf::enumerate_imports(&path, base).map_err(to_js_error)?,
                )
            }
        }),
    )?;
    Ok(obj)
}

fn symbols_array<'js>(ctx: Ctx<'js>, symbols: Vec<crate::elf::SymbolInfo>) -> JsResult<Array<'js>> {
    let array = Array::new(ctx.clone())?;
    for (index, symbol) in symbols.into_iter().enumerate() {
        let item = Object::new(ctx.clone())?;
        item.set("name", symbol.name)?;
        item.set(
            "address",
            NativePointer::instance(ctx.clone(), symbol.address as u64)?,
        )?;
        item.set("type", symbol.kind)?;
        array.set(index, item)?;
    }
    Ok(array)
}

pub(crate) fn parse_pointer(value: &Value<'_>) -> JsResult<u64> {
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
    if let Some(object) = value.as_object() {
        if let Ok(addr) = object.get::<_, u64>("__addr") {
            return Ok(addr);
        }
        if let Ok(addr) = object.get::<_, f64>("__addr") {
            return Ok(addr as u64);
        }
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

fn parse_i64(value: &Value<'_>) -> JsResult<i64> {
    if value.is_string() {
        return parse_i64_str(&value.get::<String>()?);
    }
    if value.is_number() {
        return Ok(value.as_number().unwrap_or(0.0) as i64);
    }
    if value.is_bool() {
        return Ok(i64::from(value.as_bool().unwrap_or(false)));
    }
    if let Ok(int) = Class::<Int64>::from_value(value) {
        return Ok(int.borrow().value);
    }
    if let Ok(int) = Class::<UInt64>::from_value(value) {
        return Ok(int.borrow().value as i64);
    }
    if let Ok(pointer) = Class::<NativePointer>::from_value(value) {
        return Ok(pointer.borrow().value as i64);
    }
    Err(js_error("expected an integer"))
}

fn parse_u64(value: &Value<'_>) -> JsResult<u64> {
    if value.is_string() {
        return parse_u64_str(&value.get::<String>()?);
    }
    if value.is_number() {
        let number = value.as_number().unwrap_or(0.0);
        if number < 0.0 {
            return Ok(number as i64 as u64);
        }
        return Ok(number as u64);
    }
    if value.is_bool() {
        return Ok(u64::from(value.as_bool().unwrap_or(false)));
    }
    if let Ok(int) = Class::<UInt64>::from_value(value) {
        return Ok(int.borrow().value);
    }
    if let Ok(int) = Class::<Int64>::from_value(value) {
        return Ok(int.borrow().value as u64);
    }
    if let Ok(pointer) = Class::<NativePointer>::from_value(value) {
        return Ok(pointer.borrow().value);
    }
    Err(js_error("expected an integer"))
}

fn parse_i64_str(text: &str) -> JsResult<i64> {
    let text = text.trim();
    if let Some(hex) = text
        .strip_prefix("-0x")
        .or_else(|| text.strip_prefix("-0X"))
    {
        let bits = u64::from_str_radix(hex, 16).map_err(|_| js_error("invalid int64"))?;
        return Ok(bits.wrapping_neg() as i64);
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        let bits = u64::from_str_radix(hex, 16).map_err(|_| js_error("invalid int64"))?;
        return Ok(bits as i64);
    }
    text.parse::<i64>()
        .or_else(|_| text.parse::<u64>().map(|value| value as i64))
        .map_err(|_| js_error(format!("invalid int64: {text}")))
}

fn parse_u64_str(text: &str) -> JsResult<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_err(|_| js_error("invalid uint64"));
    }
    text.parse::<u64>()
        .or_else(|_| text.parse::<i64>().map(|value| value as u64))
        .map_err(|_| js_error(format!("invalid uint64: {text}")))
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
        let ty: String = array.get(index)?;
        if ty != "..." {
            types.push(ty);
        }
    }
    let returns_pointer = ret_type == "pointer";
    let returns_bool = ret_type == "bool";

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
                    "bool" => u64::from(value.get::<bool>()?),
                    "float" => value.get::<f64>()?.to_bits() & 0xFFFF_FFFF,
                    "double" => value.get::<f64>()?.to_bits(),
                    _ if is_signed_type(ty) => value.get::<i64>()? as u64,
                    _ => value.get::<u64>().or_else(|_| parse_pointer(value))?,
                };
            }
            let argc = values.0.len().min(8);
            // SAFETY: the caller supplied the function address and signature.
            let result = unsafe { native::call(target, &raw[..argc.max(types.len()).min(8)]) }
                .map_err(to_js_error)?;
            if returns_void {
                Ok(Value::new_undefined(call_ctx.clone()))
            } else if returns_pointer {
                Ok(NativePointer::instance(call_ctx.clone(), result)?.into_value())
            } else if returns_bool {
                (result != 0).into_js(&call_ctx)
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
