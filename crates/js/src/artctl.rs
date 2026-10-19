//! Rust stand-in for frida-java-bridge's ART CModule controller.
//!
//! The C functions use the same integer ABI the ARM64 trampolines call, and
//! the interpreter hook uses [`gum::SavedRegs`] so `Interceptor.attach` can
//! point at them directly.

use std::collections::HashMap;
use std::sync::Mutex;

use gum::SavedRegs;
use rquickjs::{Ctx, Function, Object, Result as JsResult};

use crate::api::{parse_pointer, NativePointer};

struct Controller {
    methods: HashMap<usize, usize>,
    replacements: HashMap<usize, usize>,
    last_seen: usize,
    managed_stack: usize,
    top_quick_frame: usize,
    link: usize,
    oat_impl: usize,
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            methods: HashMap::new(),
            replacements: HashMap::new(),
            last_seen: 0,
            managed_stack: 0,
            top_quick_frame: 0,
            link: 0,
            oat_impl: 0,
        }
    }
}

static CTL: std::sync::OnceLock<Mutex<Controller>> = std::sync::OnceLock::new();

fn lock() -> std::sync::MutexGuard<'static, Controller> {
    CTL.get_or_init(|| Mutex::new(Controller::default()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

/// Install the ART replacement-method registry used by java-bridge.
pub fn install<'js>(ctx: &Ctx<'js>) -> JsResult<()> {
    ctx.globals().set(
        "__analyserArtController",
        Function::new(ctx.clone(), create)?,
    )?;
    Ok(())
}

fn create<'js>(ctx: Ctx<'js>, options: Object<'js>) -> JsResult<Object<'js>> {
    {
        let mut ctl = lock();
        ctl.managed_stack = int_opt(&options, "managedStack")?;
        ctl.top_quick_frame = int_opt(&options, "topQuickFrame")?;
        ctl.link = int_opt(&options, "link")?;
        ctl.oat_impl = int_opt(&options, "getOatQuickMethodHeaderImpl")?;
        ctl.methods.clear();
        ctl.replacements.clear();
    }

    let out = Object::new(ctx.clone())?;
    out.set(
        "isReplacement",
        NativePointer::instance(ctx.clone(), is_replacement as *const () as usize as u64)?,
    )?;
    out.set(
        "getReplacement",
        NativePointer::instance(ctx.clone(), get_replacement as *const () as usize as u64)?,
    )?;
    out.set(
        "setReplacement",
        NativePointer::instance(ctx.clone(), set_replacement as *const () as usize as u64)?,
    )?;
    out.set(
        "deleteReplacement",
        NativePointer::instance(ctx.clone(), delete_replacement as *const () as usize as u64)?,
    )?;
    out.set(
        "translate",
        NativePointer::instance(ctx.clone(), translate as *const () as usize as u64)?,
    )?;
    out.set(
        "synchronize",
        NativePointer::instance(ctx.clone(), synchronize as *const () as usize as u64)?,
    )?;
    out.set(
        "findReplacementFromQuickCode",
        NativePointer::instance(
            ctx.clone(),
            find_replacement_from_quick_code as *const () as usize as u64,
        )?,
    )?;
    out.set(
        "onInterpreterDoCall",
        NativePointer::instance(
            ctx.clone(),
            on_interpreter_do_call as *const () as usize as u64,
        )?,
    )?;
    out.set(
        "onPrettyMethod",
        NativePointer::instance(ctx.clone(), on_pretty_method as *const () as usize as u64)?,
    )?;
    out.set(
        "onGcLeave",
        NativePointer::instance(ctx.clone(), on_gc_leave as *const () as usize as u64)?,
    )?;
    out.set(
        "onGetOatQuickMethodHeader",
        NativePointer::instance(
            ctx.clone(),
            on_get_oat_quick_method_header as *const () as usize as u64,
        )?,
    )?;
    Ok(out)
}

fn int_opt<'js>(options: &Object<'js>, key: &str) -> JsResult<usize> {
    let value: Value<'js> = options.get(key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(0);
    }
    Ok(parse_pointer(&value)? as usize)
}

use rquickjs::Value;

unsafe extern "C" fn is_replacement(method: u64) -> u64 {
    u64::from(lock().replacements.contains_key(&(method as usize)))
}

unsafe extern "C" fn get_replacement(method: u64) -> u64 {
    lock().methods.get(&(method as usize)).copied().unwrap_or(0) as u64
}

unsafe extern "C" fn set_replacement(original: u64, replacement: u64) {
    let mut ctl = lock();
    ctl.methods.insert(original as usize, replacement as usize);
    ctl.replacements
        .insert(replacement as usize, original as usize);
}

unsafe extern "C" fn delete_replacement(original: u64) {
    let mut ctl = lock();
    if let Some(replacement) = ctl.methods.remove(&(original as usize)) {
        ctl.replacements.remove(&replacement);
    }
}

unsafe extern "C" fn translate(method: u64) -> u64 {
    let ctl = lock();
    ctl.replacements
        .get(&(method as usize))
        .copied()
        .unwrap_or(method as usize) as u64
}

unsafe extern "C" fn synchronize(_quick_code_offset: u32, nterp: u64, bridge: u64) {
    let ctl = lock();
    for (hooked, replacement) in ctl.methods.clone() {
        let flags = unsafe { std::ptr::read_unaligned(hooked as *const u32) };
        unsafe { std::ptr::write_unaligned(replacement as *mut u32, flags) };
        if nterp != 0 {
            // quickCode is at offset 24 on Android 15; java-bridge passes the
            // live offset as the first argument when it knows it.
            let _ = (bridge, hooked);
        }
    }
}

unsafe extern "C" fn find_replacement_from_quick_code(method: u64, thread: u64) -> u64 {
    let ctl = lock();
    let Some(&replacement) = ctl.methods.get(&(method as usize)) else {
        return 0;
    };
    if thread == 0 {
        return replacement as u64;
    }
    let managed = thread as usize + ctl.managed_stack;
    let top_frame =
        unsafe { std::ptr::read_unaligned((managed + ctl.top_quick_frame) as *const usize) };
    if top_frame != 0 {
        return replacement as u64;
    }
    let link = unsafe { std::ptr::read_unaligned((managed + ctl.link) as *const usize) };
    if link == 0 {
        return replacement as u64;
    }
    let link_top =
        unsafe { std::ptr::read_unaligned((link + ctl.top_quick_frame) as *const usize) } & !1;
    if link_top == 0 {
        return replacement as u64;
    }
    let frame_method = unsafe { std::ptr::read_unaligned(link_top as *const usize) };
    if frame_method != replacement {
        return replacement as u64;
    }
    0
}

unsafe extern "C" fn on_interpreter_do_call(regs: *mut SavedRegs, _data: *mut std::ffi::c_void) {
    if regs.is_null() {
        return;
    }
    let method = unsafe { (*regs).x[0] };
    let replacement = get_replacement(method);
    if replacement != 0 {
        unsafe { (*regs).x[0] = replacement };
    }
}

unsafe extern "C" fn on_pretty_method(regs: *mut SavedRegs, _data: *mut std::ffi::c_void) {
    if regs.is_null() {
        return;
    }
    let method = unsafe { (*regs).x[0] };
    let mut ctl = lock();
    if method == 0 {
        unsafe { (*regs).x[0] = ctl.last_seen as u64 };
    } else {
        ctl.last_seen = method as usize;
    }
}

unsafe extern "C" fn on_gc_leave(regs: *mut SavedRegs, _data: *mut std::ffi::c_void) {
    let _ = regs;
    synchronize(0, 0, 0);
}

unsafe extern "C" fn on_get_oat_quick_method_header(method: u64, pc: u64) -> u64 {
    if is_replacement(method) != 0 {
        return 0;
    }
    let impl_addr = lock().oat_impl;
    if impl_addr == 0 {
        return 0;
    }
    let trampoline = gum::original_trampoline(impl_addr).unwrap_or(impl_addr);
    unsafe { gum::native::call(trampoline, &[method, pc]).unwrap_or(0) }
}
