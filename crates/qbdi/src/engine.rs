//! Trace door. CommAnalyser Interceptor is the attach; QBDI runs the body.

use std::ptr;

use gum::hook::{InlineHook, SavedRegs};
use runtime::{Error, Result};

use crate::load::{self, GuestRegs};
use crate::session::TraceConfig;
use crate::{EventRing, TraceEvent};

struct EngineState {
    hook: Option<SendHook>,
    ring: EventRing,
}

struct SendHook(InlineHook);

unsafe impl Send for SendHook {}

static SESSIONS: std::sync::Mutex<Vec<Option<EngineState>>> = std::sync::Mutex::new(Vec::new());

fn sessions() -> std::sync::MutexGuard<'static, Vec<Option<EngineState>>> {
    SESSIONS.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn install(config: TraceConfig) -> Result<u32> {
    let target = usize::try_from(config.target)
        .map_err(|_| Error::Parse("Trace.function: target does not fit".into()))?;
    if target == 0 {
        return Err(Error::Parse("Trace.function: null target".into()));
    }
    load::prepare(
        config.target,
        config.until.unwrap_or(0),
        &config.events,
        &config.extra_exclude,
    )?;
    for escape in &config.escapes {
        load::add_escape(escape.break_at, escape.resume);
    }
    // SAFETY: on_enter only uses process-lifetime session state. QBDI already
    // ran the function; the trampoline must return to LR instead of the
    // relocated original (that would sqrt(d0) a second time).
    let hook = unsafe { InlineHook::attach_and_return(target, on_enter, ptr::null_mut())? };
    let mut table = sessions();
    table.clear();
    table.push(Some(EngineState {
        hook: Some(SendHook(hook)),
        ring: EventRing::new(4096),
    }));
    Ok(0)
}

/// `XPACI X16`. Android's `gum_strip_code_address` is a no-op; Stalker still
/// strips before a pointer is used as a branch target.
fn strip_pac(ptr: u64) -> u64 {
    let mut x16 = ptr;
    unsafe {
        core::arch::asm!(
            ".inst 0xdac143f0",
            inout("x16") x16,
            options(nostack, preserves_flags),
        );
    }
    x16
}

unsafe extern "C" fn on_enter(regs: *mut SavedRegs, _data: *mut std::ffi::c_void) {
    if regs.is_null() {
        return;
    }
    let mut hook = {
        let mut table = sessions();
        table
            .last_mut()
            .and_then(|slot| slot.as_mut())
            .and_then(|state| state.hook.take())
    };
    if let Some(SendHook(ref mut hook)) = hook {
        let _ = hook.detach();
    }
    let orig_lr = unsafe { (*regs).lr };
    let start = strip_pac(unsafe { (*regs).pc });
    // hypot's paciasp already signed LR with the real SP. The VM skips
    // autiasp, so the copy it runs with must be the stripped address. The
    // trampoline still returns through the original signed LR.
    let stop = strip_pac(orig_lr);
    let mut guest = GuestRegs {
        x: unsafe { (*regs).x },
        fp: unsafe { (*regs).fp },
        lr: stop,
        sp: unsafe { (*regs).sp },
        nzcv: unsafe { (*regs).nzcv },
        pc: start,
        q: unsafe { (*regs).q },
    };
    if load::run(&mut guest, start, stop).is_err() {
        return;
    }
    unsafe {
        (*regs).x = guest.x;
        (*regs).fp = guest.fp;
        (*regs).lr = orig_lr;
        (*regs).sp = guest.sp;
        (*regs).nzcv = guest.nzcv;
        (*regs).pc = guest.pc;
        (*regs).q = guest.q;
    }
}

pub fn drain_events() -> Vec<TraceEvent> {
    load::take_events()
}
