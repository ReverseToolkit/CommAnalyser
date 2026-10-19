//! TAL door via statically linked `tal_prepare` / `tal_enter`.
//! CommAnalyser Interceptor is the attach; TAL owns the QBDI VM.

use std::ptr;

use gum::hook::{InlineHook, SavedRegs};
use runtime::{Error, Result};

use crate::load;
use crate::session::TraceConfig;
use crate::{EventKind, EventRing, TraceEvent};

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
    let api = load::api()?;
    let target = usize::try_from(config.target)
        .map_err(|_| Error::Parse("Trace.function: target does not fit".into()))?;
    if target == 0 {
        return Err(Error::Parse("Trace.function: null target".into()));
    }
    let until = config.until.unwrap_or(0);
    if unsafe { (api.prepare)(config.target, until, 0, 3) } != 0 {
        return Err(Error::Parse("tal_prepare failed".into()));
    }
    for escape in &config.escapes {
        unsafe { (api.add_escape)(escape.break_at, escape.resume) };
    }
    // SAFETY: on_enter only uses process-lifetime session state.
    let hook = unsafe { InlineHook::attach(target, on_enter, ptr::null_mut())? };
    let mut table = sessions();
    table.clear();
    table.push(Some(EngineState {
        hook: Some(SendHook(hook)),
        ring: EventRing::new(4096),
    }));
    Ok(0)
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
    let Ok(api) = load::api() else {
        return;
    };
    let cpu = load::TalCpuContext {
        x: unsafe { (*regs).x },
        fp: unsafe { (*regs).fp },
        lr: unsafe { (*regs).lr },
        sp: unsafe { (*regs).sp },
        nzcv: unsafe { (*regs).nzcv },
        pc: unsafe { (*regs).pc },
    };
    let _ = unsafe { (api.enter)(&cpu) };
}

pub fn drain_events() -> Vec<TraceEvent> {
    let Ok(api) = load::api() else {
        return Vec::new();
    };
    let mut buf = vec![load::TalEvent::default(); 4096];
    let n = unsafe { (api.take_events)(buf.as_mut_ptr(), buf.len()) };
    buf.truncate(n);
    buf.into_iter()
        .map(|event| TraceEvent {
            kind: match event.kind {
                1 => EventKind::Mem,
                2 => EventKind::Call,
                _ => EventKind::Inst,
            },
            pc: event.pc,
            size: event.size as u16,
            mem_addr: event.mem_addr,
            mem_value: event.mem_value,
            is_write: event.is_write != 0,
        })
        .collect()
}
