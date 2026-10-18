//! Dedicated QuickJS worker thread.
//!
//! QuickJS is not safe to enter concurrently, and `Context` is thread-affine
//! in rquickjs.  All JS execution therefore happens on one thread.  Hook
//! callbacks (which run on arbitrary target threads) send a synchronous job to
//! this worker and wait for the possibly-modified registers.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use rquickjs::{Function, Persistent};

use ca_core::{Error, Result};
use ca_gum::{InlineHook, SavedRegs};

use crate::ScriptRuntime;

thread_local! {
    static JS_THREAD: Cell<bool> = const { Cell::new(false) };
    static HOOK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

fn is_js_thread() -> bool {
    JS_THREAD.with(Cell::get)
}

/// One listener registered by `Interceptor.attach`.
pub(crate) struct Listener {
    pub(crate) on_enter: Option<Persistent<Function<'static>>>,
    pub(crate) on_leave: Option<Persistent<Function<'static>>>,
}

/// All listeners for one target address, plus the single inline hook.
pub(crate) struct HookGroup {
    pub(crate) target: usize,
    pub(crate) listeners: Vec<Listener>,
    pub(crate) hook: Option<InlineHook>,
    pub(crate) bridge: *mut HookBridge,
}

#[derive(Default)]
pub(crate) struct HookTable {
    pub(crate) groups: Vec<HookGroup>,
}

pub(crate) struct HookBridge {
    pub(crate) group: usize,
    pub(crate) target: usize,
    pub(crate) tx: Sender<Job>,
}

pub(crate) enum Job {
    Eval {
        code: String,
        reply: Sender<Result<String>>,
    },
    Enter {
        group: usize,
        target: usize,
        regs: SavedRegs,
        reply: Sender<SavedRegs>,
    },
    Leave {
        group: usize,
        target: usize,
        regs: SavedRegs,
        reply: Sender<SavedRegs>,
    },
    Shutdown,
}

/// Handle used by the agent control thread and by hook trampolines.
#[derive(Clone)]
pub struct JsWorker {
    tx: Sender<Job>,
}

impl JsWorker {
    pub fn spawn() -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let worker_tx = tx.clone();
        std::thread::Builder::new()
            .name("ca-js".to_owned())
            .spawn(move || worker_loop(rx, worker_tx))
            .map_err(Error::Io)?;
        Ok(Self { tx })
    }

    pub fn eval(&self, code: &str) -> Result<String> {
        let (reply, response) = mpsc::channel();
        self.tx
            .send(Job::Eval {
                code: code.to_owned(),
                reply,
            })
            .map_err(|_| Error::Unsupported("JS worker stopped"))?;
        response
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::Unsupported("JS worker timed out"))?
    }
}

impl Drop for JsWorker {
    fn drop(&mut self) {
        let _ = self.tx.send(Job::Shutdown);
    }
}

fn worker_loop(rx: Receiver<Job>, tx: Sender<Job>) {
    JS_THREAD.with(|flag| flag.set(true));
    let hooks = Rc::new(RefCell::new(HookTable::default()));
    let runtime = match ScriptRuntime::new_with_hooks(tx, hooks.clone()) {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("[ca-js] failed to create runtime: {err}");
            return;
        }
    };

    while let Ok(job) = rx.recv() {
        match job {
            Job::Eval { code, reply } => {
                let _ = reply.send(runtime.eval(&code));
            }
            Job::Enter {
                group,
                target,
                regs,
                reply,
            } => {
                let _ = reply.send(runtime.run_enter(group, target, regs));
            }
            Job::Leave {
                group,
                target,
                regs,
                reply,
            } => {
                let _ = reply.send(runtime.run_leave(group, target, regs));
            }
            Job::Shutdown => break,
        }
    }
}

/// Trampoline for `Interceptor.attach` onEnter.
pub(crate) unsafe extern "C" fn hook_enter(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() || is_js_thread() {
        return;
    }
    if HOOK_ACTIVE.with(Cell::get) {
        return;
    }
    HOOK_ACTIVE.with(|flag| flag.set(true));

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    let (reply, response) = mpsc::channel();
    if bridge
        .tx
        .send(Job::Enter {
            group: bridge.group,
            target: bridge.target,
            regs: unsafe { *regs },
            reply,
        })
        .is_ok()
    {
        if let Ok(updated) = response.recv_timeout(Duration::from_secs(5)) {
            // SAFETY: regs is the live SavedRegs passed by the trampoline.
            unsafe { *regs = updated };
        }
    }

    HOOK_ACTIVE.with(|flag| flag.set(false));
}

/// Trampoline for `Interceptor.attach` onLeave.
pub(crate) unsafe extern "C" fn hook_leave(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() || is_js_thread() {
        return;
    }
    if HOOK_ACTIVE.with(Cell::get) {
        return;
    }
    HOOK_ACTIVE.with(|flag| flag.set(true));

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    let (reply, response) = mpsc::channel();
    if bridge
        .tx
        .send(Job::Leave {
            group: bridge.group,
            target: bridge.target,
            regs: unsafe { *regs },
            reply,
        })
        .is_ok()
    {
        if let Ok(updated) = response.recv_timeout(Duration::from_secs(5)) {
            // SAFETY: regs is the live SavedRegs passed by the return stub.
            unsafe { *regs = updated };
        }
    }

    HOOK_ACTIVE.with(|flag| flag.set(false));
}

pub(crate) fn make_bridge(group: usize, target: usize, tx: Sender<Job>) -> *mut HookBridge {
    Box::into_raw(Box::new(HookBridge { group, target, tx }))
}

#[cfg(test)]
mod tests {
    use super::JsWorker;

    #[test]
    fn evaluates_on_worker() {
        let worker = JsWorker::spawn().unwrap();
        assert_eq!(worker.eval("6 * 7").unwrap(), "42");
        assert_eq!(worker.eval("typeof Interceptor").unwrap(), "object");
    }
}
