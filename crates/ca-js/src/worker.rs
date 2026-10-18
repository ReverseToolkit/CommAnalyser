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

/// One hook listener registered from JavaScript.
pub(crate) struct HookListener {
    pub(crate) on_enter: Option<Persistent<Function<'static>>>,
    pub(crate) hook: Option<InlineHook>,
    /// Raw pointer to the `HookBridge` embedded in the trampoline's user_data.
    pub(crate) bridge: *mut HookBridge,
}

/// Shared state for one installed hook.
pub(crate) struct HookBridge {
    pub(crate) id: usize,
    pub(crate) target: usize,
    pub(crate) tx: Sender<Job>,
}

#[derive(Default)]
pub(crate) struct HookTable {
    pub(crate) listeners: Vec<HookListener>,
}

pub(crate) enum Job {
    Eval {
        code: String,
        reply: Sender<Result<String>>,
    },
    Hook {
        id: usize,
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
            Job::Hook {
                id,
                target,
                regs,
                reply,
            } => {
                let _ = reply.send(runtime.run_hook(id, target, regs));
            }
            Job::Shutdown => break,
        }
    }
}

/// Trampoline installed into `InlineHook` for JS `Interceptor.attach`.
pub(crate) unsafe extern "C" fn hook_trampoline(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() || is_js_thread() {
        return;
    }
    if HOOK_ACTIVE.with(Cell::get) {
        return;
    }
    HOOK_ACTIVE.with(|flag| flag.set(true));

    // SAFETY: `data` points to a HookBridge kept alive by HookListener.
    let bridge = unsafe { &*(data as *const HookBridge) };
    let (reply, response) = mpsc::channel();
    if bridge
        .tx
        .send(Job::Hook {
            id: bridge.id,
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

pub(crate) fn make_bridge(id: usize, target: usize, tx: Sender<Job>) -> *mut HookBridge {
    Box::into_raw(Box::new(HookBridge { id, target, tx }))
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
