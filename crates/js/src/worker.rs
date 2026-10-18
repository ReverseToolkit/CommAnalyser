//! Dedicated QuickJS worker thread.
//!
//! QuickJS is not safe to enter concurrently, and `Context` is thread-affine
//! in rquickjs.  All JS execution therefore happens on one thread.  Hook
//! callbacks (which run on arbitrary target threads) send a synchronous job to
//! this worker and wait for the possibly-modified registers.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::OnceLock;
use std::time::Duration;

use rquickjs::{Function, Persistent};

use art::hook::JavaHook;
use art::java::{JavaClass, MethodInfo};
use gum::{InlineHook, SavedRegs};
use runtime::{Error, Result};

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

pub(crate) struct JavaHookEntry {
    pub(crate) function: Persistent<Function<'static>>,
    pub(crate) class: Rc<JavaClass>,
    pub(crate) method: MethodInfo,
    // Held so the entrypoint is restored when the table is dropped.
    pub(crate) hook: Rc<RefCell<JavaHook>>,
}

#[derive(Default)]
pub(crate) struct JavaHookTable {
    /// Ids are stable: detaching sets the slot to `None` instead of shifting
    /// other entries (their dispatcher stubs embed the id).
    pub(crate) entries: Vec<Option<JavaHookEntry>>,
}

pub(crate) struct CallbackEntry {
    pub(crate) function: Persistent<Function<'static>>,
    pub(crate) arg_types: Vec<String>,
    pub(crate) ret_void: bool,
    pub(crate) ret_signed: bool,
    pub(crate) ret_pointer: bool,
}

#[derive(Default)]
pub(crate) struct CallbackTable {
    pub(crate) entries: Vec<CallbackEntry>,
}

static JS_TX: OnceLock<Sender<Job>> = OnceLock::new();

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
    Callback {
        id: usize,
        args: [u64; 8],
        reply: Sender<u64>,
    },
    Rpc {
        name: String,
        args: String,
        reply: Sender<Result<String>>,
    },
    JavaImpl {
        id: usize,
        args: [u64; 8],
        this_global: bool,
        reply: Sender<u64>,
    },
    Shutdown,
}

/// Handle used by the agent control thread and by hook trampolines.
#[derive(Clone)]
pub struct JsWorker {
    tx: Sender<Job>,
}

impl JsWorker {
    pub fn spawn(event_tx: Sender<String>) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let worker_tx = tx.clone();
        std::thread::Builder::new()
            .name("js".to_owned())
            .spawn(move || worker_loop(rx, worker_tx, event_tx))
            .map_err(Error::Io)?;
        Ok(Self { tx })
    }

    pub fn rpc(&self, name: &str, args: &str) -> Result<String> {
        let (reply, response) = mpsc::channel();
        self.tx
            .send(Job::Rpc {
                name: name.to_owned(),
                args: args.to_owned(),
                reply,
            })
            .map_err(|_| Error::Unsupported("JS worker stopped"))?;
        response
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::Unsupported("JS worker timed out"))?
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

fn worker_loop(rx: Receiver<Job>, tx: Sender<Job>, event_tx: Sender<String>) {
    JS_THREAD.with(|flag| flag.set(true));
    let _ = JS_TX.set(tx.clone());
    let hooks = Rc::new(RefCell::new(HookTable::default()));
    let callbacks = Rc::new(RefCell::new(CallbackTable::default()));
    let java_hooks = Rc::new(RefCell::new(JavaHookTable::default()));
    let runtime = match ScriptRuntime::new_with_hooks(
        tx,
        hooks.clone(),
        callbacks,
        java_hooks.clone(),
        event_tx,
    ) {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("[js] failed to create runtime: {err}");
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
            Job::Callback { id, args, reply } => {
                let _ = reply.send(runtime.run_callback(id, args));
            }
            Job::Rpc { name, args, reply } => {
                let _ = reply.send(runtime.run_rpc(&name, &args));
            }
            Job::JavaImpl {
                id,
                args,
                this_global,
                reply,
            } => {
                let hook = java_hooks
                    .borrow()
                    .entries
                    .get(id)
                    .and_then(|entry| entry.as_ref().map(|entry| entry.hook.clone()));
                let _ = reply.send(runtime.run_java_impl(id, args, this_global, hook));
            }
            Job::Shutdown => break,
        }
    }
    // QuickJS can assert in JS_FreeRuntime when the host closes the control
    // channel while any JS closure is still reachable.  Hooks are detached
    // first, then the runtime is intentionally leaked with the process.
    runtime.shutdown();
    std::mem::forget(runtime);
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

/// Dispatcher embedded in every NativeCallback stub.
pub(crate) extern "C" fn callback_dispatch(id: usize, args: *const u64) -> u64 {
    if args.is_null() || is_js_thread() {
        return 0;
    }
    let Some(tx) = JS_TX.get() else {
        return 0;
    };
    let mut raw = [0u64; 8];
    // SAFETY: the callback stub guarantees a pointer to eight x-registers.
    unsafe { std::ptr::copy_nonoverlapping(args, raw.as_mut_ptr(), 8) };
    let (reply, response) = mpsc::channel();
    if tx
        .send(Job::Callback {
            id,
            args: raw,
            reply,
        })
        .is_err()
    {
        return 0;
    }
    response.recv_timeout(Duration::from_secs(5)).unwrap_or(0)
}

/// Dispatcher embedded in every Java method trampoline.
pub(crate) extern "C" fn java_dispatch(id: usize, args: *const u64) -> u64 {
    if is_js_thread() {
        return 0;
    }
    let Some(tx) = JS_TX.get() else {
        return 0;
    };
    let mut saved = [0u64; 8];
    if !args.is_null() {
        // SAFETY: the hook stub passes a pointer to its saved x0-x7.
        unsafe { std::ptr::copy_nonoverlapping(args, saved.as_mut_ptr(), 8) };
    }
    let mut this_global = false;
    if crate::java::hook_is_static(id) == Some(false) && saved[1] != 0 {
        if let Ok(handle) = art::soa::convert(saved[1] as usize) {
            saved[1] = handle as u64;
            this_global = true;
        }
    }
    let (reply, response) = mpsc::channel();
    if tx
        .send(Job::JavaImpl {
            id,
            args: saved,
            this_global,
            reply,
        })
        .is_err()
    {
        return 0;
    }
    response.recv_timeout(Duration::from_secs(5)).unwrap_or(0)
}

pub(crate) fn make_bridge(group: usize, target: usize, tx: Sender<Job>) -> *mut HookBridge {
    Box::into_raw(Box::new(HookBridge { group, target, tx }))
}

#[cfg(test)]
mod tests {
    use super::JsWorker;

    #[test]
    fn evaluates_on_worker() {
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        assert_eq!(worker.eval("6 * 7").unwrap(), "42");
        assert_eq!(worker.eval("typeof Interceptor").unwrap(), "object");
        assert_eq!(worker.eval("typeof NativeFunction").unwrap(), "function");
        assert_eq!(worker.eval("typeof NativeCallback").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java").unwrap(), "object");
        assert_eq!(worker.eval("Java.available").unwrap(), "true");
        worker
            .eval("rpc.exports.add = (a, b) => a + b; send({hello: 1}); 'ok'")
            .unwrap();
        assert_eq!(worker.rpc("add", "[1, 2]").unwrap(), "3");
    }
}
