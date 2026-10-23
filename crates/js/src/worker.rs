//! Dedicated QuickJS worker thread.
//!
//! QuickJS is not safe to enter concurrently, and `Context` is thread-affine
//! in rquickjs.  All JS execution therefore happens on one thread.  Hook
//! callbacks (which run on arbitrary target threads) send a synchronous job to
//! this worker and wait for the possibly-modified registers.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rquickjs::{Function, Persistent};

use art::hook::JavaHook;
use art::java::{JavaClass, MethodInfo};
use gum::{InlineHook, SavedRegs};
use runtime::{Error, Result};

use crate::ScriptRuntime;

/// Marks the current thread as already inside a hook callback.
///
/// RAII: a panic inside the callback is contained by `ffi::guard`, and the
/// flag must still be cleared, otherwise every later hook on that thread would
/// be silently skipped.
struct HookActiveGuard;

impl HookActiveGuard {
    fn enter() -> Option<Self> {
        if HOOK_ACTIVE.with(Cell::get) {
            return None;
        }
        HOOK_ACTIVE.with(|flag| flag.set(true));
        Some(Self)
    }
}

impl Drop for HookActiveGuard {
    fn drop(&mut self) {
        HOOK_ACTIVE.with(|flag| flag.set(false));
    }
}

thread_local! {
    static JS_THREAD: Cell<bool> = const { Cell::new(false) };
    static JAVA_HOOKS_TLS: RefCell<Option<Rc<RefCell<JavaHookTable>>>> =
        const { RefCell::new(None) };
    static HOOK_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static JAVA_IMPL_DEPTH: Cell<u32> = const { Cell::new(0) };
    static RUNTIME: Cell<*const ScriptRuntime> = const { Cell::new(std::ptr::null()) };
}

/// How many Java `implementation` callbacks are on this thread's stack.
pub(crate) fn java_impl_depth() -> u32 {
    JAVA_IMPL_DEPTH.with(Cell::get)
}

pub(crate) struct JavaImplGuard;

impl JavaImplGuard {
    pub(crate) fn enter() -> Self {
        JAVA_IMPL_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for JavaImplGuard {
    fn drop(&mut self) {
        JAVA_IMPL_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
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
    pub(crate) listeners: Vec<Option<Listener>>,
    pub(crate) hook: Option<InlineHook>,
    pub(crate) bridge: *mut HookBridge,
}

#[derive(Default)]
pub(crate) struct HookTable {
    pub(crate) groups: Vec<HookGroup>,
    /// Stable ids for `listener.detach()`.  Slot `None` is a detached listener.
    pub(crate) listener_ids: Vec<Option<(usize, usize)>>,
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct DispatchResult {
    pub(crate) x0: u64,
    pub(crate) d0: u64,
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
        fargs: [u64; 8],
        params: [u64; 16],
        stack: [u64; 8],
        globals: u32,
        reply: Sender<DispatchResult>,
    },
    Shutdown,
}

#[derive(Clone, Copy)]
pub(crate) struct JavaImplArgs {
    pub args: [u64; 8],
    pub fargs: [u64; 8],
    pub params: [u64; 16],
    pub stack: [u64; 8],
    pub globals: u32,
}

pub(crate) fn find_java_hook(
    class_name: &str,
    method: &art::java::MethodInfo,
) -> Option<Rc<RefCell<art::hook::JavaHook>>> {
    JAVA_HOOKS_TLS.with(|slot| {
        let table = slot.borrow();
        let table = table.as_ref()?;
        let table = table.borrow();
        table.entries.iter().flatten().find_map(|entry| {
            (entry.class.info.name == class_name
                && entry.method.name == method.name
                && entry.method.signature == method.signature
                && entry.method.is_static == method.is_static)
                .then(|| entry.hook.clone())
        })
    })
}

/// Handle used by the agent control thread and by hook trampolines.
///
/// Deliberately not Clone: dropping any handle sends Shutdown, so a clone
/// would let an unrelated scope terminate the JS thread.
pub struct JsWorker {
    tx: Sender<Job>,
    recv: std::sync::Arc<crate::extras::RecvQueue>,
}

impl JsWorker {
    pub fn spawn(event_tx: Sender<String>) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let worker_tx = tx.clone();
        let recv = crate::extras::RecvQueue::new();
        let recv_worker = recv.clone();
        std::thread::Builder::new()
            .name("js".to_owned())
            .spawn(move || worker_loop(rx, worker_tx, event_tx, recv_worker))
            .map_err(Error::Io)?;
        Ok(Self { tx, recv })
    }

    /// Host → script message, consumed by `recv().wait()`.
    pub fn post(&self, json: impl Into<String>) {
        self.recv.post(json.into());
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

    pub(crate) fn fire_enter(
        &self,
        group: usize,
        target: usize,
        regs: SavedRegs,
    ) -> Result<SavedRegs> {
        let (reply, response) = mpsc::channel();
        self.tx
            .send(Job::Enter {
                group,
                target,
                regs,
                reply,
            })
            .map_err(|_| Error::Unsupported("JS worker stopped"))?;
        response
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| Error::Unsupported("JS worker timed out"))
    }

    pub(crate) fn fire_leave(
        &self,
        group: usize,
        target: usize,
        regs: SavedRegs,
    ) -> Result<SavedRegs> {
        let (reply, response) = mpsc::channel();
        self.tx
            .send(Job::Leave {
                group,
                target,
                regs,
                reply,
            })
            .map_err(|_| Error::Unsupported("JS worker stopped"))?;
        response
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| Error::Unsupported("JS worker timed out"))
    }
}

impl Drop for JsWorker {
    fn drop(&mut self) {
        let _ = self.tx.send(Job::Shutdown);
    }
}

/// Wall-clock budget for one JS job, in milliseconds.
const HOOK_BUDGET_MS: u64 = 4_000;
const SCRIPT_BUDGET_MS: u64 = 8_000;
// Background work must yield promptly to waiting hook callbacks.
const BACKGROUND_BUDGET_MS: u64 = 100;

/// How often the worker collects and drains finalizers.  Java handles are
/// released from a FinalizationRegistry callback, which QuickJS queues as a
/// job; without pumping jobs those references would never be freed.
const GC_INTERVAL: u32 = 128;
const MAX_FINALIZER_JOBS: usize = 64;

struct Budget<'a>(&'a AtomicU64);

impl<'a> Budget<'a> {
    fn enter(deadline: &'a AtomicU64, epoch: Instant, budget_ms: u64) -> Self {
        let now = epoch.elapsed().as_millis() as u64;
        deadline.store(now + budget_ms, Ordering::Release);
        Self(deadline)
    }
}

impl Drop for Budget<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

fn pump_background(runtime: &ScriptRuntime, deadline: &AtomicU64, epoch: Instant, collect: bool) {
    let _budget = Budget::enter(deadline, epoch, BACKGROUND_BUDGET_MS);
    if collect {
        runtime.runtime().run_gc();
    }
    runtime.with_js(|ctx| {
        for _ in 0..MAX_FINALIZER_JOBS {
            if !ctx.execute_pending_job() {
                break;
            }
        }
        crate::extras::fire_due_timers(&ctx);
    });
}

fn worker_loop(
    rx: Receiver<Job>,
    tx: Sender<Job>,
    event_tx: Sender<String>,
    recv: std::sync::Arc<crate::extras::RecvQueue>,
) {
    crate::extras::bind_recv_queue(recv);
    JS_THREAD.with(|flag| flag.set(true));
    if JS_TX.set(tx.clone()).is_err() {
        // A second worker cannot receive cross-thread dispatch: the trampolines
        // have no per-runtime context.  Say so instead of silently routing
        // callbacks to the previous (possibly dead) worker.
        eprintln!("[js] a worker is already registered for cross-thread dispatch");
    }
    let hooks = Rc::new(RefCell::new(HookTable::default()));
    let callbacks = Rc::new(RefCell::new(CallbackTable::default()));
    let java_hooks = Rc::new(RefCell::new(JavaHookTable::default()));
    JAVA_HOOKS_TLS.with(|slot| *slot.borrow_mut() = Some(java_hooks.clone()));
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
    RUNTIME.with(|slot| slot.set(&runtime as *const ScriptRuntime));
    let mut jobs_since_gc: u32 = 0;

    // A runaway script must not wedge the worker: every hooked thread waits on
    // it, so an unterminated loop becomes an ANR in the guest. QuickJS calls
    // this between bytecode instructions; returning true aborts the script.
    let epoch = Instant::now();
    let deadline = Arc::new(AtomicU64::new(0));
    {
        let deadline = deadline.clone();
        runtime
            .runtime()
            .set_interrupt_handler(Some(Box::new(move || {
                let armed = deadline.load(Ordering::Relaxed);
                armed != 0 && epoch.elapsed().as_millis() as u64 > armed
            })));
    }

    loop {
        let wait = if runtime.runtime().is_job_pending() {
            Duration::ZERO
        } else {
            crate::extras::next_timer_wait()
        };
        let job = match rx.recv_timeout(wait) {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                pump_background(&runtime, &deadline, epoch, false);
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        // Hook callbacks have a 5 s waiter on the other side; evals have the
        // control channel's 10 s. Interrupt slightly earlier so the caller
        // sees a script error instead of a silent timeout.
        let interactive = matches!(&job, Job::Eval { .. } | Job::Rpc { .. });
        let budget = if interactive {
            SCRIPT_BUDGET_MS
        } else {
            HOOK_BUDGET_MS
        };
        let budget = Budget::enter(&deadline, epoch, budget);
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
                fargs,
                params,
                stack,
                globals,
                reply,
            } => {
                let hook = java_hooks
                    .borrow()
                    .entries
                    .get(id)
                    .and_then(|entry| entry.as_ref().map(|entry| entry.hook.clone()));
                let _ = reply.send(runtime.run_java_impl(
                    id,
                    JavaImplArgs {
                        args,
                        fargs,
                        params,
                        stack,
                        globals,
                    },
                    hook,
                ));
            }
            Job::Shutdown => break,
        }
        drop(budget);
        jobs_since_gc = jobs_since_gc.wrapping_add(1);
        // Interactive jobs collect every time: a script that allocates and
        // reads handle stats in two eval()s sees the state after collection.
        // Hook traffic amortizes instead, because it is hot.
        let collect = interactive || jobs_since_gc >= GC_INTERVAL;
        if collect {
            jobs_since_gc = 0;
        }
        pump_background(&runtime, &deadline, epoch, collect);
    }
    // QuickJS can assert in JS_FreeRuntime when the host closes the control
    // channel while any JS closure is still reachable.  Hooks are detached
    // first, then the runtime is intentionally leaked with the process.
    runtime.shutdown();
    std::mem::forget(runtime);
}

/// Trampoline for `Interceptor.attach` onEnter.
pub(crate) unsafe extern "C" fn hook_enter(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    // A panic here would unwind into Gum's C frame and abort the guest.
    runtime::ffi::guard("Interceptor.onEnter", || unsafe {
        hook_enter_inner(regs, data);
    });
}

unsafe fn hook_enter_inner(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() {
        return;
    }
    let Some(_active) = HookActiveGuard::enter() else {
        return;
    };

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if !runtime.is_null() {
            let updated = unsafe { (*runtime).run_enter(bridge.group, bridge.target, *regs) };
            unsafe { *regs = updated };
        }
        return;
    }
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
}

/// Trampoline for `Interceptor.attach` onLeave.
pub(crate) unsafe extern "C" fn hook_leave(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    runtime::ffi::guard("Interceptor.onLeave", || unsafe {
        hook_leave_inner(regs, data);
    });
}

unsafe fn hook_leave_inner(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() {
        return;
    }
    let Some(_active) = HookActiveGuard::enter() else {
        return;
    };

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if !runtime.is_null() {
            let updated = unsafe { (*runtime).run_leave(bridge.group, bridge.target, *regs) };
            unsafe { *regs = updated };
        }
        return;
    }
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
}

/// Dispatcher embedded in every NativeCallback stub.
pub(crate) extern "C" fn callback_dispatch(id: usize, args: *const u64) -> u64 {
    runtime::ffi::guard("NativeCallback", || unsafe {
        callback_dispatch_inner(id, args)
    })
    .unwrap_or(0)
}

unsafe fn callback_dispatch_inner(id: usize, args: *const u64) -> u64 {
    if args.is_null() {
        return 0;
    }
    let mut raw = [0u64; 8];
    // SAFETY: the callback stub guarantees a pointer to eight x-registers.
    unsafe { std::ptr::copy_nonoverlapping(args, raw.as_mut_ptr(), 8) };
    if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if runtime.is_null() {
            return 0;
        }
        return unsafe { (*runtime).run_callback(id, raw) };
    }
    let Some(tx) = JS_TX.get() else {
        return 0;
    };
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
    let mut value = response.recv_timeout(Duration::from_secs(5)).unwrap_or(0);
    if value != 0 && crate::java::hook_returns_object(id) {
        value = art::soa::global_to_raw(value as usize).unwrap_or(0) as u64;
    }
    value
}

/// Dispatcher embedded in every Java method trampoline.
pub(crate) extern "C" fn java_dispatch(
    id: usize,
    args: *const u64,
    fargs: *const u64,
    stack: *const u64,
) -> DispatchResult {
    runtime::ffi::guard("Java.implementation", || unsafe {
        java_dispatch_inner(id, args, fargs, stack)
    })
    .unwrap_or_default()
}

unsafe fn java_dispatch_inner(
    id: usize,
    args: *const u64,
    fargs: *const u64,
    stack: *const u64,
) -> DispatchResult {
    let mut saved = [0u64; 8];
    if !args.is_null() {
        // SAFETY: the hook stub passes a pointer to its saved x0-x7.
        unsafe { std::ptr::copy_nonoverlapping(args, saved.as_mut_ptr(), 8) };
    }
    let mut float_args = [0u64; 8];
    if !fargs.is_null() {
        // SAFETY: the hook stub passes a pointer to its saved d0-d7.
        unsafe { std::ptr::copy_nonoverlapping(fargs, float_args.as_mut_ptr(), 8) };
    }
    let mut stack_args = [0u64; 8];
    if !stack.is_null() {
        // SAFETY: the stub passes the caller SP; the native ABI guarantees at
        // least the stack slots consumed by the hooked method.
        unsafe { std::ptr::copy_nonoverlapping(stack, stack_args.as_mut_ptr(), 8) };
    }
    let mut params = [0u64; 16];
    let mut globals = 0u32;
    let jni_mode = crate::java::hook_jni_mode(id);
    if let Some((is_static, param_kinds)) = crate::java::hook_meta_for(id) {
        let mut int_index = if jni_mode {
            2
        } else if is_static {
            1
        } else {
            2
        };
        let mut fp_index = 0usize;
        let mut stack_index = 0usize;
        if !is_static {
            let this_global = if jni_mode {
                if saved[0] != 0 && saved[1] != 0 {
                    art::java::jni_new_global(saved[0] as usize, saved[1] as usize)
                        .map(|handle| handle as u64)
                        .unwrap_or(saved[1])
                } else {
                    saved[1]
                }
            } else if saved[1] != 0 {
                art::soa::convert(saved[1] as usize).unwrap_or(saved[1] as usize) as u64
            } else {
                saved[1]
            };
            saved[1] = this_global;
            globals |= 1;
        }
        for (slot, kind) in param_kinds.iter().enumerate() {
            let raw = match kind {
                art::java::Kind::Float | art::java::Kind::Double => {
                    if fp_index < 8 {
                        let value = float_args[fp_index];
                        fp_index += 1;
                        value
                    } else {
                        let value = stack_args.get(stack_index).copied().unwrap_or(0);
                        stack_index += 1;
                        value
                    }
                }
                _ => {
                    if int_index < 8 {
                        let value = saved[int_index];
                        int_index += 1;
                        value
                    } else {
                        let value = stack_args.get(stack_index).copied().unwrap_or(0);
                        stack_index += 1;
                        value
                    }
                }
            };
            let value = if matches!(kind, art::java::Kind::Object(_) | art::java::Kind::Array(_))
                && raw != 0
            {
                if jni_mode && saved[0] != 0 {
                    art::java::jni_new_global(saved[0] as usize, raw as usize)
                        .map(|handle| handle as u64)
                        .unwrap_or(raw)
                } else if !jni_mode {
                    art::soa::convert(raw as usize).unwrap_or(raw as usize) as u64
                } else {
                    raw
                }
            } else {
                raw
            };
            params[slot] = value;
            if value != raw
                || (raw != 0
                    && matches!(kind, art::java::Kind::Object(_) | art::java::Kind::Array(_)))
            {
                globals |= 1 << (slot + 1);
            }
        }
    }
    let call = JavaImplArgs {
        args: saved,
        fargs: float_args,
        params,
        stack: stack_args,
        globals,
    };
    let hook = JAVA_HOOKS_TLS.with(|slot| {
        slot.borrow().as_ref().and_then(|table| {
            table
                .borrow()
                .entries
                .get(id)
                .and_then(|entry| entry.as_ref().map(|entry| entry.hook.clone()))
        })
    });
    let mut result = if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if runtime.is_null() {
            DispatchResult::default()
        } else {
            // SAFETY: RUNTIME is the live ScriptRuntime on this JS worker.
            unsafe { (*runtime).run_java_impl(id, call, hook) }
        }
    } else {
        let Some(tx) = JS_TX.get() else {
            return DispatchResult::default();
        };
        let (reply, response) = mpsc::channel();
        if tx
            .send(Job::JavaImpl {
                id,
                args: saved,
                fargs: float_args,
                params,
                stack: stack_args,
                globals,
                reply,
            })
            .is_err()
        {
            return DispatchResult::default();
        }
        response
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default()
    };
    if let Some(message) = crate::java::take_java_error() {
        let _ = art::java::throw_runtime_exception(&message);
    }
    if result.x0 != 0 && crate::java::hook_returns_object(id) {
        result.x0 = art::soa::global_to_raw(result.x0 as usize).unwrap_or(0) as u64;
    }
    result
}

pub(crate) fn make_bridge(group: usize, target: usize, tx: Sender<Job>) -> *mut HookBridge {
    Box::into_raw(Box::new(HookBridge { group, target, tx }))
}

#[cfg(test)]
mod tests {
    use super::JsWorker;
    use gum::SavedRegs;

    #[test]
    fn evaluates_on_worker() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        assert_eq!(worker.eval("6 * 7").unwrap(), "42");
        assert_eq!(worker.eval("typeof Interceptor").unwrap(), "object");
        assert_eq!(worker.eval("typeof NativeFunction").unwrap(), "function");
        assert_eq!(worker.eval("typeof NativeCallback").unwrap(), "function");
        assert_eq!(
            worker
                .eval("!new NativeCallback(function (p) { return p; }, 'pointer', ['pointer']).isNull()")
                .unwrap(),
            "true"
        );
        assert_eq!(worker.eval("typeof Java").unwrap(), "object");
        assert_eq!(worker.eval("typeof Java.ClassFactory").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.perform").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.performNow").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.use").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.choose").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.cast").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.retain").unwrap(), "function");
        assert_eq!(worker.eval("typeof Java.array").unwrap(), "function");
        assert_eq!(
            worker.eval("typeof Java.vm !== 'undefined'").unwrap(),
            "true"
        );
        assert_eq!(worker.eval("Java.available").unwrap(), "false");
        assert_eq!(worker.eval("typeof Java.ACC_PUBLIC").unwrap(), "undefined");
        worker
            .eval("rpc.exports.add = (a, b) => a + b; send({hello: 1}); 'ok'")
            .unwrap();
        assert_eq!(worker.rpc("add", "[1, 2]").unwrap(), "3");
    }

    #[test]
    fn arm64_writer_relocator_roundtrip() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let result = worker
            .eval(
                r#"
                (function () {
                    const buf = Memory.alloc(256);
                    const writer = new Arm64Writer(buf, { pc: buf });
                    writer.putPushAllXRegisters();
                    writer.putCallAddressWithArguments(ptr(0x1000), ['x0']);
                    writer.putPopAllXRegisters();
                    writer.putLabel('done');
                    writer.putBLabel('done');
                    writer.putRet();
                    writer.flush();
                    const relocator = new Arm64Relocator(buf, writer);
                    if (typeof relocator.dispose !== 'function') return 'reloc-dispose';
                    const offset = relocator.readOne();
                    if (!(offset > 0)) return 'reloc-offset:' + offset;
                    if (!relocator.input || typeof relocator.input.mnemonic !== 'string') {
                        return 'reloc-input';
                    }
                    relocator.writeAll();
                    relocator.dispose();
                    writer.dispose();
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn set_timeout_fires_on_worker_after_delay() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        worker
            .eval("globalThis.__delayed = 0; setTimeout(function () { __delayed = 1; }, 25); 'queued'")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert_eq!(worker.eval("String(__delayed)").unwrap(), "1");
    }

    #[test]
    fn runaway_background_callbacks_do_not_wedge_worker() {
        let _js = crate::js_test_guard();
        let (events, received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        // The event synchronizes with the idle timer path, outside eval's budget.
        worker
            .eval("setTimeout(() => { send('timer'); while (true) {} }, 25); 'queued'")
            .unwrap();
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(worker.eval("6 * 7").unwrap(), "42");
        worker
            .eval("Promise.resolve().then(() => { send('job'); while (true) {} }); 'queued'")
            .unwrap();
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(worker.eval("40 + 2").unwrap(), "42");
    }

    #[test]
    fn interceptor_frida_api_and_detach() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let result = worker
            .eval(
                r#"
                (function () {
                    if (typeof Interceptor.attach !== 'function') return 'attach';
                    if (typeof Interceptor.replace !== 'function') return 'replace';
                    if (typeof Interceptor.revert !== 'function') return 'revert';
                    if (typeof Interceptor.flush !== 'function') return 'flush';
                    if (typeof Interceptor.detachAll !== 'function') return 'detachAll';
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    const listener = Interceptor.attach(page, {
                        onEnter: function () {},
                        onLeave: function () {}
                    });
                    if (typeof listener.detach !== 'function') return 'listener-detach';
                    const after = page.readU32() >>> 0;
                    if ((after & 0xfc000000) !== 0x14000000) return 'patch:' + after.toString(16);
                    listener.detach();
                    const restored = page.readU32() >>> 0;
                    if (restored !== 0xd503201f) return 'restored:' + restored.toString(16);
                    const l2 = Interceptor.attach(page, { onEnter: function () {} });
                    const again = page.readU32() >>> 0;
                    if ((again & 0xfc000000) !== 0x14000000) return 'reattach:' + again.toString(16);
                    Interceptor.detachAll();
                    Interceptor.flush();
                    const afterAll = page.readU32() >>> 0;
                    if (afterAll !== 0xd503201f) return 'detachAll:' + afterAll.toString(16);
                    const l3 = Interceptor.attach(page, { onEnter: function () {} });
                    const againAll = page.readU32() >>> 0;
                    if ((againAll & 0xfc000000) !== 0x14000000) {
                        return 'reattachAll:' + againAll.toString(16);
                    }
                    Interceptor.detachAll();
                    const afterAll2 = page.readU32() >>> 0;
                    if (afterAll2 !== 0xd503201f) return 'detachAll2:' + afterAll2.toString(16);
                    const _ = l2;
                    const __ = l3;
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn interceptor_enter_rewrites_args_and_leave_replaces_retval() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let addr = worker
            .eval(
                r#"
                (function () {
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    globalThis.__hookHits = [];
                    Interceptor.attach(page, {
                        onEnter: function (args) {
                            __hookHits.push('e' + args[0].toInt32());
                            args[0] = ptr(42);
                        },
                        onLeave: function (retval) {
                            __hookHits.push('l');
                            retval.replace(ptr(7));
                        }
                    });
                    return page.toString();
                })()
                "#,
            )
            .unwrap();
        let target = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap() as usize;
        let mut regs = SavedRegs::default();
        regs.x[0] = 3;
        let after_enter = worker.fire_enter(0, target, regs).unwrap();
        assert_eq!(after_enter.x[0], 42, "onEnter must rewrite args[0]");
        let mut leave_regs = SavedRegs::default();
        leave_regs.x[0] = 99;
        let after_leave = worker.fire_leave(0, target, leave_regs).unwrap();
        assert_eq!(after_leave.x[0], 7, "onLeave must retval.replace");
        let hits = worker.eval("__hookHits.join(',')").unwrap();
        assert_eq!(hits, "e3,l");
    }

    #[test]
    fn native_callback_from_js_thread() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let result = worker
            .eval(
                r#"
                (function () {
                    const cb = new NativeCallback(function (p) {
                        return p.add(1);
                    }, 'pointer', ['pointer']);
                    const fn = new NativeFunction(cb, 'pointer', ['pointer']);
                    const got = fn(ptr('0x10'));
                    if (got.toString() !== '0x11') return 'add:' + got;
                    const argcCb = new NativeCallback(function () {
                        return arguments.length;
                    }, 'int', ['pointer', 'pointer']);
                    const argcFn = new NativeFunction(argcCb, 'int', ['pointer', 'pointer']);
                    const n = argcFn(ptr(1), ptr(2));
                    if (n !== 2) return 'argc:' + n;
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn send_delivers_payload_on_event_channel() {
        let _js = crate::js_test_guard();
        let (events, received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        assert_eq!(worker.eval("send({hello: 1}); 'ok'").unwrap(), "ok");
        let line = received
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("send event");
        assert!(line.contains("\"op\":\"send\""), "{line}");
        assert!(line.contains("\"hello\":1"), "{line}");
    }

    #[test]
    fn set_immediate_fires_on_eval() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        worker
            .eval("globalThis.__imm = 0; setImmediate(function () { __imm = 1; }); 'queued'")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(worker.eval("String(__imm)").unwrap(), "1");
    }

    #[test]
    fn interceptor_enter_rewrites_context_gprs() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let addr = worker
            .eval(
                r#"
                (function () {
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    Interceptor.attach(page, {
                        onEnter: function (args) {
                            args[1] = ptr(99);
                            this.context.x28 = ptr(0x55);
                            this.context.lr = ptr(0x1234);
                            this.context.nzcv = ptr(0x20000000);
                        }
                    });
                    return page.toString();
                })()
                "#,
            )
            .unwrap();
        let target = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap() as usize;
        let mut regs = SavedRegs::default();
        regs.x[1] = 1;
        regs.x[28] = 2;
        let after = worker.fire_enter(0, target, regs).unwrap();
        assert_eq!(after.x[1], 99);
        assert_eq!(after.x[28], 0x55);
        assert_eq!(after.lr, 0x1234);
        assert_eq!(after.nzcv, 0x2000_0000);
    }

    #[test]
    fn interceptor_enter_rewrites_context_vectors() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let addr = worker
            .eval(
                r#"
                (function () {
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    Interceptor.attach(page, {
                        onEnter: function () {
                            if (this.context.q0.byteLength !== 16) {
                                throw new Error('q0');
                            }
                            if (this.context.d0 !== 1.5) {
                                throw new Error('d0=' + this.context.d0);
                            }
                            if (this.context.s1 !== 2) {
                                throw new Error('s1=' + this.context.s1);
                            }
                            if (this.context.q31.byteLength !== 16) {
                                throw new Error('q31');
                            }
                            this.context.d0 = 4;
                            this.context.s1 = 0.25;
                            const bytes = new Uint8Array(this.context.q2);
                            bytes[0] = 0x11;
                            this.context.d31 = 7;
                        }
                    });
                    return page.toString();
                })()
                "#,
            )
            .unwrap();
        let target = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap() as usize;
        let mut regs = SavedRegs::default();
        regs.q[0] = 1.5f64.to_bits() as u128;
        regs.q[1] = 2.0f32.to_bits() as u128;
        regs.q[31] = 1;
        let after = worker.fire_enter(0, target, regs).unwrap();
        assert_eq!(after.q[0] as u64, 4.0f64.to_bits(), "d0");
        assert_eq!(after.q[1] as u32, 0.25f32.to_bits(), "s1");
        assert_eq!(after.q[2] as u8, 0x11, "q2 byte 0");
        assert_eq!(after.q[31] as u64, 7.0f64.to_bits(), "d31");
    }

    #[test]
    fn interceptor_enter_rewrites_context_x0() {
        let _js = crate::js_test_guard();
        let (events, _received) = std::sync::mpsc::channel();
        let worker = JsWorker::spawn(events).unwrap();
        let addr = worker
            .eval(
                r#"
                (function () {
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    Interceptor.attach(page, {
                        onEnter: function (args) {
                            if (args[0] !== this.context.x0) {
                                throw new Error('args[0] must be this.context.x0');
                            }
                            this.context.x0 = ptr(42);
                        }
                    });
                    return page.toString();
                })()
                "#,
            )
            .unwrap();
        let target = u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap() as usize;
        let mut regs = SavedRegs::default();
        regs.x[0] = 3;
        let after = worker.fire_enter(0, target, regs).unwrap();
        assert_eq!(after.x[0], 42, "onEnter must rewrite this.context.x0");
    }
}
