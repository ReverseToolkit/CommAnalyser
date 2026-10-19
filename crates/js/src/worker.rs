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

fn worker_loop(rx: Receiver<Job>, tx: Sender<Job>, event_tx: Sender<String>) {
    JS_THREAD.with(|flag| flag.set(true));
    let _ = JS_TX.set(tx.clone());
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
    }
    // QuickJS can assert in JS_FreeRuntime when the host closes the control
    // channel while any JS closure is still reachable.  Hooks are detached
    // first, then the runtime is intentionally leaked with the process.
    runtime.shutdown();
    std::mem::forget(runtime);
}

/// Trampoline for `Interceptor.attach` onEnter.
pub(crate) unsafe extern "C" fn hook_enter(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() {
        return;
    }
    if HOOK_ACTIVE.with(Cell::get) {
        return;
    }
    HOOK_ACTIVE.with(|flag| flag.set(true));

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if !runtime.is_null() {
            let updated = unsafe { (*runtime).run_enter(bridge.group, bridge.target, *regs) };
            unsafe { *regs = updated };
        }
        HOOK_ACTIVE.with(|flag| flag.set(false));
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

    HOOK_ACTIVE.with(|flag| flag.set(false));
}

/// Trampoline for `Interceptor.attach` onLeave.
pub(crate) unsafe extern "C" fn hook_leave(regs: *mut SavedRegs, data: *mut std::ffi::c_void) {
    if regs.is_null() || data.is_null() {
        return;
    }
    if HOOK_ACTIVE.with(Cell::get) {
        return;
    }
    HOOK_ACTIVE.with(|flag| flag.set(true));

    // SAFETY: `data` points to a HookBridge kept alive by HookGroup.
    let bridge = unsafe { &*(data as *const HookBridge) };
    if is_js_thread() {
        let runtime = RUNTIME.with(Cell::get);
        if !runtime.is_null() {
            let updated = unsafe { (*runtime).run_leave(bridge.group, bridge.target, *regs) };
            unsafe { *regs = updated };
        }
        HOOK_ACTIVE.with(|flag| flag.set(false));
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

    HOOK_ACTIVE.with(|flag| flag.set(false));
}

/// Dispatcher embedded in every NativeCallback stub.
pub(crate) extern "C" fn callback_dispatch(id: usize, args: *const u64) -> u64 {
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
    fn interceptor_frida_api_and_detach() {
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
}
