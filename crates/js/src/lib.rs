//! QuickJS runtime for CommAnalyser.
//!
//! M0 only proves the embedding path (runtime/context/eval/console).  The
//! Frida API objects are added incrementally in later milestones.

mod api;
mod cmodule;
mod elf;
mod extras;
mod il2cpp;
mod instruction;
mod java;
pub mod native;
mod trace;
mod worker;
mod writer;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::Sender;

use gum::SavedRegs;
use rquickjs::{CatchResultExt, Context, Ctx, Function, Runtime};
use runtime::{Error, Result};

thread_local! {
    static JS_ENTER_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct JsEnterGuard;

impl Drop for JsEnterGuard {
    fn drop(&mut self) {
        JS_ENTER_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub use java::last_java_error;
pub use worker::JsWorker;

use worker::{CallbackTable, HookTable, JavaHookTable, Job};

pub struct ScriptRuntime {
    // Drop order matters: JS values in the tables and the context must be
    // released before the runtime.  `rt` is therefore last.
    ctx: Context,
    hooks: Rc<RefCell<HookTable>>,
    callbacks: Rc<RefCell<CallbackTable>>,
    java_hooks: Rc<RefCell<JavaHookTable>>,
    rt: Runtime,
}

impl ScriptRuntime {
    pub fn new() -> Result<Self> {
        Self::new_inner(
            None,
            Rc::new(RefCell::new(HookTable::default())),
            Rc::new(RefCell::new(CallbackTable::default())),
            Rc::new(RefCell::new(JavaHookTable::default())),
            None,
        )
    }

    pub(crate) fn new_with_hooks(
        tx: Sender<Job>,
        hooks: Rc<RefCell<HookTable>>,
        callbacks: Rc<RefCell<CallbackTable>>,
        java_hooks: Rc<RefCell<JavaHookTable>>,
        event_tx: Sender<String>,
    ) -> Result<Self> {
        Self::new_inner(Some(tx), hooks, callbacks, java_hooks, Some(event_tx))
    }

    fn new_inner(
        tx: Option<Sender<Job>>,
        hooks: Rc<RefCell<HookTable>>,
        callbacks: Rc<RefCell<CallbackTable>>,
        java_hooks: Rc<RefCell<JavaHookTable>>,
        event_tx: Option<Sender<String>>,
    ) -> Result<Self> {
        let rt = Runtime::new().map_err(js_error)?;
        let ctx = Context::full(&rt).map_err(js_error)?;

        ctx.with(|ctx| -> Result<()> {
            let print = Function::new(ctx.clone(), |msg: String| {
                println!("{msg}");
            })
            .map_err(js_error)?;
            ctx.globals().set("print", print).map_err(js_error)?;
            crate::extras::bind_recv_queue(crate::extras::RecvQueue::new());
            ctx.eval::<(), _>(
                r#"
                globalThis.console = {
                    log: (...args) => print(args.map(String).join(' ')),
                    warn: (...args) => print(args.map(String).join(' ')),
                    error: (...args) => print(args.map(String).join(' ')),
                };
                globalThis.__analyser_string = v => String(v);
                globalThis.rpc = { exports: {} };
                "#,
            )
            .map_err(js_error)?;
            match (tx, event_tx) {
                (Some(tx), Some(event_tx)) => api::install_with_hooks(
                    &ctx,
                    tx,
                    hooks.clone(),
                    callbacks.clone(),
                    java_hooks.clone(),
                    event_tx,
                ),
                _ => api::install(&ctx, java_hooks.clone()),
            }
            .map_err(js_error)?;
            Ok(())
        })?;

        Ok(Self {
            ctx,
            hooks,
            callbacks,
            java_hooks,
            rt,
        })
    }

    /// Evaluate a script/expression and return `String(value)`.
    pub fn eval(&self, source: &str) -> Result<String> {
        self.with_js(|ctx| {
            let stringify: Function = ctx.globals().get("__analyser_string").map_err(js_error)?;
            let value: rquickjs::Value = ctx
                .eval(source)
                .catch(&ctx)
                .map_err(|err| js_caught_error(err))?;
            let text: String = stringify
                .call((value,))
                .catch(&ctx)
                .map_err(|err| js_caught_error(err))?;
            extras::fire_due_timers(&ctx);
            Ok(text)
        })
    }

    pub fn runtime(&self) -> &Runtime {
        &self.rt
    }

    /// Enter QuickJS, reusing the already-held runtime lock on nested
    /// NativeCallback / Interceptor dispatch from the JS thread.
    ///
    /// rquickjs `Context::with` borrows a `RefCell` and panics (or deadlocks
    /// with the `parallel` feature) when the JS thread re-enters it.
    fn with_js<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Ctx<'_>) -> R,
    {
        let depth = JS_ENTER_DEPTH.with(|slot| {
            let depth = slot.get();
            slot.set(depth + 1);
            depth
        });
        let _guard = JsEnterGuard;
        if depth == 0 {
            self.ctx.with(f)
        } else {
            // SAFETY: depth > 0 means this thread already holds the rquickjs
            // runtime lock inside `Context::with`. `from_raw` only dups the
            // live JSContext belonging to `self.ctx`.
            let ctx = unsafe { Ctx::from_raw(self.ctx.as_raw()) };
            f(ctx)
        }
    }

    pub(crate) fn run_enter(&self, group: usize, target: usize, mut regs: SavedRegs) -> SavedRegs {
        let listeners: Vec<_> = self
            .hooks
            .borrow()
            .groups
            .get(group)
            .map(|group| {
                group
                    .listeners
                    .iter()
                    .flatten()
                    .filter_map(|listener| listener.on_enter.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.with_js(|ctx| {
            for on_enter in listeners {
                let _ = api::invoke_enter(&ctx, on_enter, target, &mut regs);
            }
        });
        regs
    }

    pub(crate) fn run_leave(&self, group: usize, target: usize, mut regs: SavedRegs) -> SavedRegs {
        let listeners: Vec<_> = self
            .hooks
            .borrow()
            .groups
            .get(group)
            .map(|group| {
                group
                    .listeners
                    .iter()
                    .rev()
                    .flatten()
                    .filter_map(|listener| listener.on_leave.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.with_js(|ctx| {
            for on_leave in listeners {
                let _ = api::invoke_leave(&ctx, on_leave, target, &mut regs);
            }
        });
        regs
    }

    pub(crate) fn run_callback(&self, id: usize, args: [u64; 8]) -> u64 {
        let entry = self.callbacks.borrow().entries.get(id).map(|entry| {
            (
                entry.function.clone(),
                entry.arg_types.clone(),
                entry.ret_void,
                entry.ret_signed,
                entry.ret_pointer,
            )
        });
        let Some((function, arg_types, ret_void, ret_signed, ret_pointer)) = entry else {
            return 0;
        };
        self.with_js(|ctx| {
            api::invoke_callback(
                &ctx,
                function,
                &arg_types,
                ret_void,
                ret_signed,
                ret_pointer,
                args,
            )
            .unwrap_or(0)
        })
    }

    pub(crate) fn run_java_impl(
        &self,
        id: usize,
        call: crate::worker::JavaImplArgs,
        hook: Option<std::rc::Rc<std::cell::RefCell<art::hook::JavaHook>>>,
    ) -> crate::worker::DispatchResult {
        let jni_mode = crate::java::hook_jni_mode(id);
        let entry = self
            .java_hooks
            .borrow()
            .entries
            .get(id)
            .and_then(|entry| entry.as_ref())
            .map(|entry| {
                (
                    entry.function.clone(),
                    entry.class.clone(),
                    entry.method.clone(),
                )
            });
        let Some((function, class, method)) = entry else {
            return crate::worker::DispatchResult::default();
        };
        let _guard = crate::worker::JavaImplGuard::enter();
        self.with_js(|ctx| {
            let Ok(function) = function.restore(&ctx) else {
                return crate::worker::DispatchResult::default();
            };
            match crate::java::invoke_impl(
                &ctx,
                function,
                class,
                &method,
                crate::java::HookCall {
                    args: call.args,
                    fargs: call.fargs,
                    params: call.params,
                    stack: call.stack,
                    globals: call.globals,
                    hook,
                    jni_mode,
                },
            ) {
                Ok((x0, d0)) => crate::worker::DispatchResult { x0, d0 },
                Err(error) => {
                    crate::java::set_java_error(error.to_string());
                    crate::worker::DispatchResult::default()
                }
            }
        })
    }

    pub(crate) fn run_rpc(&self, name: &str, args: &str) -> Result<String> {
        self.with_js(|ctx| api::invoke_rpc(&ctx, name, args))
            .map_err(|err| Error::Parse(format!("rpc: {err}")))
    }
}

fn js_error(error: rquickjs::Error) -> Error {
    Error::Parse(format!("quickjs: {error}"))
}

fn js_caught_error(error: rquickjs::CaughtError<'_>) -> Error {
    Error::Parse(format!("quickjs: {error}"))
}

impl ScriptRuntime {
    /// Drop every persistent JS value and restore native hooks without
    /// destroying the QuickJS runtime.
    pub(crate) fn shutdown(&self) {
        self.hooks.borrow_mut().groups.clear();
        self.callbacks.borrow_mut().entries.clear();
        self.java_hooks.borrow_mut().entries.clear();
    }
}

impl Drop for ScriptRuntime {
    fn drop(&mut self) {
        // Break persistent-function references before JS_FreeRuntime checks
        // that the GC object list is empty.
        self.shutdown();
        self.rt.run_gc();
    }
}

#[cfg(test)]
pub(crate) fn js_test_guard() -> std::sync::MutexGuard<'static, ()> {
    // QuickJS runtimes and gum replace/hook tables are process-global enough
    // that parallel `ScriptRuntime`/`JsWorker` tests SIGSEGV on this host.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_arithmetic() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("20 + 22").unwrap(), "42");
    }

    #[test]
    fn console_log_does_not_throw() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        rt.eval("console.log('hello', 1 + 1)").unwrap();
    }

    #[test]
    fn reports_syntax_errors() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert!(rt.eval("function (").is_err());
    }
}

#[cfg(test)]
mod api_tests {
    use super::ScriptRuntime;

    #[test]
    fn pointer_arithmetic_and_strings() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(
            rt.eval("ptr('0x1000').add(4).toString()").unwrap(),
            "0x1004"
        );
        assert_eq!(
            rt.eval("ptr('0x1000').sub(0x10).toString()").unwrap(),
            "0xff0"
        );
        assert_eq!(rt.eval("ptr(0).isNull()").unwrap(), "true");
    }

    #[test]
    fn process_and_modules() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert!(!rt.eval("Process.arch").unwrap().is_empty());
        let count: usize = rt
            .eval("Process.enumerateModules().length")
            .unwrap()
            .parse()
            .unwrap();
        assert!(count > 0);
        assert_eq!(
            rt.eval("Module.findBaseAddress(Process.enumerateModules()[0].name) !== null")
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn memory_roundtrip() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(
            rt.eval("const p = Memory.alloc(16); p.writeU32(0x12345678); p.readU32()")
                .unwrap(),
            "305419896"
        );
        assert_eq!(
            rt.eval("const s = Memory.allocUtf8String('hello'); s.readCString()")
                .unwrap(),
            "hello"
        );
        assert_eq!(
            rt.eval("Memory.allocUtf8String('hi').readCString()")
                .unwrap(),
            "hi"
        );
    }

    #[test]
    fn export_lookup_and_array_buffer() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(
            rt.eval("Module.getExportByName(null, 'malloc') !== null")
                .unwrap(),
            "true"
        );
        assert_eq!(
            rt.eval(
                "const b = Memory.readByteArray(Memory.allocUtf8String('abc'), 3); b.byteLength"
            )
            .unwrap(),
            "3"
        );
    }

    #[test]
    fn thread_sleep() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("Thread.sleep(0)").unwrap(), "undefined");
    }

    #[test]
    fn gumjs_surface_matches_frida_names() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const buf = Memory.alloc(32);
                    const needle = ptr('0x1122334455667788');
                    buf.writePointer(needle);
                    const prot = Memory.queryProtection(buf);
                    if (prot[0] !== 'r') return 'prot:' + prot;
                    const u16 = Memory.allocUtf16String('ab');
                    if (u16.readU16() !== 0x61) return 'utf16';
                    const hits = Memory.findPointers(buf, 16, [needle]);
                    if (hits[0].compare(buf) !== 0) return 'findPointers';
                    let scanned = 0;
                    let matchAddr = null;
                    Memory.scan(buf, 16, '88 77 66 55', {
                        onMatch: function (address, size) {
                            scanned++;
                            matchAddr = address;
                            if (size !== 4) return 'stop';
                        },
                        onComplete: function () {}
                    });
                    if (scanned !== 1 || matchAddr.compare(buf) !== 0) return 'scan';
                    const sync = Memory.scanSync(buf, 16, '88 77 66 55');
                    if (sync[0].address.compare(buf) !== 0) return 'scanSync';
                    if (!Process.mainModule || typeof Process.mainModule.name !== 'string') return 'mainModule';
                    if (!Process.findModuleByAddress(Process.mainModule.base)) return 'findModuleByAddress';
                    if (!Process.enumerateThreads().some(t => t.id === Process.getCurrentThreadId())) return 'threads';
                    const range = Process.findRangeByAddress(Process.mainModule.base);
                    if (!range || range.base.compare(Process.mainModule.base) > 0) return 'findRange';
                    if (!Process.enumerateRanges('r--').length) return 'ranges';
                    Process.setExceptionHandler(null);
                    const main = Process.findModuleByName(Process.mainModule.name);
                    if (!main.enumerateSections().some(s => s.name === '.text' || s.name.length > 0)) return 'sections';
                    if (!main.enumerateRanges().length) return 'mod-ranges';
                    try { main.ensureInitialized(); } catch (e) {}
                    const map = new ModuleMap();
                    if (!map.has(Process.mainModule.base)) return 'modulemap';
                    if (map.findName(Process.mainModule.base) !== Process.mainModule.name) return 'map-name';
                    const frames = Thread.backtrace();
                    if (!(frames instanceof Array)) return 'backtrace';
                    if (buf.toJSON() !== buf.toString()) return 'toJSON';
                    if (buf.toMatchPattern().split(' ').length !== 8) return 'pattern';
                    const stripped = buf.strip();
                    if ((stripped.compare(buf) !== 0) && stripped.isNull()) return 'strip';
                    if (buf.blend(1).compare(buf) === 0) return 'blend';
                    const vol = buf.readVolatile(8);
                    buf.writeVolatile(vol);
                    if (buf.readPointer().compare(needle) !== 0) return 'volatile';
                    setTimeout(function () { globalThis.__timerHit = 1; }, 0);
                    const id = setInterval(function () { globalThis.__intervalHit = 1; }, 0);
                    clearInterval(id);
                    if (typeof SystemFunction !== 'function') return 'system';
                    const malloc = DebugSymbol.fromName('malloc');
                    if (malloc.address.isNull()) return 'debug-name';
                    const fromAddr = DebugSymbol.fromAddress(malloc.address);
                    if (fromAddr.address.compare(malloc.address) !== 0) return 'debug-addr';
                    const named = DebugSymbol.findFunctionsNamed('malloc');
                    if (!named.length) return 'debug-named';
                    const writer = new Arm64Writer(Memory.alloc(16));
                    writer.putBrkImm(1);
                    writer.flush();
                    writer.dispose();
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
        assert_eq!(rt.eval("String(__timerHit)").unwrap(), "1");
    }

    #[test]
    fn file_read_write_roundtrip() {
        let _js = crate::js_test_guard();
        let dir = std::env::temp_dir();
        let path = dir.join("ca-gumjs-file.txt");
        let path_js = path.to_string_lossy().replace('\\', "\\\\");
        let rt = ScriptRuntime::new().unwrap();
        let script = format!(
            r#"
            (function () {{
                File.writeAllText("{path_js}", "hello\nworld\n");
                if (File.readAllText("{path_js}") !== "hello\nworld\n") return 'readAllText';
                const bytes = File.readAllBytes("{path_js}");
                if (bytes.byteLength !== 12) return 'readAllBytes:' + bytes.byteLength;
                File.writeAllBytes("{path_js}", bytes);
                const f = new File("{path_js}", "r");
                const line = f.readLine();
                if (line.indexOf("hello") < 0) return 'readLine:' + line;
                const pos = f.tell();
                f.seek(0, File.SEEK_SET);
                if (f.tell() !== 0) return 'seek';
                f.close();
                const w = new File("{path_js}", "w");
                w.write("z");
                w.flush();
                w.close();
                if (File.readAllText("{path_js}") !== "z") return 'write';
                const _ = pos;
                return 'ok';
            }})()
            "#
        );
        let result = rt.eval(&script).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(result, "ok");
    }

    unsafe extern "C" fn native_ret_f64() -> f64 {
        2.5
    }

    unsafe extern "C" fn native_mul2_f64(x: f64) -> f64 {
        x * 2.0
    }

    unsafe extern "C" fn native_ilogb(x: f64) -> i32 {
        if (x - 8.0).abs() < 1e-9 {
            3
        } else {
            -1
        }
    }

    unsafe extern "C" fn native_ret_f32() -> f32 {
        0.5
    }

    unsafe extern "C" fn native_half_f32(x: f32) -> f32 {
        x * 0.5
    }

    #[test]
    fn native_function_float_and_double_returns() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let f64_addr = native_ret_f64 as *const () as usize;
        let f32_addr = native_ret_f32 as *const () as usize;
        let half_addr = native_half_f32 as *const () as usize;
        let mul_addr = native_mul2_f64 as *const () as usize;
        let ilogb_addr = native_ilogb as *const () as usize;
        let script = format!(
            r#"
            (function () {{
                const d = new NativeFunction(ptr("0x{f64_addr:x}"), "double", []);
                if (d() !== 2.5) return "double:" + d();
                const f = new NativeFunction(ptr("0x{f32_addr:x}"), "float", []);
                if (f() !== 0.5) return "float:" + f();
                const half = new NativeFunction(ptr("0x{half_addr:x}"), "float", ["float"]);
                if (half(0.5) !== 0.25) return "half:" + half(0.5);
                const sys = new SystemFunction(ptr("0x{f64_addr:x}"), "double", []);
                if (sys() !== 2.5) return "system";
                const mul = new NativeFunction(ptr("0x{mul_addr:x}"), "double", ["double"]);
                if (mul(1.5) !== 3) return "mul:" + mul(1.5);
                const il = new NativeFunction(ptr("0x{ilogb_addr:x}"), "int", ["double"]);
                if (il(8) !== 3) return "ilogb:" + il(8);
                return "ok";
            }})()
            "#
        );
        assert_eq!(rt.eval(&script).unwrap(), "ok");
    }

    #[test]
    fn trace_function_exists_and_errors_without_qbdi() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("typeof Trace").unwrap(), "object");
        assert_eq!(rt.eval("typeof Trace.function").unwrap(), "function");
        assert_eq!(rt.eval("typeof Trace.exclude").unwrap(), "function");
        assert_eq!(rt.eval("typeof Trace.takeEvents").unwrap(), "undefined");
        rt.eval("Trace.exclude('libc.so')").unwrap();
        let err = rt
            .eval("Trace.function(ptr('0x1000'), { events: ['inst', 'mem'], exclude: ['libfoo.so'] })")
            .unwrap_err();
        assert!(err.to_string().contains("QBDI is not linked"), "{err}");
        let err2 = rt.eval("Trace.function(ptr('0x2000'))").unwrap_err();
        assert!(err2.to_string().contains("QBDI is not linked"), "{err2}");
        let empty = rt
            .eval("Trace.function(ptr('0x1000'), { file: '' })")
            .unwrap_err();
        assert!(empty.to_string().contains("empty file path"), "{empty}");
    }

    #[test]
    fn recv_waits_for_host_post() {
        let _js = crate::js_test_guard();
        let (events, _rx) = std::sync::mpsc::channel();
        let worker = super::JsWorker::spawn(events).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(30));
                worker.post(r#"{"type":"send","payload":7}"#);
            });
            let got = worker
                .eval(
                    r#"
                    var got = null;
                    recv(function (message) { got = message.payload; }).wait();
                    String(got);
                    "#,
                )
                .unwrap();
            assert_eq!(got, "7");
        });
    }

    #[test]
    fn java_runtime_is_installed() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("typeof Java").unwrap(), "object");
        assert_eq!(rt.eval("typeof Java.use").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.perform").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.performNow").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.choose").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.cast").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.retain").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.array").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.vm !== 'undefined'").unwrap(), "true");
        assert_eq!(rt.eval("typeof Java.ClassFactory").unwrap(), "function");
        assert_eq!(rt.eval("typeof Java.available").unwrap(), "boolean");
        // Host has no ART. ACC_PUBLIC is a java-bridge Runtime field; its
        // absence shows eval installed the Rust Java object.
        assert_eq!(rt.eval("Java.available").unwrap(), "false");
        assert_eq!(rt.eval("typeof Java.ACC_PUBLIC").unwrap(), "undefined");
        assert_eq!(
            rt.eval("typeof __analyser_java_set_impl").unwrap(),
            "function"
        );
        assert_eq!(
            rt.eval("typeof __analyser_make_java_method").unwrap(),
            "function"
        );
        let use_err = rt.eval("Java.use('java.lang.String')").unwrap_err();
        assert!(
            use_err.to_string().contains("Java API not available"),
            "use: {use_err}"
        );
        let perform_err = rt
            .eval("Java.perform(function () { return 1; })")
            .unwrap_err();
        assert!(
            perform_err.to_string().contains("Java API not available"),
            "perform: {perform_err}"
        );
    }

    #[test]
    fn pointer_and_memory_primitives() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const p = Memory.alloc(16);
                    p.writePointer(ptr('0x1122334455667788'));
                    if (p.readPointer().toString() !== '0x1122334455667788') return 'pointer';
                    const src = Memory.allocUtf8String('abcd');
                    const d = Memory.dup(src, 5);
                    Memory.copy(d, src, 5);
                    if (d.readCString() !== 'abcd') return 'dup';
                    if (Memory.protect(Memory.alloc(32), 32, 'rw-') !== true) return 'protect';
                    const codeBuf = Memory.alloc(8);
                    Memory.patchCode(codeBuf, 4, code => { code.writeU32(0xd503201f); });
                    if ((codeBuf.readU32() >>> 0).toString(16) !== 'd503201f') return 'patch:' + (codeBuf.readU32() >>> 0).toString(16);
                    if (!(Process.getModuleByName(Process.enumerateModules()[0].name).name.length > 0)) return 'module';
                    const nop = Memory.alloc(4);
                    nop.writeU32(0xd503201f);
                    if (Instruction.parse(nop).mnemonic !== 'nop') return 'nop';
                    const ldr = Memory.alloc(4);
                    ldr.writeU32(0xf9400c20);
                    const insn = Instruction.parse(ldr);
                    if (insn.mnemonic + ':' + insn.operands[1].value.base + ':' + insn.operands[1].value.disp !== 'ldr:x1:24') {
                        return 'ldr:' + insn.mnemonic;
                    }
                    const mallocPtr = Module.getExportByName(null, 'malloc');
                    if (!mallocPtr) return 'malloc-export';
                    const malloc = new NativeFunction(mallocPtr, 'pointer', ['int']);
                    const free = new NativeFunction(Module.getExportByName(null, 'free'), 'void', ['pointer']);
                    const block = malloc(32);
                    block.writeU32(0x41);
                    const v = block.readU32();
                    free(block);
                    if (v !== 65) return 'native:' + v;
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn interceptor_replace_rewrites_arm64_bytes() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        // Interceptor lives on the worker; drive it through eval after hooks install.
        // ScriptRuntime::new() does not install Interceptor; the worker does.
        let (events, _rx) = std::sync::mpsc::channel();
        let worker = super::JsWorker::spawn(events).unwrap();
        let result = worker
            .eval(
                r#"
                (function () {
                    const page = Memory.alloc(Process.pageSize);
                    Memory.protect(page, Process.pageSize, 'rwx');
                    page.writeU32(0xd503201f);
                    page.add(4).writeU32(0xd503201f);
                    page.add(8).writeU32(0xd503201f);
                    page.add(12).writeU32(0xd503201f);
                    const replacement = Memory.alloc(16);
                    try {
                        Interceptor.replace(page, replacement);
                    } catch (e) {
                        return 'replace-error:' + e;
                    }
                    const after = page.readU32();
                    Interceptor.revert(page);
                    const restored = page.readU32();
                    return 'after=' + (after >>> 0).toString(16) + ',restored=' + (restored >>> 0).toString(16);
                })()
                "#,
            )
            .unwrap();
        // The redirect is a direct B when the trampoline page is in range and
        // an ldr/ret literal jump otherwise; both are valid. What matters is
        // that the prologue changed and revert restored it.
        assert!(result.contains("restored=d503201f"), "{result}");
        assert!(!result.contains("after=d503201f"), "{result}");
        assert!(!result.contains("replace-error:"), "{result}");
        let _ = rt;
    }

    #[test]
    fn arm64_writer_exposes_exception_clear_api() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const proto = Arm64Writer.prototype;
                    const needed = [
                        'putPushAllXRegisters', 'putPopAllXRegisters',
                        'putCallAddressWithArguments', 'putBLabel', 'putBCondLabel',
                        'putCbzRegLabel', 'putCbnzRegLabel', 'putTbzRegImmLabel',
                        'putTbnzRegImmLabel', 'putPushRegReg', 'putPopRegReg',
                        'putMovRegReg', 'putBlImm', 'putLdrRegRegOffset',
                        'putRet', 'flush', 'dispose', 'putBCondLabelWide'
                    ];
                    for (const name of needed) {
                        if (typeof proto[name] !== 'function') return 'missing:' + name;
                    }
                    if (typeof Arm64Relocator !== 'function') return 'reloc-ctor';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn int64_roundtrip_and_pointer_write() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    if (!(int64(1) instanceof Int64)) return 'ctor';
                    if (int64('0x10').add(1).toString() !== '17') return 'add';
                    if (int64(-1).toString() !== '-1') return 'neg';
                    const p = Memory.alloc(8);
                    p.writeS64(int64(-1));
                    const got = p.readS64();
                    if (!(got instanceof Int64)) return 'read-type';
                    if (got.toString() !== '-1') return 'read:' + got;
                    if (uint64('0xff').and(1).toString() !== '1') return 'uint';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn native_function_is_instance() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const malloc = new NativeFunction(
                        Module.getExportByName(null, 'malloc'),
                        'pointer',
                        ['int']
                    );
                    if (!(malloc instanceof NativeFunction)) return 'instanceof';
                    if (typeof malloc.isNull !== 'function') return 'isnull';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn pointer_bitwise_compare_and_integer_conversions() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    if (!NULL.isNull() || !NULL.equals(ptr(0))) return 'null';
                    if (ptr('0xff').and(1).toString() !== '0x1') return 'and';
                    if (ptr('0x10').or(1).toString() !== '0x11') return 'or';
                    if (ptr('0xff').xor(0xf0).toString() !== '0xf') return 'xor';
                    if (ptr('0x1').shl(4).toString() !== '0x10') return 'shl';
                    if (ptr('0x10').shr(4).toString() !== '0x1') return 'shr';
                    if (ptr(0).not().toString() !== '0xffffffffffffffff') return 'not';
                    if (ptr(1).compare(ptr(2)) !== -1) return 'cmp-lt';
                    if (ptr(2).compare(2) !== 0) return 'cmp-eq';
                    if (ptr(3).compare(1) !== 1) return 'cmp-gt';
                    if (!ptr(4).equals(4)) return 'equals';
                    if (ptr('0xffffffff').toInt32() !== -1) return 'toInt32';
                    if (ptr(7).toUInt32() !== 7) return 'toUInt32';
                    if (ptr(7).valueOf() !== 7) return 'valueOf';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn pointer_signed_float_utf_and_byte_widths() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const p = Memory.alloc(32);
                    p.writeS8(-1);
                    if (p.readS8() !== -1) return 's8';
                    p.writeS16(-2);
                    if (p.readS16() !== -2) return 's16';
                    p.writeS32(-3);
                    if (p.readS32() !== -3) return 's32';
                    p.writeInt(-4);
                    if (p.readInt() !== -4) return 'int';
                    p.writeU8(0xff);
                    if (p.readU8() !== 255) return 'u8';
                    p.writeU16(0xabcd);
                    if (p.readU16() !== 0xabcd) return 'u16';
                    p.writeU64(7);
                    if (p.readU64() !== 7) return 'u64:' + p.readU64();
                    p.writeFloat(1.5);
                    if (Math.abs(p.readFloat() - 1.5) > 1e-6) return 'float';
                    p.writeDouble(2.25);
                    if (p.readDouble() !== 2.25) return 'double';
                    p.writeUtf8String('hi');
                    if (p.readUtf8String() !== 'hi') return 'utf8';
                    if (p.readUtf8String(2) !== 'hi') return 'utf8-n';
                    const u16 = Memory.allocUtf16String('ab');
                    if (u16.readUtf16String() !== 'ab') return 'utf16';
                    const src = Memory.alloc(4);
                    src.writeU32(0x01020304);
                    p.writeByteArray(src.readByteArray(4));
                    const bytes = p.readByteArray(4);
                    if (bytes.byteLength !== 4) return 'bytes';
                    Memory.writeUtf8String(p, 'z');
                    if (Memory.readU8(p) !== 122) return 'mem-u8';
                    if (Memory.readU64(p).toString() === '') return 'mem-u64';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn int64_uint64_full_arithmetic() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    if (int64(8).sub(3).toString() !== '5') return 'i-sub';
                    if (int64(1).or(2).toString() !== '3') return 'i-or';
                    if (int64(7).xor(1).toString() !== '6') return 'i-xor';
                    if (int64(1).shl(3).toString() !== '8') return 'i-shl';
                    if (int64(8).shr(2).toString() !== '2') return 'i-shr';
                    if (int64(1).compare(2) !== -1) return 'i-cmp';
                    if (!int64(5).equals(5)) return 'i-eq';
                    if (int64(9).toNumber() !== 9) return 'i-num';
                    if (int64(-1).toInt32() !== -1) return 'i-i32';
                    if (int64(255).toString(16) !== 'ff') return 'i-hex';
                    if (uint64(8).sub(3).toString() !== '5') return 'u-sub';
                    if (uint64(1).or(2).toString() !== '3') return 'u-or';
                    if (uint64(7).xor(1).toString() !== '6') return 'u-xor';
                    if (uint64(1).shl(3).toString() !== '8') return 'u-shl';
                    if (uint64(8).shr(2).toString() !== '2') return 'u-shr';
                    if (uint64(3).compare(1) !== 1) return 'u-cmp';
                    if (!uint64(5).equals(5)) return 'u-eq';
                    if (uint64(9).toNumber() !== 9) return 'u-num';
                    if (uint64(255).toString(16) !== 'ff') return 'u-hex';
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn script_cmodule_matchpattern_print_and_immediates() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    var n = 0;
                    Script.nextTick(function () { n = 1; });
                    if (n !== 1) return 'nextTick';
                    const id = Script.bindWeak({}, function () {});
                    Script.unbindWeak(id);
                    const cm = CModule('int add(int a, int b) { return a + b; }');
                    if (typeof cm !== 'object' || !cm.add) return 'cmodule';
                    const add = new NativeFunction(cm.add, 'int', ['int', 'int']);
                    if (add(20, 22) !== 42) return 'add=' + add(20, 22);
                    cm.dispose();
                    if (String(new MatchPattern('ff ?? aa')) !== 'ff ?? aa') return 'pattern';
                    print('host-test-print');
                    globalThis.__imm = 0;
                    const imm = setImmediate(function () { __imm = 1; });
                    const skipped = setImmediate(function () { __imm = 2; });
                    clearImmediate(skipped);
                    const to = setTimeout(function () { __imm = 3; }, 0);
                    clearTimeout(to);
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
        assert_eq!(rt.eval("String(__imm)").unwrap(), "1");
    }

    #[test]
    fn process_identity_dirs_and_module_exports() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let pid = std::process::id();
        let script = format!(
            r#"
            (function () {{
                if (Process.id !== {pid}) return 'id';
                if (typeof Process.platform !== 'string' || !Process.platform.length) return 'platform';
                if (!(Process.pageSize >= 4096)) return 'page';
                if (Process.pointerSize !== 8) return 'ptrsize';
                if (typeof Process.myUid() !== 'number') return 'uid';
                if (typeof Process.getCurrentDir() !== 'string') return 'cwd';
                if (typeof Process.getHomeDir() !== 'string') return 'home';
                if (typeof Process.getTmpDir() !== 'string') return 'tmp';
                if (typeof Process.isDebuggerAttached() !== 'boolean') return 'dbg';
                const obs = Process.attachThreadObserver({{}});
                if (typeof obs.detach !== 'function') return 'observer';
                obs.detach();
                const malloc = Module.findExportByName(null, 'malloc');
                if (!malloc || malloc.isNull()) return 'findExport';
                const globalMalloc = Module.getGlobalExportByName('malloc');
                if (globalMalloc.compare(malloc) !== 0) return 'global';
                return 'ok';
            }})()
            "#
        );
        assert_eq!(rt.eval(&script).unwrap(), "ok");
    }

    #[test]
    fn debug_symbol_matching_and_get_function() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        let result = rt
            .eval(
                r#"
                (function () {
                    const named = DebugSymbol.getFunctionByName('malloc');
                    if (named.isNull()) return 'getFunction';
                    const matching = DebugSymbol.findFunctionsMatching('malloc');
                    if (!matching.length) return 'matching';
                    if (matching[0].compare(named) !== 0 && matching.every(p => p.compare(named) !== 0)) {
                        return 'match-addr';
                    }
                    return 'ok';
                })()
                "#,
            )
            .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn java_remaining_methods_error_without_art() {
        let _js = crate::js_test_guard();
        let rt = ScriptRuntime::new().unwrap();
        for expr in [
            "Java.choose('java.lang.String', { onMatch: function () {}, onComplete: function () {} })",
            "Java.cast(ptr(0), 'java.lang.String')",
            "Java.retain(ptr(0))",
            "Java.array('int', [1, 2])",
            "Java.enumerateLoadedClassesSync()",
            "Java.enumerateLoadedClasses({ onMatch: function () {}, onComplete: function () {} })",
            "Java.classFactory.use('java.lang.Object')",
        ] {
            let err = rt.eval(expr).unwrap_err();
            assert!(
                err.to_string().contains("Java API not available"),
                "{expr}: {err}"
            );
        }
    }
}
