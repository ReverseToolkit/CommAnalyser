//! QuickJS runtime for CommAnalyser.
//!
//! M0 only proves the embedding path (runtime/context/eval/console).  The
//! Frida API objects are added incrementally in later milestones.

mod api;
mod artctl;
mod elf;
mod instruction;
mod java;
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
mod tests {
    use super::*;

    #[test]
    fn evaluates_arithmetic() {
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("20 + 22").unwrap(), "42");
    }

    #[test]
    fn console_log_does_not_throw() {
        let rt = ScriptRuntime::new().unwrap();
        rt.eval("console.log('hello', 1 + 1)").unwrap();
    }

    #[test]
    fn reports_syntax_errors() {
        let rt = ScriptRuntime::new().unwrap();
        assert!(rt.eval("function (").is_err());
    }
}

#[cfg(test)]
mod api_tests {
    use super::ScriptRuntime;

    #[test]
    fn pointer_arithmetic_and_strings() {
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
        let rt = ScriptRuntime::new().unwrap();
        assert_eq!(rt.eval("Thread.sleep(0)").unwrap(), "undefined");
    }

    #[test]
    fn java_runtime_is_installed() {
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
        assert!(
            result.contains("after=58000050") && result.contains("restored=d503201f"),
            "{result}"
        );
        let _ = rt;
    }

    #[test]
    fn arm64_writer_exposes_exception_clear_api() {
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
}
