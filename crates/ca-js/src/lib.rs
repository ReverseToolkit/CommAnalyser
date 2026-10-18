//! QuickJS runtime for CommAnalyser.
//!
//! M0 only proves the embedding path (runtime/context/eval/console).  The
//! Frida API objects are added incrementally in later milestones.

mod api;
mod elf;
mod worker;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::Sender;

use ca_core::{Error, Result};
use ca_gum::SavedRegs;
use rquickjs::{CatchResultExt, Context, Function, Runtime};

pub use worker::JsWorker;

use worker::{CallbackTable, HookTable, Job};

pub struct ScriptRuntime {
    // Drop order matters: JS values in the tables and the context must be
    // released before the runtime.  `rt` is therefore last.
    ctx: Context,
    hooks: Rc<RefCell<HookTable>>,
    callbacks: Rc<RefCell<CallbackTable>>,
    rt: Runtime,
}

impl ScriptRuntime {
    pub fn new() -> Result<Self> {
        Self::new_inner(
            None,
            Rc::new(RefCell::new(HookTable::default())),
            Rc::new(RefCell::new(CallbackTable::default())),
            None,
        )
    }

    pub(crate) fn new_with_hooks(
        tx: Sender<Job>,
        hooks: Rc<RefCell<HookTable>>,
        callbacks: Rc<RefCell<CallbackTable>>,
        event_tx: Sender<String>,
    ) -> Result<Self> {
        Self::new_inner(Some(tx), hooks, callbacks, Some(event_tx))
    }

    fn new_inner(
        tx: Option<Sender<Job>>,
        hooks: Rc<RefCell<HookTable>>,
        callbacks: Rc<RefCell<CallbackTable>>,
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
                globalThis.__ca_string = v => String(v);
                globalThis.rpc = { exports: {} };
                "#,
            )
            .map_err(js_error)?;
            match (tx, event_tx) {
                (Some(tx), Some(event_tx)) => {
                    api::install_with_hooks(&ctx, tx, hooks.clone(), callbacks.clone(), event_tx)
                }
                _ => api::install(&ctx),
            }
            .map_err(js_error)?;
            Ok(())
        })?;

        Ok(Self {
            ctx,
            hooks,
            callbacks,
            rt,
        })
    }

    /// Evaluate a script/expression and return `String(value)`.
    pub fn eval(&self, source: &str) -> Result<String> {
        self.ctx.with(|ctx| {
            let stringify: Function = ctx.globals().get("__ca_string").map_err(js_error)?;
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
                    .filter_map(|listener| listener.on_enter.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.ctx.with(|ctx| {
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
                    .filter_map(|listener| listener.on_leave.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.ctx.with(|ctx| {
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
        self.ctx.with(|ctx| {
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

    pub(crate) fn run_rpc(&self, name: &str, args: &str) -> Result<String> {
        self.ctx
            .with(|ctx| api::invoke_rpc(&ctx, name, args))
            .map_err(|err| Error::Parse(format!("rpc: {err}")))
    }
}

fn js_error(error: rquickjs::Error) -> Error {
    Error::Parse(format!("quickjs: {error}"))
}

fn js_caught_error(error: rquickjs::CaughtError<'_>) -> Error {
    Error::Parse(format!("quickjs: {error}"))
}

impl Drop for ScriptRuntime {
    fn drop(&mut self) {
        // Break persistent-function references before JS_FreeRuntime checks
        // that the GC object list is empty.
        self.hooks.borrow_mut().groups.clear();
        self.callbacks.borrow_mut().entries.clear();
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
        assert_eq!(rt.eval("Thread.sleep(1)").unwrap(), "undefined");
    }
}
