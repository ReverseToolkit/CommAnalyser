//! QuickJS runtime for CommAnalyser.
//!
//! M0 only proves the embedding path (runtime/context/eval/console).  The
//! Frida API objects are added incrementally in later milestones.

use ca_core::{Error, Result};
use rquickjs::{Context, Function, Runtime};

pub struct ScriptRuntime {
    rt: Runtime,
    ctx: Context,
}

impl ScriptRuntime {
    pub fn new() -> Result<Self> {
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
                "#,
            )
            .map_err(js_error)?;
            Ok(())
        })?;

        Ok(Self { rt, ctx })
    }

    /// Evaluate a script/expression and return `String(value)`.
    pub fn eval(&self, source: &str) -> Result<String> {
        self.ctx.with(|ctx| {
            let stringify: Function = ctx.globals().get("__ca_string").map_err(js_error)?;
            let value: rquickjs::Value = ctx.eval(source).map_err(js_error)?;
            let text: String = stringify.call((value,)).map_err(js_error)?;
            Ok(text)
        })
    }

    pub fn runtime(&self) -> &Runtime {
        &self.rt
    }
}

fn js_error(error: rquickjs::Error) -> Error {
    Error::Parse(format!("quickjs: {error}"))
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
