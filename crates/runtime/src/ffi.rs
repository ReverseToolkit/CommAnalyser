//! Panic containment for native entry points.
//!
//! The agent is a cdylib living inside a third-party process. A panic that
//! reaches an ABI boundary either aborts the process (Rust >= 1.81 aborts when
//! unwinding out of extern "C") or, with panic = "unwind", silently unwinds
//! through C frames. Both kill the instrumented app.
//!
//! Every entry point reachable from foreign code (Gum trampolines, QBDI
//! callbacks, the injected agent_main) therefore runs its body through
//! [guard]. The panic is contained, logged, and the entry point returns its
//! zero value; the guest keeps running.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `body`, containing any panic that would otherwise cross an ABI
/// boundary. Returns `None` when the body panicked.
pub fn guard<R>(what: &'static str, body: impl FnOnce() -> R) -> Option<R> {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => Some(value),
        Err(payload) => {
            log_panic(what, payload.as_ref());
            None
        }
    }
}

fn log_panic(what: &str, payload: &(dyn std::any::Any + Send)) {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>");
    // stderr is often detached in an injected process; the agent control
    // channel is the companion source of truth.
    eprintln!("[comm-analyser] panic contained at {what}: {message}");
}
