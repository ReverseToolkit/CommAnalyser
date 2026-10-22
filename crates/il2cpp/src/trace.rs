//! Method enter/leave trace. Same idea as upstream `Il2Cpp.trace`: hook the
//! method's native address and append one line per call. Instruction-level
//! QBDI traces stay on `Trace.function`.

use std::fs::OpenOptions;
use std::io::Write;

use gum::{Address, CallListener, Gum, Interceptor};

use crate::runtime::{Method, Runtime};
use runtime::Result;

/// Hook `method` and append enter/leave lines to `path`.
///
/// The attachment is kept for the life of the process. Gum's guard is not
/// `Send`, so it cannot sit in a mutex; leaking it is the same lifetime the
/// upstream tracer uses.
pub fn trace_method(rt: &mut Runtime, method: Method, path: String) -> Result<()> {
    let address = method.virtual_address(rt)?;
    let name = method.signature(rt)?;
    let gum = Gum::init();
    let interceptor = Interceptor::obtain(&gum).map_err(|err| runtime::Error::Parse(err.to_string()))?;
    let enter_path = path.clone();
    let enter_name = name.clone();
    let leave_path = path;
    let leave_name = name;
    let listener = CallListener::builder()
        .on_enter(move |_ctx| {
            let _ = append(&enter_path, &format!("enter {enter_name}"));
        })
        .on_leave(move |_ctx| {
            let _ = append(&leave_path, &format!("leave {leave_name}"));
        })
        .build(&gum)
        .map_err(|err| runtime::Error::Parse(err.to_string()))?;
    let attachment = interceptor
        .attach(Address::new(address), listener)
        .map_err(|err| runtime::Error::Parse(err.to_string()))?;
    std::mem::forget(attachment);
    Ok(())
}

fn append(path: &str, line: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}
