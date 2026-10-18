//! Gum-like primitives exposed to the JavaScript layer.
//!
//! Only the self-process parts are implemented so far.  Remote-process
//! access belongs to `ca-inject`.

pub mod interceptor;
pub mod memory;
pub mod native;

pub use ca_arch_arm64 as arch;
pub use ca_core::{module, process, thread};
pub use ca_core::{Error, Result};

pub use interceptor::{HookListener, Interceptor, InvocationContext};
pub use memory::{alloc, free, patch_code, protect, read, write};
