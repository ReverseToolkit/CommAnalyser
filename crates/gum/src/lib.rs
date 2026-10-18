//! Gum-like primitives exposed to the JavaScript layer.
//!
//! Only the self-process parts are implemented so far.  Remote-process
//! access belongs to `inject`.

pub mod hook;
pub mod interceptor;
pub mod memory;
pub mod native;

pub use arch_arm64 as arch;
pub use runtime::{module, process, thread};
pub use runtime::{Error, Result};

pub use hook::{HookCallback, InlineHook, SavedRegs};
pub use interceptor::{HookListener, Interceptor, InvocationContext};
pub use memory::{alloc, free, patch_code, protect, read, write};
