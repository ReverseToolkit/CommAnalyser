use runtime::{Error, Result};

/// AArch64 CPU context handed to hook listeners.  Layout intentionally mirrors
/// the fields scripts see in Frida's `this.context`.
#[derive(Clone, Debug)]
pub struct InvocationContext {
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
    pub fp: u64,
    pub x: [u64; 29],
    pub q: [u8; 128],
}

/// Listener installed by `Interceptor.attach`.
pub trait HookListener: Send + Sync {
    fn on_enter(&self, _ctx: &mut InvocationContext, _args: &mut [u64]) {}
    fn on_leave(&self, _ctx: &mut InvocationContext, _retval: &mut u64) {}
}

/// Inline-hook registry.  The actual ARM64 trampoline engine lands in M2;
/// this type defines the contract the JS layer will use.
#[derive(Default)]
pub struct Interceptor {
    _private: (),
}

impl Interceptor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach(&self, _target: usize, _listener: Box<dyn HookListener>) -> Result<()> {
        Err(Error::Unsupported("interceptor: M2"))
    }

    pub fn replace(&self, _target: usize, _replacement: usize) -> Result<()> {
        Err(Error::Unsupported("interceptor replace: M2"))
    }

    pub fn revert(&self, _target: usize) -> Result<()> {
        Err(Error::Unsupported("interceptor revert: M2"))
    }

    pub fn flush(&self) {}
}

impl Default for InvocationContext {
    fn default() -> Self {
        Self {
            pc: 0,
            sp: 0,
            lr: 0,
            fp: 0,
            x: [0; 29],
            q: [0; 128],
        }
    }
}
