//! Frida-shaped Interceptor surface backed by the ARM64 inline hook and
//! replace trampolines.

use runtime::Result;

use crate::hook::{HookCallback, InlineHook};
use crate::replace;

/// AArch64 CPU context handed to hook listeners.  Layout mirrors Gum's
/// `GumArm64CpuContext` (`x0`–`x28`, `fp`, `lr`, `sp`, `pc`).
#[derive(Clone, Debug)]
pub struct InvocationContext {
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
    pub fp: u64,
    pub x: [u64; 29],
    pub q: [u8; 128],
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

/// Listener installed by `Interceptor.attach`.
pub trait HookListener: Send + Sync {
    fn on_enter(&self, _ctx: &mut InvocationContext, _args: &mut [u64]) {}
    fn on_leave(&self, _ctx: &mut InvocationContext, _retval: &mut u64) {}
}

/// Inline-hook / replace registry used by the JS `Interceptor` object.
#[derive(Default)]
pub struct Interceptor {
    _private: (),
}

impl Interceptor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install an ARM64 inline hook at `target`.
    ///
    /// # Safety
    /// `user_data` must remain valid while the hook is active.
    pub unsafe fn attach(
        target: usize,
        on_enter: HookCallback,
        on_leave: Option<HookCallback>,
        user_data: *mut std::ffi::c_void,
    ) -> Result<InlineHook> {
        // SAFETY: forwarded to the ARM64 trampoline engine.
        unsafe { InlineHook::attach_ex(target, on_enter, on_leave, user_data) }
    }

    pub fn replace(target: usize, replacement: usize) -> Result<()> {
        replace::replace(target, replacement)
    }

    pub fn revert(target: usize) -> Result<()> {
        replace::revert(target)
    }

    pub fn original_trampoline(target: usize) -> Option<usize> {
        replace::original_trampoline(target)
    }

    pub fn flush() {}
}

#[cfg(test)]
mod tests {
    use super::Interceptor;
    use crate::replace::original_trampoline;

    #[test]
    fn replace_and_revert_go_through_interceptor() {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let target = page as usize;
        unsafe {
            for i in 0..16 {
                *(target as *mut u8).add(i) = [0x1F, 0x20, 0x03, 0xD5][i % 4];
            }
        }
        let before = unsafe { std::slice::from_raw_parts(target as *const u8, 16) }.to_vec();
        Interceptor::replace(target, 0xAABB_CCDD).unwrap();
        assert!(original_trampoline(target).is_some());
        let patched = unsafe { std::slice::from_raw_parts(target as *const u8, 16) };
        let word = u32::from_le_bytes(patched[..4].try_into().unwrap());
        let len = if word & 0xFC00_0000 == 0x1400_0000 {
            4
        } else {
            16
        };
        assert_eq!(&patched[len..], &before[len..]);
        Interceptor::flush();
        Interceptor::revert(target).unwrap();
        let restored = unsafe { std::slice::from_raw_parts(target as *const u8, 16) };
        assert_eq!(restored, &before);
        unsafe { libc::munmap(page, 0x1000) };
    }
}
