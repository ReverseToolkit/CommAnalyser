//! On-device smoke test: hook libc `getpid`, call it, detach, verify.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use gum::hook::{InlineHook, SavedRegs};

static CALLS: AtomicUsize = AtomicUsize::new(0);
static LEAVES: AtomicUsize = AtomicUsize::new(0);
const REPLACED_PID: u64 = 0x1234;

unsafe extern "C" fn on_getpid(_regs: *mut SavedRegs, _data: *mut c_void) {
    CALLS.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_getpid_leave(regs: *mut SavedRegs, _data: *mut c_void) {
    LEAVES.fetch_add(1, Ordering::SeqCst);
    // SAFETY: regs is the live register snapshot from the return stub.
    unsafe { (*regs).x[0] = REPLACED_PID };
}

fn main() {
    let target = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"getpid".as_ptr()) } as usize;
    if target == 0 {
        eprintln!("selftest: dlsym(getpid) failed");
        std::process::exit(2);
    }

    let hook =
        unsafe { InlineHook::attach_ex(target, on_getpid, Some(on_getpid_leave), ptr::null_mut()) };
    let mut hook = match hook {
        Ok(hook) => hook,
        Err(err) => {
            eprintln!("selftest: attach failed: {err}");
            std::process::exit(3);
        }
    };

    let before = CALLS.load(Ordering::SeqCst);
    let mut replaced_ok = true;
    for _ in 0..5 {
        // SAFETY: plain libc call; onLeave must replace the return value.
        let value = unsafe { libc::getpid() } as u64;
        replaced_ok &= value == REPLACED_PID;
    }
    let after = CALLS.load(Ordering::SeqCst);
    let leaves = LEAVES.load(Ordering::SeqCst);
    let detached = hook.detach();

    // Calls after detach must not hit our callback and must return the real pid.
    let baseline = CALLS.load(Ordering::SeqCst);
    let real_pid = unsafe { libc::getpid() } as u64;
    let final_count = CALLS.load(Ordering::SeqCst);

    println!(
        "selftest: pid={} target={:#x} trampoline={:#x} before={} after={} leaves={} final={} replaced_ok={} real_pid={} detach={:?}",
        std::process::id(),
        target,
        hook.trampoline(),
        before,
        after,
        leaves,
        final_count,
        replaced_ok,
        real_pid,
        detached
    );

    let ok = after >= before + 5
        && leaves >= 5
        && replaced_ok
        && final_count == baseline
        && real_pid == std::process::id() as u64;
    if !ok {
        eprintln!("selftest: FAILED (expected 5 hits and no hits after detach)");
        std::process::exit(1);
    }
    println!("selftest: OK");
}
