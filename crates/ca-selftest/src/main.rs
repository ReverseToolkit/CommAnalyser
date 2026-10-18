//! On-device smoke test: hook libc `getpid`, call it, detach, verify.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use ca_gum::hook::{InlineHook, SavedRegs};

static CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn on_getpid(_regs: *mut SavedRegs, _data: *mut c_void) {
    CALLS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    let target = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"getpid".as_ptr()) } as usize;
    if target == 0 {
        eprintln!("selftest: dlsym(getpid) failed");
        std::process::exit(2);
    }

    let hook = unsafe { InlineHook::attach(target, on_getpid, ptr::null_mut()) };
    let mut hook = match hook {
        Ok(hook) => hook,
        Err(err) => {
            eprintln!("selftest: attach failed: {err}");
            std::process::exit(3);
        }
    };

    let before = CALLS.load(Ordering::SeqCst);
    for _ in 0..5 {
        // SAFETY: plain libc call.
        unsafe {
            libc::getpid();
        }
    }
    let after = CALLS.load(Ordering::SeqCst);
    let detached = hook.detach();

    // Calls after detach must not hit our callback.
    let baseline = CALLS.load(Ordering::SeqCst);
    for _ in 0..5 {
        unsafe {
            libc::getpid();
        }
    }
    let final_count = CALLS.load(Ordering::SeqCst);

    println!(
        "selftest: pid={} target={:#x} trampoline={:#x} before={} after={} final={} detach={:?}",
        std::process::id(),
        target,
        hook.trampoline(),
        before,
        after,
        final_count,
        detached
    );

    let ok = after >= before + 5 && final_count == baseline;
    if !ok {
        eprintln!("selftest: FAILED (expected 5 hits and no hits after detach)");
        std::process::exit(1);
    }
    println!("selftest: OK");
}
