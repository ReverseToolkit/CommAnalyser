//! In-process agent payload.
//!
//! The injector calls `agent_main(config)` after `dlopen()`.  M0 only
//! validates the ABI and logs; the QuickJS runtime and control channel are
//! wired in M1.

#[cfg(feature = "gum-static")]
mod control;
#[cfg(feature = "gum-static")]
mod selftest;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Entrypoint called by the injector.
///
/// `config` is a NUL-terminated UTF-8 string (JSON in later milestones).  It
/// may be null.  Returns 0 on success.
///
/// # Safety
/// `config` must be null or point to a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn agent_main(config: *const c_char) -> c_int {
    // The injector calls this through a C ABI; a panic must not unwind into
    // the loader stub or abort the freshly attached process.
    runtime::ffi::guard("agent_main", || unsafe { agent_main_inner(config) }).unwrap_or(-1)
}

unsafe fn agent_main_inner(config: *const c_char) -> c_int {
    let text = if config.is_null() {
        String::new()
    } else {
        // SAFETY: caller guarantees NUL-termination.
        unsafe { CStr::from_ptr(config) }
            .to_str()
            .unwrap_or("")
            .to_owned()
    };
    eprintln!("[agent] loaded (config={text:?})");
    #[cfg(feature = "gum-static")]
    if !text.is_empty() {
        let _ = gum::Gum::init();
        control::spawn(text);
    }
    0
}

/// Same as [`agent_main`], but blocks until the hello line is on the socket.
///
/// Zygisk calls this from `postAppSpecialize`. The ptrace injector must keep
/// calling [`agent_main`], which returns before the control thread runs.
///
/// # Safety
/// `config` must be null or point to a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn agent_main_wait(config: *const c_char) -> c_int {
    runtime::ffi::guard("agent_main_wait", || unsafe { agent_main_wait_inner(config) })
        .unwrap_or(-1)
}

unsafe fn agent_main_wait_inner(config: *const c_char) -> c_int {
    let text = if config.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(config) }
            .to_str()
            .unwrap_or("")
            .to_owned()
    };
    #[cfg(feature = "gum-static")]
    {
        if !text.is_empty() {
            let _ = gum::Gum::init();
            if !control::spawn_ready(text) {
                return -1;
            }
        }
    }
    #[cfg(not(feature = "gum-static"))]
    let _ = text;
    0
}

/// ABI/version probe used by the injector before calling the entrypoint.
#[no_mangle]
pub extern "C" fn agent_abi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_version() {
        assert_eq!(super::agent_abi_version(), 1);
    }

    #[test]
    fn null_config_is_ok() {
        let rc = unsafe { super::agent_main(std::ptr::null()) };
        assert_eq!(rc, 0);
    }
}
