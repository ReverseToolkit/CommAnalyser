//! In-process agent payload.
//!
//! The injector calls `ca_agent_main(config)` after `dlopen()`.  M0 only
//! validates the ABI and logs; the QuickJS runtime and control channel are
//! wired in M1.

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
pub unsafe extern "C" fn ca_agent_main(config: *const c_char) -> c_int {
    let text = if config.is_null() {
        ""
    } else {
        // SAFETY: caller guarantees NUL-termination.
        unsafe { CStr::from_ptr(config) }.to_str().unwrap_or("")
    };
    eprintln!("[ca-agent] loaded (config={text:?})");
    0
}

/// ABI/version probe used by the injector before calling the entrypoint.
#[no_mangle]
pub extern "C" fn ca_agent_abi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_version() {
        assert_eq!(super::ca_agent_abi_version(), 1);
    }

    #[test]
    fn null_config_is_ok() {
        let rc = unsafe { super::ca_agent_main(std::ptr::null()) };
        assert_eq!(rc, 0);
    }
}
