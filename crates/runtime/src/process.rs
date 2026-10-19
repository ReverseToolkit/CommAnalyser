use std::sync::OnceLock;

/// Current process id.
#[inline]
pub fn id() -> u32 {
    std::process::id()
}

/// System page size in bytes.
pub fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: sysconf is safe to call and _SC_PAGESIZE is always supported.
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if value > 0 {
            value as usize
        } else {
            4096
        }
    })
}

/// Pointer width in bytes.
#[inline]
pub const fn pointer_size() -> usize {
    std::mem::size_of::<usize>()
}

/// Frida-compatible architecture name.
pub const fn arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "x86")]
    {
        "ia32"
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    {
        "unknown"
    }
}

/// Frida-compatible platform name.
pub const fn platform() -> &'static str {
    if cfg!(any(target_os = "android", target_os = "linux")) {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_identity() {
        assert!(id() > 0);
        assert!(page_size() >= 4096);
        assert_eq!(pointer_size(), std::mem::size_of::<usize>());
        assert!(!arch().is_empty());
        assert!(!platform().is_empty());
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch(), "x64");
        #[cfg(target_os = "linux")]
        assert_eq!(platform(), "linux");
    }
}
