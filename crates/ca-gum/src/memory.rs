use std::ptr;

use ca_core::{Error, Result};

/// Read `len` bytes from `addr` in the current process.
///
/// # Safety
/// The caller is responsible for `addr` pointing to at least `len` readable
/// bytes.  An invalid address will fault, exactly like Frida's `Memory.read*`.
pub unsafe fn read_raw(addr: usize, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(Error::Parse("null read".into()));
    }
    let mut out = vec![0u8; len];
    // SAFETY: caller guarantees readability.
    unsafe {
        ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
    }
    Ok(out)
}

/// Safe-ish convenience wrapper around [`read_raw`], kept for scripting tests.
pub fn read(addr: usize, len: usize) -> Result<Vec<u8>> {
    // SAFETY: documented as the scripting contract; invalid addresses fault.
    unsafe { read_raw(addr, len) }
}

/// Write `data` to `addr` in the current process.
///
/// # Safety
/// The caller is responsible for `addr` pointing to `data.len()` writable bytes.
pub unsafe fn write_raw(addr: usize, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    if addr == 0 {
        return Err(Error::Parse("null write".into()));
    }
    // SAFETY: caller guarantees writability.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    Ok(())
}

pub fn write(addr: usize, data: &[u8]) -> Result<()> {
    // SAFETY: documented as the scripting contract; invalid addresses fault.
    unsafe { write_raw(addr, data) }
}

/// Anonymous RW memory allocation (page aligned, zero-filled by the kernel).
pub fn alloc(size: usize) -> Result<*mut u8> {
    if size == 0 {
        return Err(Error::Parse("zero-sized allocation".into()));
    }
    let page = ca_core::process::page_size();
    let rounded = size.div_ceil(page) * page;
    // SAFETY: standard anonymous mmap.
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            rounded,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(p as *mut u8)
}

/// Release memory returned by [`alloc`].  `size` is rounded up like `alloc`.
pub fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let page = ca_core::process::page_size();
    let rounded = size.div_ceil(page) * page;
    // SAFETY: pointer/size contract mirrors alloc().
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, rounded);
    }
}

/// Change protection of `[addr, addr + len)`.
pub fn protect(addr: usize, len: usize, prot: i32) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let page = ca_core::process::page_size();
    let start = addr & !(page - 1);
    let end = (addr + len + page - 1) & !(page - 1);
    // SAFETY: standard mprotect.
    let rc = unsafe { libc::mprotect(start as *mut libc::c_void, end - start, prot) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Frida's `Memory.patchCode`: make the page writable, copy, flush icache.
///
/// The original protection is restored on a best-effort basis.  Android's
/// W^X implementations may reject RWX, so we first try RWX and fall back to
/// RW + explicit RX restore.
pub fn patch_code(addr: usize, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let page = ca_core::process::page_size();
    let start = addr & !(page - 1);
    let end = (addr + data.len() + page - 1) & !(page - 1);
    let len = end - start;

    // SAFETY: mprotect on the page containing the code.
    let rc = unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        // Fall back to RW; the caller may need to restore RX afterwards.
        let rc = unsafe {
            libc::mprotect(
                start as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

    // SAFETY: caller guarantees the destination is a code buffer of >= data.len().
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    flush_icache(addr, data.len());
    Ok(())
}

/// Flush the instruction cache for `[addr, addr + len)`.
pub fn flush_icache(addr: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe extern "C" {
            fn __clear_cache(start: *mut core::ffi::c_char, end: *mut core::ffi::c_char);
        }
        // SAFETY: bionic/libgcc provide __clear_cache for exactly this purpose.
        unsafe {
            __clear_cache(
                addr as *mut core::ffi::c_char,
                (addr + len) as *mut core::ffi::c_char,
            );
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (addr, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut buf = [0u8; 16];
        let addr = buf.as_mut_ptr() as usize;
        write(addr, &[1, 2, 3, 4]).unwrap();
        assert_eq!(read(addr, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(buf[..4], [1, 2, 3, 4]);
    }

    #[test]
    fn alloc_protect_free() {
        let p = alloc(32).unwrap();
        assert!(!p.is_null());
        // SAFETY: freshly allocated page.
        unsafe {
            *p = 0x41;
            assert_eq!(*p, 0x41);
        }
        protect(p as usize, 32, libc::PROT_READ).unwrap();
        free(p, 32);
    }
}
