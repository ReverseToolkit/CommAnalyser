//! In-process reads and writes. The agent already lives in the target.

use std::ffi::{CStr, CString};

use runtime::{Error, Result};

pub fn read_u64(addr: u64) -> Result<u64> {
    if addr == 0 {
        return Ok(0);
    }
    // SAFETY: `addr` is a mapped IL2CPP pointer checked by the caller. The
    // value may be unaligned inside a native struct.
    Ok(unsafe { std::ptr::read_unaligned(addr as *const u64) })
}

pub fn read_u32(addr: u64) -> Result<u32> {
    if addr == 0 {
        return Ok(0);
    }
    Ok(unsafe { std::ptr::read_unaligned(addr as *const u32) })
}

pub fn read_u8(addr: u64) -> Result<u8> {
    if addr == 0 {
        return Ok(0);
    }
    Ok(unsafe { std::ptr::read(addr as *const u8) })
}

pub fn write_u64(addr: u64, value: u64) -> Result<()> {
    if addr == 0 {
        return Err(Error::Parse("il2cpp write: null address".into()));
    }
    unsafe { std::ptr::write_unaligned(addr as *mut u64, value) };
    Ok(())
}

pub fn cstr(addr: u64) -> Result<String> {
    if addr == 0 {
        return Ok(String::new());
    }
    // SAFETY: IL2CPP name pointers are NUL-terminated C strings in the image.
    let text = unsafe { CStr::from_ptr(addr as *const libc::c_char) };
    Ok(text.to_string_lossy().into_owned())
}

/// Allocate a temporary C string. The caller must keep it alive across the call.
pub fn cstring(text: &str) -> Result<CString> {
    CString::new(text).map_err(|_| Error::Parse(format!("il2cpp string contains NUL: {text}")))
}

pub fn is_executable(addr: u64) -> bool {
    let Ok(maps) = runtime::maps::read_self_maps() else {
        return false;
    };
    maps.iter()
        .any(|mapping| mapping.range.contains(addr as usize) && mapping.perms.exec)
}
