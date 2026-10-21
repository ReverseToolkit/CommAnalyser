//! Writing to memory the agent does not own.
//!
//! Java metadata and framework code live in mappings with protections decided
//! by the runtime, not by us. The only correct way to patch them is: read the
//! real protection from /proc/self/maps, add write, write, then put the
//! original protection back -- and treat a failed mprotect as an error.

use std::ffi::{c_int, c_void};

use crate::error::{Error, Result};
use crate::maps::{self, Perms};

/// Fail early when an assumed object layout does not match the runtime.
pub fn ensure_mapped(address: usize, len: usize) -> Result<()> {
    let mapping = maps::self_mapping_containing(address)?.ok_or_else(|| {
        Error::Parse(format!("{address:#x} is not mapped"))
    })?;
    if !mapping.perms.read {
        return Err(Error::Parse(format!("{address:#x} is not readable")));
    }
    if address.saturating_add(len) > mapping.range.end {
        return Err(Error::Parse(format!(
            "{len} bytes at {address:#x} cross a mapping boundary"
        )));
    }
    Ok(())
}

/// Run `write` against a range temporarily granted write access, then restore
/// the protection reported by /proc/self/maps.
///
/// A failed mprotect is returned as an error instead of writing to a page we
/// do not actually own; the restore failure is reported too, because it leaves
/// the mapping writable.
pub fn with_writable(address: usize, len: usize, write: impl FnOnce()) -> Result<()> {
    let mapping = maps::self_mapping_containing(address)?
        .ok_or_else(|| Error::Parse(format!("{address:#x} is not mapped")))?;
    let end_address = address
        .checked_add(len)
        .ok_or_else(|| Error::Parse("address overflow".into()))?;
    if end_address > mapping.range.end {
        return Err(Error::Parse(format!(
            "write of {len} bytes at {address:#x} crosses a mapping boundary"
        )));
    }
    let page_size = crate::process::page_size();
    let start = address & !(page_size - 1);
    let end = (end_address + page_size - 1) & !(page_size - 1);
    let original = prot_of(mapping.perms);
    let added_write = original & libc::PROT_WRITE == 0;
    if added_write
        && unsafe {
            libc::mprotect(
                start as *mut c_void,
                end - start,
                original | libc::PROT_WRITE,
            )
        } != 0
    {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    write();
    if mapping.perms.exec {
        crate::patch::flush_icache(address, len);
    }
    if added_write && unsafe { libc::mprotect(start as *mut c_void, end - start, original) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Convert /proc permissions into mprotect flags.
pub fn prot_of(perms: Perms) -> c_int {
    let mut prot = 0;
    if perms.read {
        prot |= libc::PROT_READ;
    }
    if perms.write {
        prot |= libc::PROT_WRITE;
    }
    if perms.exec {
        prot |= libc::PROT_EXEC;
    }
    prot
}

/// Make freshly written instructions visible to the core.
pub fn flush_icache(address: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        let start = address & !63;
        let end = (address + len + 63) & !63;
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (address, len);
    }
}
