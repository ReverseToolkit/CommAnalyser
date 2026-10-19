//! ARM64 `Interceptor.replace` / `revert`.
//!
//! The target is overwritten with an absolute jump.  Relocated original
//! instructions live on a trampoline so a replacement can still call through.

use std::collections::HashMap;
use std::ptr;
use std::sync::Mutex;

use arch_arm64::relocator::relocate_one;
use arch_arm64::writer::CodeWriter;
use runtime::{Error, Result};

use crate::memory::{self, flush_icache};

const PATCH_LEN: usize = 16;
const PAGE: usize = 0x1000;

struct Replacement {
    original: [u8; PATCH_LEN],
    trampoline: usize,
}

static REPLACED: Mutex<Option<HashMap<usize, Replacement>>> = Mutex::new(None);

fn registry() -> std::sync::MutexGuard<'static, Option<HashMap<usize, Replacement>>> {
    REPLACED.lock().unwrap_or_else(|err| err.into_inner())
}

/// Replace `target` with an ARM64 jump to `replacement`.
///
/// # Errors
/// Returns an error when the target cannot be made writable or the jump
/// cannot be encoded.
pub fn replace(target: usize, replacement: usize) -> Result<()> {
    if target == 0 || replacement == 0 {
        return Err(Error::Parse("replace: null address".into()));
    }

    let mut original = [0u8; PATCH_LEN];
    // SAFETY: target is a live function prologue.
    unsafe {
        ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), PATCH_LEN);
    }

    let trampoline = emit_trampoline(target, &original)?;
    let jump = abs_jump(replacement);
    memory::with_writable(target, PATCH_LEN, || {
        unsafe {
            ptr::copy_nonoverlapping(jump.as_ptr(), target as *mut u8, PATCH_LEN);
        }
        flush_icache(target, PATCH_LEN);
    })?;

    let mut slot = registry();
    let map = slot.get_or_insert_with(HashMap::new);
    map.insert(
        target,
        Replacement {
            original,
            trampoline,
        },
    );
    Ok(())
}

/// Restore the original bytes at `target`.
pub fn revert(target: usize) -> Result<()> {
    let mut slot = registry();
    let Some(map) = slot.as_mut() else {
        return Ok(());
    };
    let Some(entry) = map.remove(&target) else {
        return Ok(());
    };
    memory::with_writable(target, PATCH_LEN, || {
        unsafe {
            ptr::copy_nonoverlapping(entry.original.as_ptr(), target as *mut u8, PATCH_LEN);
        }
        flush_icache(target, PATCH_LEN);
    })?;
    Ok(())
}

/// Trampoline that runs the original instructions of a replaced function.
pub fn original_trampoline(target: usize) -> Option<usize> {
    registry()
        .as_ref()
        .and_then(|map| map.get(&target).map(|entry| entry.trampoline))
}

fn abs_jump(target: usize) -> [u8; PATCH_LEN] {
    let mut w = CodeWriter::with_capacity(PATCH_LEN);
    w.abs_b(target);
    let bytes = w.into_bytes();
    let mut out = [0u8; PATCH_LEN];
    out.copy_from_slice(&bytes[..PATCH_LEN]);
    out
}

fn emit_trampoline(target: usize, original: &[u8; PATCH_LEN]) -> Result<usize> {
    let page = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let mut w = CodeWriter::with_capacity(256);
    w.bti_jc();
    let mut consumed = 0usize;
    while consumed < PATCH_LEN {
        let word = u32::from_le_bytes(original[consumed..consumed + 4].try_into().unwrap());
        let relocated = relocate_one(word, target + consumed)
            .map_err(|err| Error::Parse(format!("replace relocate: {err}")))?;
        w.put_bytes(&relocated.bytes);
        consumed += relocated.consumed;
    }
    w.abs_b(target + PATCH_LEN);

    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), page as *mut u8, w.len());
    }
    flush_icache(page as usize, w.len());
    Ok(page as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_jump_is_arm64_ldr_br() {
        let bytes = abs_jump(0x1234);
        assert_eq!(&bytes[..4], &0x5800_0050u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0xD61F_0200u32.to_le_bytes());
        assert_eq!(&bytes[8..], &0x1234u64.to_le_bytes());
    }

    #[test]
    fn replace_rewrites_and_reverts_a_buffer() {
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
        let replacement = 0xAABB_CCDDusize;
        replace(target, replacement).unwrap();
        let patched = unsafe { std::slice::from_raw_parts(target as *const u8, 16) };
        assert_eq!(&patched[..8], &abs_jump(replacement)[..8]);
        assert!(original_trampoline(target).is_some());
        revert(target).unwrap();
        let restored = unsafe { std::slice::from_raw_parts(target as *const u8, 4) };
        assert_eq!(restored, &[0x1F, 0x20, 0x03, 0xD5]);
        unsafe { libc::munmap(page, 0x1000) };
    }
}
