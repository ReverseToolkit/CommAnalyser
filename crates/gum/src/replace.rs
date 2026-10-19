//! ARM64 `Interceptor.replace` / `revert`.
//!
//! Frida allocates the trampoline near the target and patches one `B` when
//! that page is in range.  Otherwise the patch is the 16-byte absolute jump.
//! Relocated original instructions live on the trampoline so a replacement
//! can still call through.  The bytes saved for `revert` are the ones from
//! before the first `replace`.

use std::collections::HashMap;
use std::ptr;
use std::sync::Mutex;

use arch_arm64::relocator::relocate_one;
use arch_arm64::writer::CodeWriter;
use runtime::{Error, Result};

use crate::memory::{self, flush_icache};

const MAX_PATCH: usize = 16;
const PAGE: usize = 0x1000;
const NEAR_RADIUS: usize = 0x700_0000;

struct Replacement {
    /// Bytes at `patch_at` before the first `replace`.
    original: [u8; MAX_PATCH],
    /// Instruction actually overwritten. Leading BTI/PAC stays in place.
    patch_at: usize,
    /// Bytes currently overwritten.
    len: usize,
    mapping: usize,
    original_code: usize,
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

    let (original, patch_at, previous) = {
        let slot = registry();
        if let Some(existing) = slot.as_ref().and_then(|map| map.get(&target)) {
            (
                existing.original,
                existing.patch_at,
                Some((existing.mapping, existing.len)),
            )
        } else {
            let patch_at = skip_landing_pad(target)?;
            let mut original = [0u8; MAX_PATCH];
            // SAFETY: patch_at is inside the live prologue, at least 16 bytes.
            unsafe {
                ptr::copy_nonoverlapping(patch_at as *const u8, original.as_mut_ptr(), MAX_PATCH);
            }
            (original, patch_at, None)
        }
    };

    let page = memory::alloc_near(PAGE, patch_at, NEAR_RADIUS)? as usize;
    let redirect = redirect_bytes(patch_at, page, replacement);
    let original_code =
        match write_trampoline(page, patch_at, &original, redirect.len(), replacement) {
            Ok(addr) => addr,
            Err(err) => {
                memory::free(page as *mut u8, PAGE);
                return Err(err);
            }
        };

    let previous_len = previous.as_ref().map(|(_, len)| *len).unwrap_or(0);
    let write_len = redirect.len().max(previous_len);
    let mut image = [0u8; MAX_PATCH];
    image[..write_len].copy_from_slice(&original[..write_len]);
    image[..redirect.len()].copy_from_slice(&redirect);
    if let Err(err) = memory::with_writable(patch_at, write_len, || {
        // SAFETY: with_writable made `patch_at` writable for `write_len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(image.as_ptr(), patch_at as *mut u8, write_len);
        }
    }) {
        memory::free(page as *mut u8, PAGE);
        return Err(err);
    }

    if let Some((mapping, _)) = previous {
        memory::free(mapping as *mut u8, PAGE);
    }

    let mut slot = registry();
    let map = slot.get_or_insert_with(HashMap::new);
    map.insert(
        target,
        Replacement {
            original,
            patch_at,
            len: redirect.len(),
            mapping: page,
            original_code,
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
    memory::with_writable(entry.patch_at, entry.len, || {
        // SAFETY: with_writable made the patched bytes writable.
        unsafe {
            ptr::copy_nonoverlapping(
                entry.original.as_ptr(),
                entry.patch_at as *mut u8,
                entry.len,
            );
        }
    })?;
    memory::free(entry.mapping as *mut u8, PAGE);
    Ok(())
}

/// Trampoline that runs the original instructions of a replaced function.
pub fn original_trampoline(target: usize) -> Option<usize> {
    registry()
        .as_ref()
        .and_then(|map| map.get(&target).map(|entry| entry.original_code))
}

/// Patch bytes for `target`.  A nearby trampoline takes one `B`; otherwise
/// the 16-byte absolute jump straight to `replacement`.
fn redirect_bytes(target: usize, page: usize, replacement: usize) -> Vec<u8> {
    if let Some(word) = b_to(target, page) {
        word.to_le_bytes().to_vec()
    } else {
        abs_jump(replacement).to_vec()
    }
}

fn b_to(from: usize, to: usize) -> Option<u32> {
    let offset = (to as i64).wrapping_sub(from as i64);
    if offset & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&offset) {
        return None;
    }
    Some(0x1400_0000 | (((offset >> 2) as u32) & 0x03FF_FFFF))
}

fn abs_jump(target: usize) -> [u8; MAX_PATCH] {
    let mut w = CodeWriter::with_capacity(MAX_PATCH);
    w.abs_b_signed(target);
    let bytes = w.into_bytes();
    let mut out = [0u8; MAX_PATCH];
    out.copy_from_slice(&bytes[..MAX_PATCH]);
    out
}

/// First instruction that is not a BTI or PAC prologue op, at most four words.
fn skip_landing_pad(target: usize) -> Result<usize> {
    let mut at = target;
    for _ in 0..4 {
        let mut buf = [0u8; 4];
        // SAFETY: `at` is inside the prologue the caller asked to replace.
        unsafe {
            ptr::copy_nonoverlapping(at as *const u8, buf.as_mut_ptr(), 4);
        }
        let word = u32::from_le_bytes(buf);
        if !crate::hook::is_bti_or_pac(word) {
            return Ok(at);
        }
        at += 4;
    }
    Err(Error::Parse("replace: prologue is only BTI/PAC".into()))
}

/// Write the trampoline into an already-allocated page.
///
/// When `redirect_len` is 4 the page starts with an absolute jump to
/// `replacement` (the `B` at `target` lands there).  The relocated prologue
/// follows.  A 16-byte redirect jumps to `replacement` itself, so the page
/// holds only the original prologue.
fn write_trampoline(
    page: usize,
    target: usize,
    original: &[u8; MAX_PATCH],
    redirect_len: usize,
    replacement: usize,
) -> Result<usize> {
    let mut w = CodeWriter::with_capacity(256);
    if redirect_len == 4 {
        w.bti_jc();
        w.abs_b_signed(replacement);
    }
    let original_off = w.len();
    w.bti_jc();
    let mut consumed = 0usize;
    while consumed < redirect_len {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&original[consumed..consumed + 4]);
        let word = u32::from_le_bytes(buf);
        let relocated = relocate_one(word, target + consumed)
            .map_err(|err| Error::Parse(format!("replace relocate: {err}")))?;
        w.put_bytes(&relocated.bytes);
        consumed += relocated.consumed;
    }
    w.abs_b_signed(target + redirect_len);
    if w.len() > PAGE {
        return Err(Error::Unsupported("replace: trampoline exceeds a page"));
    }

    // SAFETY: `page` is a private mapping of at least PAGE bytes.
    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), page as *mut u8, w.len());
    }
    flush_icache(page, w.len());
    memory::protect(page, PAGE, libc::PROT_READ | libc::PROT_EXEC)?;
    Ok(page + original_off)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_leaves_bti_and_patches_the_next_instruction() {
        let page = map_exec();
        let target = page as usize;
        let mut original = [0u8; 32];
        original[..4].copy_from_slice(&0xD503_245Fu32.to_le_bytes());
        original[4..8].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        for (i, byte) in original.iter_mut().enumerate().skip(8) {
            *byte = 0xA0 + i as u8;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), target as *mut u8, original.len());
        }
        let first = map_near(target);
        let second = map_near(target);
        replace(target, first).unwrap();
        let mid = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(&mid[..4], &original[..4], "BTI c must stay the landing pad");
        let branch = u32::from_le_bytes(mid[4..8].try_into().unwrap());
        assert_eq!(branch & 0xFC00_0000, 0x1400_0000, "patch is one B");
        assert_eq!(&mid[8..], &original[8..]);
        replace(target, second).unwrap();
        let mid = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(&mid[..4], &original[..4]);
        assert_eq!(&mid[8..], &original[8..]);
        revert(target).unwrap();
        let restored = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(restored, &original);
        unsafe {
            libc::munmap(page, 0x1000);
            libc::munmap(first as *mut libc::c_void, 0x1000);
            libc::munmap(second as *mut libc::c_void, 0x1000);
        }
    }

    #[test]
    fn abs_jump_is_arm64_ldr_ret() {
        let bytes = abs_jump(0x1234);
        assert_eq!(&bytes[..4], &0x5800_0050u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0xD65F_0200u32.to_le_bytes());
        assert_eq!(&bytes[8..], &0x1234u64.to_le_bytes());
        assert!(!bytes.windows(4).any(|w| w == 0xD61F_0200u32.to_le_bytes()));
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
        let mut original = [0u8; 16];
        for i in 0..16 {
            original[i] = [0x1F, 0x20, 0x03, 0xD5][i % 4];
        }
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), target as *mut u8, original.len());
        }
        let replacement = 0xAABB_CCDDusize;
        replace(target, replacement).unwrap();
        let patched = unsafe { std::slice::from_raw_parts(target as *const u8, 16) };
        let len = redirect_len_at(target);
        assert!(len == 4 || len == 16, "redirect is a B or the 16-byte jump");
        assert_eq!(&patched[len..], &original[len..]);
        assert!(original_trampoline(target).is_some());
        revert(target).unwrap();
        let restored = unsafe { std::slice::from_raw_parts(target as *const u8, 16) };
        assert_eq!(restored, &original);
        unsafe { libc::munmap(page, 0x1000) };
    }

    #[test]
    fn near_redirect_is_one_branch_and_second_replace_keeps_original() {
        let page = map_exec();
        let target = page as usize;
        let mut original = [0u8; 32];
        for (i, byte) in original.iter_mut().enumerate() {
            *byte = 0xA0 + (i as u8);
        }
        // Keep the first instruction a NOP so relocate succeeds, then the pattern.
        original[..4].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), target as *mut u8, original.len());
        }
        let first = map_near(target);
        let second = map_near(target);
        replace(target, first).unwrap();
        let len = redirect_len_at(target);
        assert_eq!(len, 4, "nearby trampoline is one B");
        let mid = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(&mid[4..], &original[4..]);

        replace(target, second).unwrap();
        let len = redirect_len_at(target);
        assert_eq!(len, 4);
        let mid = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(&mid[4..], &original[4..]);

        revert(target).unwrap();
        let restored = unsafe { std::slice::from_raw_parts(target as *const u8, 32) };
        assert_eq!(restored, &original);
        unsafe {
            libc::munmap(page, 0x1000);
            libc::munmap(first as *mut libc::c_void, 0x1000);
            libc::munmap(second as *mut libc::c_void, 0x1000);
        }
    }

    #[test]
    fn far_redirect_is_sixteen_byte_abs_jump() {
        let bytes = redirect_bytes(0x1000, 0x8000_0000, 0x8000_0000);
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes, abs_jump(0x8000_0000));
    }

    #[test]
    fn failed_relocate_does_not_keep_a_mapping() {
        let page = map_exec();
        let target = page as usize;
        unsafe {
            std::ptr::write_unaligned(target as *mut u32, 0xD800_0000);
        }
        let before = exec_ranges_near(target);
        let err = replace(target, target.wrapping_add(0x1000)).unwrap_err();
        assert!(err.to_string().contains("replace relocate"), "{err}");
        let after = exec_ranges_near(target);
        let leaked: Vec<_> = after
            .iter()
            .copied()
            .filter(|range| !before.contains(range))
            .collect();
        assert!(
            leaked.is_empty(),
            "failed replace left an executable mapping {leaked:?}"
        );
        let word = unsafe { std::ptr::read_unaligned(target as *const u32) };
        assert_eq!(word, 0xD800_0000);
        unsafe { libc::munmap(page, 0x1000) };
    }

    fn redirect_len_at(target: usize) -> usize {
        let word = unsafe { std::ptr::read_unaligned(target as *const u32) };
        if word & 0xFC00_0000 == 0x1400_0000 {
            4
        } else {
            16
        }
    }

    fn map_exec() -> *mut libc::c_void {
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
        page
    }

    fn map_near(near: usize) -> usize {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x10_0000;
        for delta in (0x1000..0x2_0000).step_by(0x1000) {
            for cand in [near.wrapping_add(delta), near.wrapping_sub(delta)] {
                let p = unsafe {
                    libc::mmap(
                        cand as *mut libc::c_void,
                        0x1000,
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                        flags,
                        -1,
                        0,
                    )
                };
                if p as usize == cand {
                    return cand;
                }
                if p != libc::MAP_FAILED {
                    unsafe { libc::munmap(p, 0x1000) };
                }
            }
        }
        panic!("no executable page near {near:#x}");
    }

    fn exec_ranges_near(addr: usize) -> Vec<(usize, usize)> {
        let text = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut ranges = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(span) = parts.next() else { continue };
            let Some(perms) = parts.next() else { continue };
            if !perms.contains('x') {
                continue;
            }
            let Some((start, end)) = span.split_once('-') else {
                continue;
            };
            let Ok(start) = usize::from_str_radix(start, 16) else {
                continue;
            };
            let Ok(end) = usize::from_str_radix(end, 16) else {
                continue;
            };
            if start.abs_diff(addr) <= NEAR_RADIUS || end.abs_diff(addr) <= NEAR_RADIUS {
                ranges.push((start, end));
            }
        }
        ranges.sort();
        ranges
    }
}
