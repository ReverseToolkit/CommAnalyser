//! Minimal AArch64 inline hook.
//!
//! The trampoline saves the caller-saved argument registers, calls a Rust
//! callback, restores the registers, executes the relocated prologue with the
//! original SP, and jumps back after it.  This is intentionally smaller than
//! Frida's Interceptor (no onLeave/return hijack yet) but it is enough to
//! validate the decoder/relocator/patch path on a real device.

use std::ffi::c_void;
use std::ptr;

use ca_arch_arm64::relocator::relocate_one;
use ca_arch_arm64::writer::CodeWriter;
use ca_core::{Error, Result};

use crate::memory::{flush_icache, protect};

const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const PAGE: usize = 0x1000;
const SAVE_SIZE: u32 = 160;
const NEAR_RADIUS: usize = 0x700_0000;

/// Registers visible to the hook callback (x0-x18 + LR).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedRegs {
    pub x: [u64; 19],
    pub lr: u64,
}

impl SavedRegs {
    #[inline]
    pub fn arg(&self, n: usize) -> u64 {
        self.x.get(n).copied().unwrap_or(0)
    }

    #[inline]
    pub fn set_arg(&mut self, n: usize, value: u64) {
        if let Some(slot) = self.x.get_mut(n) {
            *slot = value;
        }
    }
}

pub type HookCallback = unsafe extern "C" fn(*mut SavedRegs, *mut c_void);

#[repr(C)]
struct HookEntry {
    callback: HookCallback,
    user_data: *mut c_void,
}

unsafe extern "C" fn dispatch(entry: *mut HookEntry, regs: *mut SavedRegs) {
    if entry.is_null() || regs.is_null() {
        return;
    }
    // SAFETY: the trampoline embeds a pointer to a HookEntry that outlives it.
    let entry = unsafe { &*entry };
    // SAFETY: caller-provided callback and data; contract is documented on attach().
    unsafe { (entry.callback)(regs, entry.user_data) };
}

pub struct InlineHook {
    patch_at: usize,
    original: u32,
    trampoline: usize,
    entry: *mut HookEntry,
    active: bool,
}

impl InlineHook {
    /// Install a hook at `target`.  `callback` runs with the saved registers
    /// and may modify x0-x18/LR before the relocated prologue executes.
    ///
    /// # Safety
    /// `user_data` must remain valid for as long as the hook is active.
    pub unsafe fn attach(
        target: usize,
        callback: HookCallback,
        user_data: *mut c_void,
    ) -> Result<Self> {
        if target == 0 {
            return Err(Error::Parse("hook: null target".into()));
        }

        let entry = Box::into_raw(Box::new(HookEntry {
            callback,
            user_data,
        }));

        // Skip BTI/PAC prologue instructions: leaving them in place means an
        // indirect call still lands on a valid BTI pad and PAC is computed
        // with the original SP before our patch.
        let mut patch_at = target;
        let mut relocated = None;
        for _ in 0..4 {
            // SAFETY: target points into executable memory.
            let word = unsafe { ptr::read_unaligned(patch_at as *const u32) };
            if is_bti_or_pac(word) {
                patch_at += 4;
                continue;
            }
            relocated = Some(relocate_one(word, patch_at).map_err(|err| {
                Error::Parse(format!(
                    "hook: cannot relocate {word:#010x} at {patch_at:#x}: {err}"
                ))
            })?);
            break;
        }
        let relocated = relocated.ok_or_else(|| Error::Parse("hook: prologue too short".into()))?;

        let trampoline = alloc_near(patch_at)?;
        let mut w = CodeWriter::with_capacity(512);
        emit_trampoline(&mut w, entry, &relocated.bytes, patch_at + 4);

        // Write the trampoline.  alloc_near returns RWX where possible; if it
        // had to fall back to RW we flip it to RX after writing.
        // SAFETY: trampoline is a private page of at least PAGE bytes.
        unsafe {
            ptr::copy_nonoverlapping(w.bytes().as_ptr(), trampoline as *mut u8, w.len());
        }
        flush_icache(trampoline, w.len());
        if protect(trampoline, PAGE, libc::PROT_READ | libc::PROT_EXEC).is_err() {
            return Err(Error::Unsupported(
                "hook: cannot make trampoline executable",
            ));
        }

        let offset = trampoline as i64 - patch_at as i64;
        if offset & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&offset) {
            return Err(Error::Unsupported("hook: trampoline out of branch range"));
        }
        let patch = 0x1400_0000 | (((offset >> 2) as u32) & 0x03FF_FFFF);
        // SAFETY: patch_at is the prologue address we just decoded.
        let original = unsafe { ptr::read_unaligned(patch_at as *const u32) };
        patch_code(patch_at, patch)?;

        Ok(Self {
            patch_at,
            original,
            trampoline,
            entry,
            active: true,
        })
    }

    pub fn target(&self) -> usize {
        self.patch_at
    }

    pub fn trampoline(&self) -> usize {
        self.trampoline
    }

    /// Restore the original prologue word.
    pub fn detach(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        patch_code(self.patch_at, self.original)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        let _ = self.detach();
        // The trampoline may still be executing on another thread; leaking the
        // page and entry is safer than freeing them here.
        let _ = self.entry;
    }
}

fn emit_trampoline(w: &mut CodeWriter, entry: *mut HookEntry, prologue: &[u8], resume: usize) {
    w.bti_c();
    w.sub_sp(SAVE_SIZE);
    for i in 0..9u8 {
        w.stp(i * 2, i * 2 + 1, 31, (i as i64) * 16);
    }
    w.str_imm(18, 31, 144);
    w.str_imm(30, 31, 152);

    w.abs_addr(0, entry as usize as u64);
    w.put(0x9100_03E1); // mov x1, sp
    w.abs_bl(dispatch as *const () as usize);

    for i in 0..9u8 {
        w.ldp(i * 2, i * 2 + 1, 31, (i as i64) * 16);
    }
    w.ldr_imm(18, 31, 144);
    w.ldr_imm(30, 31, 152);
    w.add_sp(SAVE_SIZE);

    w.put_bytes(prologue);
    w.ldr_literal_x(16, 8);
    w.ret(16);
    w.put_u64(resume as u64);
}

fn is_bti_or_pac(word: u32) -> bool {
    matches!(
        word,
        0xD503_241F // BTI
            | 0xD503_245F // BTI c
            | 0xD503_249F // BTI j
            | 0xD503_24DF // BTI jc
            | 0xD503_233F // PACIASP
            | 0xD503_237F // PACIBSP
            | 0xD503_23BF // AUTIASP
            | 0xD503_23FF // AUTIBSP
    )
}

/// Allocate one executable page within +/-128 MiB of `near`.
fn alloc_near(near: usize) -> Result<usize> {
    let base = near & !(PAGE - 1);
    for delta in (0..NEAR_RADIUS).step_by(0x1_0000) {
        for candidate in [base.checked_add(delta), base.checked_sub(delta)] {
            let Some(candidate) = candidate else {
                continue;
            };
            if candidate == 0 {
                continue;
            }
            if let Some(page) = try_map(candidate) {
                return Ok(page);
            }
        }
    }
    // Last resort: let the kernel choose, then verify the distance.
    // SAFETY: standard anonymous mmap.
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
        // Retry without PROT_EXEC (some Android domains deny anonymous execmem).
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let addr = page as usize;
        if addr.abs_diff(near) > NEAR_RADIUS {
            unsafe { libc::munmap(page, PAGE) };
            return Err(Error::Unsupported("hook: no executable page near target"));
        }
        return Ok(addr);
    }
    let addr = page as usize;
    if addr.abs_diff(near) > NEAR_RADIUS {
        unsafe { libc::munmap(page, PAGE) };
        return Err(Error::Unsupported("hook: no executable page near target"));
    }
    Ok(addr)
}

fn try_map(addr: usize) -> Option<usize> {
    // SAFETY: MAP_FIXED_NOREPLACE either maps exactly at addr or fails.
    let p = unsafe {
        libc::mmap(
            addr as *mut c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        // Retry without exec; callers flip the page to RX after writing.
        let p = unsafe {
            libc::mmap(
                addr as *mut c_void,
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED || p as usize != addr {
            if p != libc::MAP_FAILED {
                unsafe { libc::munmap(p, PAGE) };
            }
            return None;
        }
        return Some(addr);
    }
    if p as usize == addr {
        Some(addr)
    } else {
        unsafe { libc::munmap(p, PAGE) };
        None
    }
}

fn patch_code(addr: usize, word: u32) -> Result<()> {
    let page = addr & !(PAGE - 1);
    let original = original_prot(addr);
    // Prefer RWX; fall back to RW, then restore the original protection.
    let mut writable = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    if protect(page, PAGE, writable).is_err() {
        writable = libc::PROT_READ | libc::PROT_WRITE;
        protect(page, PAGE, writable)?;
    }
    // SAFETY: the page is writable and addr is 4-byte aligned.
    unsafe { ptr::write_unaligned(addr as *mut u32, word) };
    flush_icache(addr, 4);
    let _ = protect(page, PAGE, original);
    Ok(())
}

fn original_prot(addr: usize) -> i32 {
    match ca_core::maps::self_mapping_containing(addr) {
        Ok(Some(mapping)) => {
            let mut prot = 0;
            if mapping.perms.read {
                prot |= libc::PROT_READ;
            }
            if mapping.perms.write {
                prot |= libc::PROT_WRITE;
            }
            if mapping.perms.exec {
                prot |= libc::PROT_EXEC;
            }
            prot
        }
        _ => libc::PROT_READ | libc::PROT_EXEC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_regs_layout() {
        assert_eq!(std::mem::size_of::<SavedRegs>(), 160);
        assert_eq!(std::mem::align_of::<SavedRegs>(), 8);
    }

    #[test]
    fn skips_bti_and_pac() {
        assert!(is_bti_or_pac(0xD503_245F));
        assert!(is_bti_or_pac(0xD503_233F));
        assert!(!is_bti_or_pac(0xD503_201F));
    }
}
