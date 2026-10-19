//! Minimal AArch64 inline hook.
//!
//! The trampoline saves GPRs plus Q0–Q7 (AAPCS64 argument/return NEON),
//! calls a Rust `onEnter` callback, then either executes the relocated
//! prologue or jumps to the saved LR.  Mid-function resume uses `RET Xn`,
//! matching Frida `put_jmp_reg` when pointer authentication is not the way
//! back: `RET` is exempt from BTI and does not authenticate against SP.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

use arch_arm64::relocator::relocate_one;
use arch_arm64::writer::CodeWriter;
use runtime::{Error, Result};

use crate::memory::{flush_icache, protect};

const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const PAGE: usize = 0x1000;
/// GPR frame (272) plus Q0–Q7 (128). AAPCS64 float args/returns live in V0–V7.
const SAVE_SIZE: u32 = 400;
const NEAR_RADIUS: usize = 0x700_0000;
const OFF_LR: u32 = 240;
const OFF_SP: u32 = 248;
const OFF_NZCV: u32 = 256;
const OFF_PC: u32 = 264;
const OFF_Q: u32 = 272;

/// AArch64 GPRs plus the eight argument/return NEON registers (Q0–Q7).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedRegs {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub pc: u64,
    pub q: [u128; 8],
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

struct LeaveFrame {
    on_leave: HookCallback,
    user_data: *mut c_void,
    original_lr: u64,
    pc: u64,
}

thread_local! {
    static LEAVE_FRAMES: RefCell<Vec<LeaveFrame>> = const { RefCell::new(Vec::new()) };
}

#[repr(C)]
struct HookEntry {
    on_enter: HookCallback,
    on_leave: Option<HookCallback>,
    user_data: *mut c_void,
    return_stub: usize,
    pc: u64,
}

unsafe extern "C" fn dispatch(entry: *mut HookEntry, regs: *mut SavedRegs) {
    if entry.is_null() || regs.is_null() {
        return;
    }
    // SAFETY: the trampoline embeds a pointer to a HookEntry that outlives it.
    let entry = unsafe { &*entry };
    // The trampoline stored the relocated prologue in the PC slot (Frida's
    // `next_hop = on_invoke_trampoline`) before this call.
    let hop = unsafe { (*regs).pc };
    unsafe { (*regs).pc = entry.pc };
    let original_lr = unsafe { (*regs).lr };

    // SAFETY: caller-provided callback and data; contract is documented on attach().
    unsafe { (entry.on_enter)(regs, entry.user_data) };

    if let Some(on_leave) = entry.on_leave {
        if entry.return_stub != 0 {
            LEAVE_FRAMES.with(|frames| {
                frames.borrow_mut().push(LeaveFrame {
                    on_leave,
                    user_data: entry.user_data,
                    original_lr,
                    pc: unsafe { (*regs).pc },
                });
            });
            // The relocated prologue may save this LR; the function's RET will
            // therefore land in the shared return stub.
            unsafe { (*regs).lr = entry.return_stub as u64 };
        }
    }

    // Listener left `pc` at the hooked function: restore the prologue hop.
    if unsafe { (*regs).pc } == entry.pc {
        unsafe { (*regs).pc = hop };
    }
}

unsafe extern "C" fn leave_dispatch(regs: *mut SavedRegs) {
    if regs.is_null() {
        return;
    }
    let frame = LEAVE_FRAMES.with(|frames| frames.borrow_mut().pop());
    let Some(frame) = frame else {
        return;
    };
    // SAFETY: caller-provided on_leave callback and user_data.
    unsafe { (frame.on_leave)(regs, frame.user_data) };
    // SAFETY: regs is the live SavedRegs passed by the return stub.
    unsafe {
        (*regs).lr = frame.original_lr;
        (*regs).pc = frame.pc;
    }
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
    /// and may modify GPRs/Q0–Q7 before the relocated prologue executes.
    ///
    /// # Safety
    /// `user_data` must remain valid for as long as the hook is active.
    pub unsafe fn attach(
        target: usize,
        callback: HookCallback,
        user_data: *mut c_void,
    ) -> Result<Self> {
        // SAFETY: forwarded to attach_ex.
        unsafe { Self::attach_ex(target, callback, None, user_data) }
    }

    /// Like [`attach`], but after `onEnter` the trampoline restores registers
    /// and returns to the saved LR.  Used when the callback already ran the
    /// function (TAL `tal_enter`).
    ///
    /// # Safety
    /// Same contract as [`attach`].
    pub unsafe fn attach_and_return(
        target: usize,
        callback: HookCallback,
        user_data: *mut c_void,
    ) -> Result<Self> {
        // SAFETY: forwarded to attach_with.
        unsafe { Self::attach_with(target, callback, None, user_data, AfterEnter::Return) }
    }

    /// Install a hook with an optional `onLeave` callback.
    ///
    /// # Safety
    /// `user_data` must remain valid for as long as the hook is active.
    pub unsafe fn attach_ex(
        target: usize,
        on_enter: HookCallback,
        on_leave: Option<HookCallback>,
        user_data: *mut c_void,
    ) -> Result<Self> {
        // SAFETY: forwarded to attach_with.
        unsafe { Self::attach_with(target, on_enter, on_leave, user_data, AfterEnter::Continue) }
    }

    unsafe fn attach_with(
        target: usize,
        on_enter: HookCallback,
        on_leave: Option<HookCallback>,
        user_data: *mut c_void,
        after: AfterEnter,
    ) -> Result<Self> {
        if target == 0 {
            return Err(Error::Parse("hook: null target".into()));
        }

        let return_stub = if on_leave.is_some() {
            return_stub()?
        } else {
            0
        };
        let entry = Box::into_raw(Box::new(HookEntry {
            on_enter,
            on_leave,
            user_data,
            return_stub,
            pc: target as u64,
        }));
        // Drop frees the entry and any trampoline page if we return before publish.
        let mut attempt = Attempt { entry, page: 0 };

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
        attempt.page = trampoline;
        let mut w = CodeWriter::with_capacity(640);
        emit_trampoline(&mut w, entry, &relocated.bytes, patch_at + 4, after);

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

        let published = Self {
            patch_at,
            original,
            trampoline,
            entry,
            active: true,
        };
        attempt.entry = ptr::null_mut();
        attempt.page = 0;
        Ok(published)
    }

    pub fn target(&self) -> usize {
        self.patch_at
    }

    pub fn trampoline(&self) -> usize {
        self.trampoline
    }

    pub fn is_active(&self) -> bool {
        self.active
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

/// Page and metadata for an attach that has not been published yet.
struct Attempt {
    entry: *mut HookEntry,
    page: usize,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if self.page != 0 {
            // SAFETY: page is a mapping this attempt owns.
            unsafe { libc::munmap(self.page as *mut c_void, PAGE) };
        }
        if !self.entry.is_null() {
            // SAFETY: entry came from Box::into_raw and is not published.
            unsafe { drop(Box::from_raw(self.entry)) };
        }
    }
}

#[derive(Clone, Copy)]
enum AfterEnter {
    Continue,
    Return,
}

fn emit_trampoline(
    w: &mut CodeWriter,
    entry: *mut HookEntry,
    prologue: &[u8],
    resume: usize,
    after: AfterEnter,
) {
    w.bti_jc();
    emit_save_regs(w);
    // Frida sets next_hop to the on-invoke prologue before the listener runs.
    let hop_adr = if matches!(after, AfterEnter::Continue) {
        let at = w.len();
        w.put(0x1000_0000 | 2); // placeholder: adr x2, prologue
        w.str_imm(2, 31, OFF_PC);
        Some(at)
    } else {
        None
    };
    w.abs_addr(0, entry as usize as u64);
    w.put(0x9100_03E1); // mov x1, sp
    w.abs_bl(dispatch as *const () as usize);
    emit_restore_regs(w);
    match after {
        AfterEnter::Return => {
            // gum leave: next_hop = gum_sign_code_pointer(caller_ret_addr); BR.
            emit_mov_sp_from_slot(w);
            w.put(0xAA1E_03F0); // mov x16, x30
            w.jmp_auth_lr(16);
        }
        AfterEnter::Continue => {
            emit_jump_saved_pc(w);
            let prologue_at = w.len();
            if let Some(adr_at) = hop_adr {
                w.set_word(adr_at, adr_x2(prologue_at as i64 - adr_at as i64));
            }
            w.put_bytes(prologue);
            w.abs_b_signed(resume);
        }
    }
}

/// `ADR X2, #offset` with a byte offset from this instruction.
fn adr_x2(offset: i64) -> u32 {
    let immlo = (offset as u32) & 3;
    let immhi = ((offset >> 2) as u32) & 0x7_FFFF;
    0x1000_0000 | (immlo << 29) | (immhi << 5) | 2
}

fn return_stub() -> Result<usize> {
    static STUB: OnceLock<usize> = OnceLock::new();
    load_stub(&STUB, make_return_stub)
}

/// Remember a stub address only after allocation succeeds.
fn load_stub(slot: &OnceLock<usize>, alloc: impl FnOnce() -> Option<usize>) -> Result<usize> {
    if let Some(addr) = slot.get().copied() {
        return Ok(addr);
    }
    let addr = alloc().ok_or(Error::Unsupported("hook: cannot allocate return stub"))?;
    // A failed allocation never reaches set, so the next call tries again.
    let _ = slot.set(addr);
    Ok(slot.get().copied().unwrap_or(addr))
}

fn make_return_stub() -> Option<usize> {
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
        return None;
    }

    let mut w = CodeWriter::with_capacity(512);
    emit_return_stub(&mut w);
    // SAFETY: page is a private mapping of at least PAGE bytes.
    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), page as *mut u8, w.len());
    }
    flush_icache(page as usize, w.len());
    if protect(page as usize, PAGE, libc::PROT_READ | libc::PROT_EXEC).is_err() {
        unsafe { libc::munmap(page, PAGE) };
        return None;
    }
    Some(page as usize)
}

fn emit_return_stub(w: &mut CodeWriter) {
    w.bti_jc();
    emit_save_regs(w);
    w.put(0x9100_03E0); // mov x0, sp
    w.abs_bl(leave_dispatch as *const () as usize);
    emit_restore_regs(w);
    emit_mov_sp_from_slot(w);
    w.put(0xAA1E_03F0); // mov x16, x30
    w.jmp_auth_lr(16);
}

/// `ldr x17, [sp, #OFF_SP]; mov sp, x17`.  SP still addresses the frame.
fn emit_mov_sp_from_slot(w: &mut CodeWriter) {
    w.ldr_imm(17, 31, OFF_SP);
    w.put(0x9100_023F); // add sp, x17, #0
}

/// Load the saved SP and PC.  A zero PC falls through into the relocated prologue.
fn emit_jump_saved_pc(w: &mut CodeWriter) {
    w.ldr_imm(16, 31, OFF_PC);
    emit_mov_sp_from_slot(w);
    w.put(0xB400_0050); // cbz x16, #8
    w.ret(16);
}

fn emit_save_regs(w: &mut CodeWriter) {
    w.sub_sp(SAVE_SIZE);
    for i in 0..14u8 {
        w.stp(i * 2, i * 2 + 1, 31, (i as i64) * 16);
    }
    w.stp(28, 29, 31, 224);
    w.str_imm(30, 31, OFF_LR);
    // Original SP is the frame plus SAVE_SIZE; NZCV via MRS. x16 was already stored.
    w.put(0x9100_0000 | (SAVE_SIZE << 10) | (31 << 5) | 16); // add x16, sp, #SAVE_SIZE
    w.str_imm(16, 31, OFF_SP);
    w.put(0xD53B_4210); // mrs x16, nzcv
    w.str_imm(16, 31, OFF_NZCV);
    for i in 0..4u8 {
        w.stp_q(i * 2, i * 2 + 1, 31, i64::from(OFF_Q + u32::from(i) * 32));
    }
}

fn emit_restore_regs(w: &mut CodeWriter) {
    for i in 0..4u8 {
        w.ldp_q(i * 2, i * 2 + 1, 31, i64::from(OFF_Q + u32::from(i) * 32));
    }
    w.ldr_imm(16, 31, OFF_NZCV);
    w.put(0xD51B_4210); // msr nzcv, x16
    for i in 0..14u8 {
        w.ldp(i * 2, i * 2 + 1, 31, (i as i64) * 16);
    }
    w.ldp(28, 29, 31, 224);
    w.ldr_imm(30, 31, OFF_LR);
}

pub(crate) fn is_bti_or_pac(word: u32) -> bool {
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
    match runtime::maps::self_mapping_containing(addr) {
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
        assert_eq!(std::mem::size_of::<SavedRegs>(), 400);
        assert_eq!(std::mem::size_of::<SavedRegs>(), SAVE_SIZE as usize);
        assert_eq!(core::mem::offset_of!(SavedRegs, lr), OFF_LR as usize);
        assert_eq!(core::mem::offset_of!(SavedRegs, sp), OFF_SP as usize);
        assert_eq!(core::mem::offset_of!(SavedRegs, nzcv), OFF_NZCV as usize);
        assert_eq!(core::mem::offset_of!(SavedRegs, pc), OFF_PC as usize);
        assert_eq!(core::mem::offset_of!(SavedRegs, q), OFF_Q as usize);
        assert!(std::mem::align_of::<SavedRegs>() >= 16);
        let mut regs = SavedRegs::default();
        regs.set_arg(0, 7);
        regs.set_arg(28, 9);
        assert_eq!(regs.arg(0), 7);
        assert_eq!(regs.arg(28), 9);
        assert_eq!(regs.arg(99), 0);
        regs.fp = 1;
        regs.lr = 2;
        regs.sp = 3;
        regs.nzcv = 4;
        regs.pc = 5;
        assert_eq!(
            (regs.fp, regs.lr, regs.sp, regs.nzcv, regs.pc),
            (1, 2, 3, 4, 5)
        );
    }

    #[test]
    fn skips_bti_and_pac() {
        assert!(is_bti_or_pac(0xD503_245F));
        assert!(is_bti_or_pac(0xD503_233F));
        assert!(!is_bti_or_pac(0xD503_201F));
    }

    unsafe extern "C" fn empty_enter(_regs: *mut SavedRegs, _data: *mut c_void) {}

    #[test]
    fn attach_patches_prologue_and_detach_restores() {
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
        assert_ne!(page, libc::MAP_FAILED);
        let target = page as usize;
        unsafe {
            ptr::write_unaligned(target as *mut u32, 0xD503_201F);
            ptr::write_unaligned((target + 4) as *mut u32, 0xD503_201F);
        }
        let mut hook =
            unsafe { InlineHook::attach(target, empty_enter, ptr::null_mut()) }.expect("attach");
        let patched = unsafe { ptr::read_unaligned(target as *const u32) };
        assert_ne!(patched, 0xD503_201F, "prologue must be overwritten with B");
        assert_eq!(patched & 0xFC00_0000, 0x1400_0000, "ARM64 B encoding");
        hook.detach().unwrap();
        let restored = unsafe { ptr::read_unaligned(target as *const u32) };
        assert_eq!(restored, 0xD503_201F);
        unsafe { libc::munmap(page, PAGE) };
    }

    #[test]
    fn epilogue_reloads_saved_sp_and_branches_to_saved_pc() {
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
        assert_ne!(page, libc::MAP_FAILED);
        let target = page as usize;
        unsafe { ptr::write_unaligned(target as *mut u32, 0xD503_201F) };
        let hook =
            unsafe { InlineHook::attach(target, empty_enter, ptr::null_mut()) }.expect("attach");
        let bytes = unsafe { std::slice::from_raw_parts(hook.trampoline() as *const u8, 0x400) };
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // ldr x16, [sp, #OFF_PC]; ldr x17, [sp, #OFF_SP]; mov sp, x17; cbz; ret x16
        let hop = [
            0xF940_87F0,
            0xF940_7FF1,
            0x9100_023F,
            0xB400_0050,
            0xD65F_0200,
        ];
        assert!(
            words.windows(5).any(|window| window == hop),
            "epilogue missing SP reload and PC branch"
        );
        let back = [0x5800_0050, 0xD65F_0200]; // ldr x16, #8; ret x16
        assert!(
            words.windows(2).any(|window| window == back),
            "mid-function resume is not RET"
        );
        assert!(!words.contains(&0xD61F_0A1F), "resume still uses BRAAZ");
        assert!(words.contains(&0xA940_07E0), "ldp x0, x1");
        assert!(words.contains(&0xF940_7BFE), "ldr lr");
        assert!(words.contains(&0xD51B_4210), "msr nzcv");
        assert!(
            !words.contains(&0x9106_43FF),
            "epilogue still adds a fixed frame"
        );
        drop(hook);
        unsafe { libc::munmap(page, PAGE) };
    }

    #[test]
    fn failed_stub_allocation_is_not_cached() {
        let slot = OnceLock::new();
        assert!(load_stub(&slot, || None).is_err());
        assert_eq!(load_stub(&slot, || Some(0x1000)).unwrap(), 0x1000);
        assert_eq!(load_stub(&slot, || None).unwrap(), 0x1000);
    }

    #[test]
    fn failed_attempt_unmaps_its_page() {
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
        assert_ne!(page, libc::MAP_FAILED);
        let entry = Box::into_raw(Box::new(HookEntry {
            on_enter: empty_enter,
            on_leave: None,
            user_data: ptr::null_mut(),
            return_stub: 0,
            pc: 1,
        }));
        let addr = page as usize;
        drop(Attempt { entry, page: addr });
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        assert!(
            !maps.contains(&format!("{addr:x}-")),
            "failed attach left {addr:#x} mapped"
        );
    }

    #[test]
    fn attach_of_prfm_does_not_patch() {
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
        assert_ne!(page, libc::MAP_FAILED);
        let target = page as usize;
        unsafe { ptr::write_unaligned(target as *mut u32, 0xD800_0000) };
        let err = unsafe { InlineHook::attach(target, empty_enter, ptr::null_mut()) };
        let Err(err) = err else {
            panic!("prfm prologue was hooked");
        };
        assert!(err.to_string().contains("cannot relocate"), "{err}");
        assert_eq!(
            unsafe { ptr::read_unaligned(target as *const u32) },
            0xD800_0000
        );
        unsafe { libc::munmap(page, PAGE) };
    }
}
