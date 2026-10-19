//! Statically linked QBDI FFI (`feature = "link"`).
//!
//! TAL door (`PangBaiWork/TAL` `library.cpp` `on_enter` + `vm.cpp` `init`):
//! Gum attach → one-shot detach → `syn_reg_gum` into `getGPRState` → custom
//! host stack → `VM::run(start, stop)`. Guest SP is the live interceptor SP,
//! not a `callA` virtual stack (QBDI `callA` returns false when SP == 0).

use std::ffi::{c_char, c_void};
use std::mem::size_of;
use std::ptr;

use gum::hook::{InlineHook, SavedRegs};
use runtime::{Error, Result};

use crate::session::TraceConfig;
use crate::{blacklist, EventKind, EventRing, TraceEvent};

type Rword = usize;
type VmRef = *mut c_void;

const CONTINUE: u32 = 0;
const STOP: u32 = 4;
const PREINST: u32 = 0;
const MEMORY_READ_WRITE: u32 = 3;
/// TAL `RawBufferStack(1 << 24)` — host stack for the engine, not the guest.
const HOST_STACK: usize = 1 << 24;
const PAC_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

#[repr(C)]
struct GprState {
    x: [u64; 29],
    x29: u64,
    lr: u64,
    sp: u64,
    nzcv: u64,
    pc: u64,
    local_monitor_addr: u64,
    local_monitor_enable: u64,
}

#[repr(C)]
struct InstAnalysis {
    mnemonic: *const c_char,
    address: Rword,
    inst_size: u32,
}

#[repr(C)]
struct MemoryAccess {
    inst_address: Rword,
    access_address: Rword,
    value: Rword,
    size: u16,
    type_flags: u32,
    flags: u32,
}

extern "C" {
    fn qbdi_initVM(
        instance: *mut VmRef,
        cpu: *const c_char,
        mattrs: *const *const c_char,
        opts: u32,
    );
    fn qbdi_terminateVM(instance: VmRef);
    fn qbdi_addInstrumentedModuleFromAddr(instance: VmRef, addr: Rword) -> bool;
    fn qbdi_addInstrumentedRange(instance: VmRef, start: Rword, end: Rword);
    fn qbdi_removeInstrumentedRange(instance: VmRef, start: Rword, end: Rword);
    fn qbdi_run(instance: VmRef, start: Rword, stop: Rword) -> bool;
    fn qbdi_getGPRState(instance: VmRef) -> *mut GprState;
    fn qbdi_addCodeCB(
        instance: VmRef,
        pos: u32,
        cbk: extern "C" fn(VmRef, *mut c_void, *mut c_void, *mut c_void) -> u32,
        data: *mut c_void,
        priority: i32,
    ) -> u32;
    fn qbdi_addMemAccessCB(
        instance: VmRef,
        kind: u32,
        cbk: extern "C" fn(VmRef, *mut c_void, *mut c_void, *mut c_void) -> u32,
        data: *mut c_void,
        priority: i32,
    ) -> u32;
    fn qbdi_getInstAnalysis(instance: VmRef, analysis: u32) -> *const InstAnalysis;
    fn qbdi_getInstMemoryAccess(instance: VmRef, size: *mut usize) -> *mut MemoryAccess;
    fn qbdi_recordMemoryAccess(instance: VmRef, kind: u32) -> bool;
}

struct EngineState {
    config: TraceConfig,
    hook: Option<SendHook>,
    ring: EventRing,
}

/// `InlineHook` holds a trampoline pointer; only the traced thread detaches it.
struct SendHook(InlineHook);

unsafe impl Send for SendHook {}

static SESSIONS: std::sync::Mutex<Vec<Option<EngineState>>> = std::sync::Mutex::new(Vec::new());

fn sessions() -> std::sync::MutexGuard<'static, Vec<Option<EngineState>>> {
    SESSIONS.lock().unwrap_or_else(|err| err.into_inner())
}

fn strip_pac(addr: u64) -> u64 {
    addr & PAC_MASK
}

pub fn install(config: TraceConfig) -> Result<u32> {
    let target = usize::try_from(strip_pac(config.target))
        .map_err(|_| Error::Parse("Trace.function: target does not fit".into()))?;
    if target == 0 {
        return Err(Error::Parse("Trace.function: null target".into()));
    }
    // TAL `HookUtils::gum_attach` (UNIGNORABLE): our inline hook always fires.
    // SAFETY: `on_enter` only uses process-lifetime session state.
    let hook = unsafe { InlineHook::attach(target, on_enter, ptr::null_mut())? };
    let mut table = sessions();
    table.clear();
    table.push(Some(EngineState {
        config,
        hook: Some(SendHook(hook)),
        ring: EventRing::new(4096),
    }));
    Ok(0)
}

/// TAL `syn_reg_gum` (F2Q): copy live Gum context into QBDI GPR, including SP.
fn syn_reg_gum(gpr: &mut GprState, regs: &SavedRegs, callees: &[u64; 11], guest_sp: u64) {
    for (index, value) in regs.x.iter().enumerate() {
        gpr.x[index] = *value;
    }
    for (index, value) in callees.iter().take(10).enumerate() {
        gpr.x[19 + index] = *value;
    }
    gpr.x29 = callees[10];
    gpr.lr = strip_pac(regs.lr);
    gpr.sp = guest_sp;
}

#[repr(C)]
struct Outcome {
    x19_x28: [u64; 10],
    x29: u64,
    x0: u64,
    sp: u64,
    lr: u64,
}

/// Callee-saved regs still live at interceptor entry (trampoline only saved x0–x18/LR).
#[cfg(target_arch = "aarch64")]
fn capture_callees() -> [u64; 11] {
    let mut x19: u64;
    let mut x20: u64;
    let mut x21: u64;
    let mut x22: u64;
    let mut x23: u64;
    let mut x24: u64;
    let mut x25: u64;
    let mut x26: u64;
    let mut x27: u64;
    let mut x28: u64;
    let mut x29: u64;
    unsafe {
        core::arch::asm!(
            "mov {x19}, x19",
            "mov {x20}, x20",
            "mov {x21}, x21",
            "mov {x22}, x22",
            "mov {x23}, x23",
            "mov {x24}, x24",
            "mov {x25}, x25",
            "mov {x26}, x26",
            "mov {x27}, x27",
            "mov {x28}, x28",
            "mov {x29}, x29",
            x19 = out(reg) x19,
            x20 = out(reg) x20,
            x21 = out(reg) x21,
            x22 = out(reg) x22,
            x23 = out(reg) x23,
            x24 = out(reg) x24,
            x25 = out(reg) x25,
            x26 = out(reg) x26,
            x27 = out(reg) x27,
            x28 = out(reg) x28,
            x29 = out(reg) x29,
            options(nostack, nomem, preserves_flags),
        );
    }
    [x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29]
}

#[cfg(not(target_arch = "aarch64"))]
fn capture_callees() -> [u64; 11] {
    [0; 11]
}

unsafe extern "C" fn on_enter(regs: *mut SavedRegs, _data: *mut c_void) {
    if regs.is_null() {
        return;
    }
    let callees = capture_callees();
    let guest_sp = regs as u64 + size_of::<SavedRegs>() as u64;
    let mut hook = {
        let mut table = sessions();
        table
            .last_mut()
            .and_then(|slot| slot.as_mut())
            .and_then(|state| state.hook.take())
    };
    if let Some(SendHook(ref mut hook)) = hook {
        let _ = hook.detach();
    }
    // SAFETY: `regs` is the trampoline's SavedRegs frame for this call.
    let regs_ref = unsafe { &*regs };
    match run_one(regs_ref, &callees, guest_sp) {
        Ok(outcome) => {
            drop(hook);
            // TAL never returns to the interceptor; the function already ran in the VM.
            unsafe { finish_like_tal(&outcome) };
        }
        Err(_) => {}
    }
}

fn run_one(regs: &SavedRegs, callees: &[u64; 11], guest_sp: u64) -> Result<Outcome> {
    let mut table = sessions();
    let Some(Some(state)) = table.last_mut() else {
        return Err(Error::Parse("Trace.function: no session".into()));
    };
    let target = strip_pac(state.config.target) as usize;
    let extra = state.config.extra_exclude.clone();
    let until = state.config.until.map(strip_pac);
    drop(table);

    let mut vm: VmRef = ptr::null_mut();
    // SAFETY: QBDI creates a VM; VmDrop terminates it.
    unsafe { qbdi_initVM(&mut vm, ptr::null(), ptr::null(), 0) };
    if vm.is_null() {
        return Err(Error::Parse("qbdi_initVM failed".into()));
    }
    let _vm = VmDrop(vm);

    // SAFETY: `vm` is a live instance (TAL `init`).
    unsafe {
        qbdi_addInstrumentedModuleFromAddr(vm, target);
        qbdi_recordMemoryAccess(vm, MEMORY_READ_WRITE);
    }
    if let Ok(ranges) = blacklist::excluded_executable_ranges(&extra) {
        for (start, end) in ranges {
            unsafe { qbdi_removeInstrumentedRange(vm, start as Rword, end as Rword) };
        }
    }
    // Keep the hooked function even if its module is in the conflict set (libc strlen).
    unsafe {
        qbdi_addInstrumentedRange(vm, target, target.saturating_add(0x400));
    }

    let mut ctx = DispatchCtx { _until: until };
    unsafe {
        qbdi_addCodeCB(
            vm,
            PREINST,
            on_preinst,
            (&mut ctx as *mut DispatchCtx).cast(),
            0,
        );
        qbdi_addMemAccessCB(vm, MEMORY_READ_WRITE, on_mem, ptr::null_mut(), -10);
    }

    // SAFETY: `vm` is live until `VmDrop`.
    let gpr = unsafe { qbdi_getGPRState(vm) };
    if gpr.is_null() {
        return Err(Error::Parse("qbdi_getGPRState failed".into()));
    }
    // SAFETY: GPRState is VM-owned until terminate.
    unsafe { syn_reg_gum(&mut *gpr, regs, callees, guest_sp) };
    // SAFETY: `gpr` came from `qbdi_getGPRState` on a live VM.
    if unsafe { (*gpr).sp } == 0 {
        return Err(Error::Parse("QBDI GPR SP is 0 after syn_reg_gum".into()));
    }

    let stop = until.filter(|pc| *pc != 0).unwrap_or_else(|| {
        // SAFETY: `gpr` still points at the live VM GPRState.
        unsafe { (*gpr).lr }
    });
    if stop == 0 {
        return Err(Error::Parse(
            "Trace.function: no stop address (LR is 0)".into(),
        ));
    }

    let ran = run_on_host_stack(vm, target, stop as Rword);
    if !ran {
        return Err(Error::Parse("qbdi_run failed".into()));
    }

    // SAFETY: VM still live; guest has returned to `stop`.
    let gpr = unsafe { &*gpr };
    let mut x19_x28 = [0u64; 10];
    x19_x28.copy_from_slice(&gpr.x[19..29]);
    Ok(Outcome {
        x19_x28,
        x29: gpr.x29,
        x0: gpr.x[0],
        sp: gpr.sp,
        lr: gpr.lr,
    })
}

fn run_on_host_stack(vm: VmRef, start: Rword, stop: Rword) -> bool {
    match HostStack::allocate() {
        Some(stack) => {
            // SAFETY: `stack.top()` is 16-byte aligned RW memory of HOST_STACK bytes.
            unsafe { qbdi_run_on_stack(vm, start, stop, stack.top()) }
        }
        None => {
            // SAFETY: `vm` is a live instance; guest SP is already in GPRState.
            unsafe { qbdi_run(vm, start, stop) }
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn qbdi_run_on_stack(vm: VmRef, start: Rword, stop: Rword, stack_top: usize) -> bool {
    let mut ret: usize = vm as usize;
    // SAFETY: `stack_top` is 16-byte aligned RW anonymous memory; guest SP lives in GPR.
    // x20 holds the host SP across `qbdi_run` (C ABI callee-saved).
    unsafe {
        core::arch::asm!(
            "mov x20, sp",
            "mov sp, {top}",
            "blr {f}",
            "mov sp, x20",
            top = in(reg) stack_top,
            f = in(reg) qbdi_run,
            inout("x0") ret,
            in("x1") start,
            in("x2") stop,
            out("x20") _,
            out("x3") _,
            out("x4") _,
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            out("x30") _,
        );
    }
    ret != 0
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn qbdi_run_on_stack(vm: VmRef, start: Rword, stop: Rword, _stack_top: usize) -> bool {
    unsafe { qbdi_run(vm, start, stop) }
}

#[cfg(target_arch = "aarch64")]
unsafe fn finish_like_tal(out: &Outcome) -> ! {
    // SAFETY: loads complete before `mov sp`; then branch to the original LR.
    unsafe {
        core::arch::asm!(
            "ldp x19, x20, [{p}]",
            "ldp x21, x22, [{p}, #16]",
            "ldp x23, x24, [{p}, #32]",
            "ldp x25, x26, [{p}, #48]",
            "ldp x27, x28, [{p}, #64]",
            "ldr x29, [{p}, #80]",
            "ldr x0, [{p}, #88]",
            "ldr x16, [{p}, #96]",
            "ldr x30, [{p}, #104]",
            "mov sp, x16",
            "br x30",
            p = in(reg) out,
            options(noreturn),
        );
    }
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn finish_like_tal(out: &Outcome) -> ! {
    let _ = out;
    loop {
        std::thread::park();
    }
}

struct DispatchCtx {
    _until: Option<u64>,
}

struct VmDrop(VmRef);

impl Drop for VmDrop {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a VM from `qbdi_initVM` that has not been terminated.
            unsafe { qbdi_terminateVM(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

struct HostStack {
    ptr: *mut c_void,
    len: usize,
}

impl HostStack {
    fn allocate() -> Option<Self> {
        let len = HOST_STACK;
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            None
        } else {
            Some(Self { ptr, len })
        }
    }

    fn top(&self) -> usize {
        (self.ptr as usize + self.len) & !0xF
    }
}

impl Drop for HostStack {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.ptr != libc::MAP_FAILED {
            unsafe { libc::munmap(self.ptr, self.len) };
        }
    }
}

extern "C" fn on_preinst(
    vm: VmRef,
    _gpr: *mut c_void,
    _fpr: *mut c_void,
    data: *mut c_void,
) -> u32 {
    let analysis = unsafe { qbdi_getInstAnalysis(vm, 1) };
    if analysis.is_null() {
        return CONTINUE;
    }
    let pc = strip_pac(unsafe { (*analysis).address as u64 });
    let size = unsafe { (*analysis).inst_size as u16 };
    if let Some(state) = sessions().last_mut().and_then(|slot| slot.as_mut()) {
        state.ring.push(TraceEvent {
            kind: EventKind::Inst,
            pc,
            size,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
        });
        if state.config.should_stop(pc) {
            return STOP;
        }
    }
    let _ = data;
    CONTINUE
}

extern "C" fn on_mem(vm: VmRef, _gpr: *mut c_void, _fpr: *mut c_void, _data: *mut c_void) -> u32 {
    let mut count = 0usize;
    let accesses = unsafe { qbdi_getInstMemoryAccess(vm, &mut count) };
    if accesses.is_null() {
        return CONTINUE;
    }
    if let Some(state) = sessions().last_mut().and_then(|slot| slot.as_mut()) {
        for index in 0..count {
            let access = unsafe { &*accesses.add(index) };
            state.ring.push(TraceEvent {
                kind: EventKind::Mem,
                pc: strip_pac(access.inst_address as u64),
                size: access.size,
                mem_addr: access.access_address as u64,
                mem_value: access.value as u64,
                is_write: access.type_flags != 1,
            });
        }
    }
    CONTINUE
}

/// Drain batched events after a traced call (JS worker).
pub fn drain_events() -> Vec<TraceEvent> {
    sessions()
        .last_mut()
        .and_then(|slot| slot.as_mut())
        .map(|state| state.ring.drain())
        .unwrap_or_default()
}
