//! Statically linked QBDI FFI used only when `feature = "link"`.

use std::ffi::{c_char, c_void, CString};
use std::ptr;

use gum::native;
use gum::replace;
use runtime::{Error, Result};

use crate::session::TraceConfig;
use crate::{blacklist, EventKind, EventRing, TraceEvent};

type Rword = usize;
type VmRef = *mut c_void;

const CONTINUE: u32 = 0;
const STOP: u32 = 4;
const PREINST: u32 = 0;
const MEMORY_READ_WRITE: u32 = 3;

#[repr(C)]
struct GprState {
    // AArch64 GPRState in QBDI: x0-x28, fp, lr, sp, pc, nzcv (and padding).
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    nzcv: u64,
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
    fn qbdi_callA(
        instance: VmRef,
        retval: *mut Rword,
        function: Rword,
        arg_num: u32,
        args: *const Rword,
    ) -> bool;
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
    original: usize,
    ring: EventRing,
}

static SESSIONS: std::sync::Mutex<Vec<Option<EngineState>>> = std::sync::Mutex::new(Vec::new());

fn sessions() -> std::sync::MutexGuard<'static, Vec<Option<EngineState>>> {
    SESSIONS.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn install(config: TraceConfig) -> Result<u32> {
    let target = usize::try_from(config.target)
        .map_err(|_| Error::Parse("Trace.function: target does not fit".into()))?;
    if target == 0 {
        return Err(Error::Parse("Trace.function: null target".into()));
    }
    let stub = native::make_callback_stub(trace_dispatch as *const () as usize, 0)?;
    replace::replace(target, stub)?;
    let original = replace::original_trampoline(target).unwrap_or(target);
    let mut table = sessions();
    let id = table.len() as u32;
    table.push(Some(EngineState {
        config,
        original,
        ring: EventRing::new(4096),
    }));
    let _ = id;
    // The stub cannot carry a session id in make_callback_stub (it encodes 0).
    // Use a single active session for v1 (TAL also keeps one cur_tracer).
    Ok(0)
}

extern "C" fn trace_dispatch(_id: usize, args: *const u64) -> u64 {
    let mut raw = [0u64; 8];
    if !args.is_null() {
        // SAFETY: NativeCallback stub passes eight saved GPRs.
        unsafe { ptr::copy_nonoverlapping(args, raw.as_mut_ptr(), 8) };
    }
    run_one(&raw).unwrap_or(0)
}

fn run_one(args: &[u64; 8]) -> Result<u64> {
    let mut table = sessions();
    let Some(Some(state)) = table.last_mut() else {
        return Ok(0);
    };
    let original = state.original;
    let target = state.config.target as usize;
    let extra = state.config.extra_exclude.clone();
    let until = state.config.until;
    drop(table);

    let mut vm: VmRef = ptr::null_mut();
    // SAFETY: QBDI creates a VM; we terminate it below.
    unsafe { qbdi_initVM(&mut vm, ptr::null(), ptr::null(), 0) };
    if vm.is_null() {
        return Err(Error::Parse("qbdi_initVM failed".into()));
    }
    // SAFETY: vm is a live instance.
    unsafe {
        qbdi_addInstrumentedModuleFromAddr(vm, target);
        qbdi_addInstrumentedRange(vm, original, original.saturating_add(0x40));
        qbdi_recordMemoryAccess(vm, MEMORY_READ_WRITE);
    }
    if let Ok(ranges) = blacklist::excluded_executable_ranges(&extra) {
        for (start, end) in ranges {
            unsafe { qbdi_removeInstrumentedRange(vm, start as Rword, end as Rword) };
        }
    }
    // Keep the hooked function itself even if its module is blacklisted.
    unsafe {
        qbdi_addInstrumentedRange(vm, target, target.saturating_add(0x400));
        qbdi_addInstrumentedRange(vm, original, original.saturating_add(0x80));
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
    let mut retval: Rword = 0;
    let words: [Rword; 8] = args.map(|v| v as Rword);
    // SAFETY: original is the backup trampoline; args are the live call.
    let _ = unsafe { qbdi_callA(vm, &mut retval, original, 8, words.as_ptr()) };
    unsafe { qbdi_terminateVM(vm) };
    let _ = until;
    Ok(retval as u64)
}

struct DispatchCtx {
    _until: Option<u64>,
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
    let pc = unsafe { (*analysis).address as u64 };
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
                pc: access.inst_address as u64,
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
