//! QBDI VM for `Trace.function`. The hook is ours; this module prepares the
//! VM, skips PAC hints, and collects events. No TAL.

use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;

use runtime::{Error, Result};

use crate::blacklist;
use crate::session::EventMask;
use crate::TraceEvent;
use crate::EventKind;

const OPT_BYPASS_PAUTH: u32 = 1 << 25;
const PREINST: u32 = 0;
const POSTINST: u32 = 1;
const CONTINUE: u32 = 0;
const SKIP_PATCH: u32 = 2;
const BREAK_TO_VM: u32 = 3;
const ANALYSIS_INSTRUCTION: u32 = 1;
const MEMORY_READ_WRITE: u32 = 3;
const MEMORY_WRITE: u32 = 2;

const PAC_HINTS: [u32; 8] = [
    0xD503_233F, // PACIASP
    0xD503_237F, // PACIBSP
    0xD503_23BF, // AUTIASP
    0xD503_23FF, // AUTIBSP
    0xD503_231F, // PACIAZ
    0xD503_235F, // PACIBZ
    0xD503_239F, // AUTIAZ
    0xD503_23DF, // AUTIBZ
];

/// Guest registers copied into QBDI before `qbdi_run` and back afterwards.
pub struct GuestRegs {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub pc: u64,
    pub q: [u128; 32],
}

#[repr(C)]
struct GprState {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    nzcv: u64,
    pc: u64,
    local_monitor_addr: u64,
    local_monitor_enable: u64,
}

#[repr(C)]
struct FprState {
    v: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

#[repr(C)]
struct InstAnalysis {
    _mnemonic: *const i8,
    address: u64,
    inst_size: u32,
    _cpu_mode: u32,
    _affect_control_flow: bool,
    _is_branch: bool,
    is_call: bool,
}

#[repr(C)]
struct MemoryAccess {
    inst_address: u64,
    access_address: u64,
    value: u64,
    size: u16,
    kind: u32,
    _flags: u32,
}

#[repr(C)]
struct MemoryMap {
    start: u64,
    end: u64,
    _permission: u32,
    name: *mut i8,
}

struct Vm(*mut c_void);

unsafe impl Send for Vm {}

struct Door {
    vm: Vm,
    events: Vec<TraceEvent>,
    escapes: Vec<(u64, u64)>,
    until: u64,
    inst: bool,
    mem: bool,
    call: bool,
}

static DOOR: Mutex<Option<Door>> = Mutex::new(None);

fn door() -> std::sync::MutexGuard<'static, Option<Door>> {
    DOOR.lock().unwrap_or_else(|err| err.into_inner())
}

extern "C" {
    fn qbdi_initVM(instance: *mut *mut c_void, cpu: *const i8, mattrs: *const i8);
    fn qbdi_terminateVM(instance: *mut c_void);
    fn qbdi_getOptions(instance: *mut c_void) -> u32;
    fn qbdi_setOptions(instance: *mut c_void, options: u32);
    fn qbdi_addInstrumentedModuleFromAddr(instance: *mut c_void, addr: u64) -> bool;
    fn qbdi_removeInstrumentedRange(instance: *mut c_void, start: u64, end: u64);
    fn qbdi_getCurrentProcessMaps(full_path: bool, size: *mut usize) -> *mut MemoryMap;
    fn qbdi_freeMemoryMapArray(arr: *mut MemoryMap, size: usize);
    fn qbdi_getGPRState(instance: *mut c_void) -> *mut GprState;
    fn qbdi_getFPRState(instance: *mut c_void) -> *mut FprState;
    fn qbdi_addCodeCB(
        instance: *mut c_void,
        pos: u32,
        cbk: unsafe extern "C" fn(*mut c_void, *mut GprState, *mut FprState, *mut c_void) -> u32,
        data: *mut c_void,
        priority: i32,
    ) -> u32;
    fn qbdi_getInstAnalysis(instance: *mut c_void, kind: u32) -> *const InstAnalysis;
    fn qbdi_recordMemoryAccess(instance: *mut c_void, kind: u32) -> bool;
    fn qbdi_getInstMemoryAccess(instance: *mut c_void, size: *mut usize) -> *mut MemoryAccess;
    fn qbdi_run(instance: *mut c_void, start: u64, stop: u64) -> bool;
}

/// Create a VM for `target`, instrument its module, and drop conflict ranges.
pub fn prepare(target: u64, until: u64, events: &EventMask) -> Result<()> {
    let mut vm = ptr::null_mut();
    unsafe { qbdi_initVM(&mut vm, ptr::null(), ptr::null()) };
    if vm.is_null() {
        return Err(Error::Parse("qbdi_initVM failed".into()));
    }
    unsafe {
        let options = qbdi_getOptions(vm) | OPT_BYPASS_PAUTH;
        qbdi_setOptions(vm, options);
        qbdi_addCodeCB(vm, PREINST, pre_inst, ptr::null_mut(), 0);
        if events.mem {
            qbdi_recordMemoryAccess(vm, MEMORY_READ_WRITE);
            qbdi_addCodeCB(vm, POSTINST, post_inst, ptr::null_mut(), 0);
        }
        if !qbdi_addInstrumentedModuleFromAddr(vm, target) {
            qbdi_terminateVM(vm);
            return Err(Error::Parse(
                "qbdi_addInstrumentedModuleFromAddr failed".into(),
            ));
        }
        drop_conflict_ranges(vm);
    }
    let mut slot = door();
    if let Some(previous) = slot.take() {
        unsafe { qbdi_terminateVM(previous.vm.0) };
    }
    *slot = Some(Door {
        vm: Vm(vm),
        events: Vec::new(),
        escapes: Vec::new(),
        until,
        inst: events.inst,
        mem: events.mem,
        call: events.call,
    });
    Ok(())
}

pub fn add_escape(break_at: u64, resume: u64) {
    if let Some(door) = door().as_mut() {
        door.escapes.push((break_at, resume));
    }
}

/// Copy `regs` into the VM, run from `start` until `stop`, then copy them back.
pub fn run(regs: &mut GuestRegs, start: u64, stop: u64) -> Result<()> {
    let (vm, stop) = {
        let slot = door();
        let door = slot
            .as_ref()
            .ok_or_else(|| Error::Parse("QBDI VM is not prepared".into()))?;
        let stop = if door.until != 0 { door.until } else { stop };
        (door.vm.0, stop)
    };
    unsafe {
        let gpr = qbdi_getGPRState(vm);
        let fpr = qbdi_getFPRState(vm);
        if gpr.is_null() || fpr.is_null() {
            return Err(Error::Parse("QBDI register state is null".into()));
        }
        copy_gpr_in(gpr, regs);
        (*fpr).v = regs.q;
        qbdi_run(vm, start, stop);
        copy_gpr_out(regs, gpr);
        regs.q = (*fpr).v;
    }
    Ok(())
}

pub fn take_events() -> Vec<TraceEvent> {
    door()
        .as_mut()
        .map(|door| std::mem::take(&mut door.events))
        .unwrap_or_default()
}

fn copy_gpr_in(dst: *mut GprState, src: &GuestRegs) {
    unsafe {
        (*dst).x = src.x;
        (*dst).fp = src.fp;
        (*dst).lr = src.lr;
        (*dst).sp = src.sp;
        (*dst).nzcv = src.nzcv;
        (*dst).pc = src.pc;
    }
}

fn copy_gpr_out(dst: &mut GuestRegs, src: *const GprState) {
    unsafe {
        dst.x = (*src).x;
        dst.fp = (*src).fp;
        dst.lr = (*src).lr;
        dst.sp = (*src).sp;
        dst.nzcv = (*src).nzcv;
        dst.pc = (*src).pc;
    }
}

fn drop_conflict_ranges(vm: *mut c_void) {
    let mut size = 0usize;
    let maps = unsafe { qbdi_getCurrentProcessMaps(true, &mut size) };
    if maps.is_null() {
        return;
    }
    for index in 0..size {
        let map = unsafe { &*maps.add(index) };
        if map.name.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(map.name.cast()) }.to_string_lossy();
        if blacklist::is_conflict(&name) {
            unsafe { qbdi_removeInstrumentedRange(vm, map.start, map.end) };
        }
    }
    unsafe { qbdi_freeMemoryMapArray(maps, size) };
}

unsafe extern "C" fn pre_inst(
    vm: *mut c_void,
    gpr: *mut GprState,
    _fpr: *mut FprState,
    _data: *mut c_void,
) -> u32 {
    let analysis = unsafe { qbdi_getInstAnalysis(vm, ANALYSIS_INSTRUCTION) };
    if analysis.is_null() {
        return CONTINUE;
    }
    let address = unsafe { (*analysis).address };
    let inst_size = unsafe { (*analysis).inst_size };
    let is_call = unsafe { (*analysis).is_call };
    if address != 0 {
        let word = unsafe { ptr::read_unaligned(address as *const u32) };
        if PAC_HINTS.contains(&word) {
            return SKIP_PATCH;
        }
    }
    let mut slot = door();
    let Some(door) = slot.as_mut() else {
        return CONTINUE;
    };
    if let Some((_, resume)) = door.escapes.iter().find(|(at, _)| *at == address) {
        unsafe { (*gpr).pc = *resume };
        return BREAK_TO_VM;
    }
    if door.inst {
        door.events.push(TraceEvent {
            kind: EventKind::Inst,
            pc: address,
            size: inst_size as u16,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
        });
    }
    if door.call && is_call {
        door.events.push(TraceEvent {
            kind: EventKind::Call,
            pc: address,
            size: inst_size as u16,
            mem_addr: 0,
            mem_value: 0,
            is_write: false,
        });
    }
    CONTINUE
}

unsafe extern "C" fn post_inst(
    vm: *mut c_void,
    _gpr: *mut GprState,
    _fpr: *mut FprState,
    _data: *mut c_void,
) -> u32 {
    let mut count = 0usize;
    let accesses = unsafe { qbdi_getInstMemoryAccess(vm, &mut count) };
    if accesses.is_null() || count == 0 {
        return CONTINUE;
    }
    let mut slot = door();
    let Some(door) = slot.as_mut() else {
        return CONTINUE;
    };
    if !door.mem {
        return CONTINUE;
    }
    for index in 0..count {
        let access = unsafe { &*accesses.add(index) };
        door.events.push(TraceEvent {
            kind: EventKind::Mem,
            pc: access.inst_address,
            size: access.size,
            mem_addr: access.access_address,
            mem_value: access.value,
            is_write: access.kind & MEMORY_WRITE != 0,
        });
    }
    CONTINUE
}
