//! The QBDI trace session: one VM, one host stack, one event sink.
//!
//! The VM and its callbacks come from `qbdi-rs`; this module owns the
//! CommAnalyser policy: what to instrument, when to break out of the VM, and
//! what to record while the guest runs.
//!
//! Two rules keep the callbacks usable:
//!
//! - no module enumeration per instruction. Module names come from a snapshot
//!   taken when the session is prepared. Event text is formatted on demand;
//!   symbols are resolved lazily per module.
//! - no locking per callback.  A trace is exclusive (see [Busy]), so the
//!   callbacks reach the session through a thread-local pointer owned by
//!   [run].

// The trace door is what calls into this module; without it the session is
// unreachable and the compiler cannot see the use.
#![cfg_attr(not(feature = "vm"), allow(dead_code))]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use qbdi_rs::{
    Action, AnalysisType, FloatRegisters, HostStack, InstAnalysis, InstContext, InstPosition,
    MemoryAccessType, Reg, RegisterAccess, Registers, Vm, VmContext, VmEvent,
};
use runtime::{Error, Result};

use crate::blacklist;
use crate::policy::{self, InstKind};
use crate::ring::{EventRing, TraceEvent};
use crate::session::{PrintMode, TraceConfig};
use crate::symbols::Symbols;

const PRIORITY_POST: i32 = 10;
const PRIORITY_MEM: i32 = -10;
const VM_STACK: usize = 16 << 20;
const PRINTABLE_SIZE: i32 = 4;

/// Guest registers copied into QBDI before the run and back afterwards.
pub struct GuestRegs {
    pub x: [u64; 29],
    pub q: [u128; 32],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub pc: u64,
    pub fpcr: u64,
    pub fpsr: u64,
}

/// Where an address lives, captured when the session is prepared.
#[derive(Clone)]
struct Place {
    name: Arc<str>,
    path: Arc<str>,
    base: u64,
}

struct Segment {
    start: u64,
    end: u64,
    place: Place,
}

/// Immutable snapshot of the process module layout.
///
/// Modules can load and unload while a trace runs.  A snapshot makes the
/// callback path allocation-free and syscall-free; events are labelled with
/// the layout that was current when the trace started, which is what a trace
/// describes anyway.
struct ModuleIndex {
    segments: Vec<Segment>,
}

impl ModuleIndex {
    fn snapshot() -> Result<Self> {
        // Without the module layout, call events lose their module names and
        // the lookup silently labels everything with a raw address.  A trace
        // is not worth starting in that state.
        let modules = runtime::module::enumerate()?;
        let mut segments = Vec::new();
        for module in modules {
            let place = Place {
                name: Arc::from(module.name.as_str()),
                path: Arc::from(module.path.as_str()),
                base: module.base as u64,
            };
            for range in &module.ranges {
                segments.push(Segment {
                    start: range.start as u64,
                    end: range.end as u64,
                    place: place.clone(),
                });
            }
        }
        segments.sort_unstable_by_key(|segment| segment.start);
        Ok(Self { segments })
    }

    fn lookup(&self, address: u64) -> Option<&Place> {
        let after = self.segments.partition_point(|segment| segment.start <= address);
        let segment = self.segments.get(after.checked_sub(1)?)?;
        (address < segment.end).then_some(&segment.place)
    }
}

/// The live trace session.
struct Door {
    /// Boxed so the address survives a move of the session.
    vm: Box<Vm>,
    /// Boxed for the same reason.
    stack: Box<HostStack>,
    index: ModuleIndex,
    ring: EventRing,
    trace_end: u64,
    inst: bool,
    mem: bool,
    call: bool,
    kind: InstKind,
    mode: PrintMode,
    printable: i32,
    inst_path: Arc<str>,
    reads: Vec<i16>,
    writes: Vec<i16>,
    last_inst: bool,
    symbols: Symbols,
}

static DOOR: Mutex<Option<Door>> = Mutex::new(None);

fn door() -> std::sync::MutexGuard<'static, Option<Door>> {
    DOOR.lock().unwrap_or_else(|error| error.into_inner())
}

thread_local! {
    /// The session [run] is currently executing on this thread.
    static CURRENT: Cell<*mut Door> = const { Cell::new(std::ptr::null_mut()) };
}

fn current() -> Option<*mut Door> {
    CURRENT.with(|slot| {
        let pointer = slot.get();
        (!pointer.is_null()).then_some(pointer)
    })
}

/// One trace at a time: the VM, the host stack and the event ring are single
/// instances, and QBDI callbacks run on the guest thread.
static BUSY: AtomicBool = AtomicBool::new(false);

struct Busy;

impl Busy {
    fn acquire() -> Result<Self> {
        if BUSY.swap(true, Ordering::AcqRel) {
            return Err(Error::Parse(
                "Trace.function: a trace is already running".into(),
            ));
        }
        Ok(Self)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

fn map_error(error: qbdi_rs::Error) -> Error {
    Error::Parse(error.to_string())
}

/// Create the VM, instrument it, and register the trace callbacks.
pub fn prepare(config: &TraceConfig) -> Result<()> {
    if !config.escapes.is_empty() {
        // `CheckAndBreak` needs the private ExecBlock shim and a register
        // write-back design that is not validated yet.
        return Err(Error::Unsupported(
            "Trace.function: escape breakpoints are not enabled",
        ));
    }
    if BUSY.load(Ordering::Acquire) {
        return Err(Error::Parse(
            "Trace.function: cannot replace a session while it is running".into(),
        ));
    }
    // Snapshot before touching the live session so a failure leaves it intact.
    let index = ModuleIndex::snapshot()?;
    let mut vm = Vm::new().map_err(map_error)?;
    vm.add_code_callback(InstPosition::Pre, 0, on_pre_inst)
        .map_err(map_error)?;
    vm.add_code_callback(InstPosition::Post, PRIORITY_POST, on_post_inst)
        .map_err(map_error)?;
    vm.add_vm_event_callback(VmEvent::EXEC_TRANSFER_CALL, on_transfer_call)
        .map_err(map_error)?;
    vm.add_vm_event_callback(VmEvent::EXEC_TRANSFER_RETURN, |_| Action::Continue)
        .map_err(map_error)?;
    vm.add_vm_event_callback(VmEvent::BASIC_BLOCK_NEW, |_| Action::Continue)
        .map_err(map_error)?;
    if config.events.mem {
        vm.add_mem_access_callback(MemoryAccessType::READ_WRITE, PRIORITY_MEM, on_memory_access)
            .map_err(map_error)?;
    }
    // The pinned QBDI has no blacklist mode: choose the instrumented set
    // explicitly. `trace_all` covers every executable map, then subtracts the
    // avoid ranges; the per-function mode instruments the target's module.
    if config.trace_all {
        if !vm.instrument_all_executable_maps() {
            return Err(Error::Parse(
                "Trace.function: instrumenting every executable map failed".into(),
            ));
        }
        for &(start, end) in &config.avoid {
            vm.remove_instrumented_range(start, end);
        }
    } else if !vm.add_instrumented_module_from_addr(config.target) {
        return Err(Error::Parse(
            "Trace.function: target is not in an executable module".into(),
        ));
    }
    remove_conflict_module(&vm, &config.extra_exclude);
    let stack = HostStack::new(VM_STACK).map_err(map_error)?;
    let mut slot = door();
    if let Some(previous) = slot.take() {
        // Terminates the old VM and frees its stack.
        drop(previous);
    }
    *slot = Some(Door {
        vm: Box::new(vm),
        stack: Box::new(stack),
        index,
        ring: EventRing::new(config.max_events.max(1)),
        trace_end: config.trace_end(),
        inst: config.events.inst,
        mem: config.events.mem,
        call: config.events.call,
        kind: InstKind::None,
        mode: config.mode,
        printable: if config.mode == PrintMode::Bin {
            0
        } else {
            PRINTABLE_SIZE
        },
        inst_path: Arc::from(""),
        reads: Vec::new(),
        writes: Vec::new(),
        last_inst: false,
        symbols: Symbols::default(),
    });
    Ok(())
}

/// Copy the guest registers into the VM, run from `start` until `stop`, then
/// copy the resulting registers and floating point state back into `regs`.
pub fn run(regs: &mut GuestRegs, start: u64, fallback_stop: u64) -> Result<()> {
    let _busy = Busy::acquire()?;
    let mut slot = door();
    let door = slot
        .as_mut()
        .ok_or_else(|| Error::Parse("QBDI VM is not prepared".into()))?;
    // TAL's trace_end transfers back to native execution at that address.
    // Returning STOP through QBDI first lets Rust release its session guards
    // before the door restores the guest registers and resumes there.
    // The pre-instruction callback stops at trace_end. Always retain the
    // caller's return address as a stop too, in case trace_end is not reached.
    let stop = fallback_stop;
    let door: *mut Door = door;
    // SAFETY: both boxes are owned by the session, which cannot be replaced
    // while `_busy` is held; the borrows end before the callbacks run.
    let (vm, stack) = unsafe { (&*(*door).vm as *const Vm, &*(*door).stack as *const HostStack) };
    let (vm, stack) = unsafe { (&*vm, &*stack) };
    // Gum's relocated prologue lives outside the original module. Starting
    // there bypasses the replacement and executes each original instruction
    // once before entering the instrumented module body.
    let page = runtime::process::page_size() as u64;
    let trampoline_page = start & !(page - 1);
    vm.add_instrumented_range(trampoline_page.into(), (trampoline_page + page).into())
        .map_err(map_error)?;
    set_registers(vm, regs);
    CURRENT.with(|cell| cell.set(door));
    let result = runtime::ffi::guard("Trace.run", || run_on_stack(vm, stack, start, stop))
        .unwrap_or_else(|| Err(Error::Parse("QBDI trace panicked".into())));
    CURRENT.with(|cell| cell.set(std::ptr::null_mut()));
    copy_back(vm, regs);
    // Do not touch `door` here: the callbacks created references from it.
    result
}

fn set_registers(vm: &Vm, regs: &GuestRegs) {
    let mut state = Registers::default();
    state.set_x(&regs.x);
    state.set(Reg::Fp, regs.fp);
    state.set(Reg::Lr, regs.lr);
    state.set(Reg::Sp, regs.sp);
    state.set(Reg::Nzcv, regs.nzcv);
    state.set(Reg::Pc, regs.pc);
    vm.set_registers(&state);
    let mut floats = FloatRegisters::default();
    for (index, value) in regs.q.iter().enumerate() {
        floats.set(index, *value);
    }
    floats.set_fpcr(regs.fpcr);
    floats.set_fpsr(regs.fpsr);
    vm.set_floats(&floats);
}

fn copy_back(vm: &Vm, regs: &mut GuestRegs) {
    if let Some(state) = vm.registers() {
        regs.x = state.x();
        regs.fp = state.get(Reg::Fp);
        regs.lr = state.get(Reg::Lr);
        regs.sp = state.get(Reg::Sp);
        regs.nzcv = state.get(Reg::Nzcv);
        regs.pc = state.get(Reg::Pc);
    }
    if let Some(after) = vm.floats() {
        regs.fpcr = after.fpcr();
        regs.fpsr = after.fpsr();
        for (index, value) in regs.q.iter_mut().enumerate() {
            *value = after.get(index);
        }
    }
}

/// The events the last traced call produced.
pub fn take_events() -> Vec<TraceEvent> {
    take_batch().0
}

/// The batch and how many events the ring dropped, read atomically so a
/// script cannot pair one trace's events with another trace's drop count.
pub fn take_batch() -> (Vec<TraceEvent>, u64) {
    door()
        .as_mut()
        .map(|door| {
            // The post-instruction pass refers to the last event; dropping the
            // batch must not leave that flag behind.
            door.last_inst = false;
            (door.ring.drain(), door.ring.dropped())
        })
        .unwrap_or_default()
}

/// How many events the ring discarded because it was full.
pub fn dropped_events() -> u64 {
    door().as_ref().map(|door| door.ring.dropped()).unwrap_or(0)
}

fn run_on_stack(vm: &Vm, stack: &HostStack, start: u64, stop: u64) -> Result<()> {
    if !stack.run(vm, start, stop) {
        return Err(Error::Parse("qbdi_run returned false".into()));
    }
    Ok(())
}

/// Drop the executable maps that must not be instrumented.
fn remove_conflict_module(vm: &Vm, extra: &[String]) {
    for map in vm.process_maps(false) {
        let Some(name) = map.name() else {
            continue;
        };
        if !map.permission().is_exec() {
            continue;
        }
        if blacklist::is_excluded(name, extra) {
            vm.remove_instrumented_range(map.start(), map.end());
        }
    }
}

/// The session installed by [run] on this thread.
fn session() -> Option<*mut Door> {
    current()
}

fn on_pre_inst(context: &mut InstContext<'_>) -> Action {
    // SAFETY: QBDI invokes callbacks on the thread that owns the session.
    let Some(pointer) = session() else {
        return Action::Continue;
    };
    // SAFETY: the pointer is installed by run() on this thread and outlives the callback.
    let door = unsafe { &mut *pointer };
    let Some(analysis) = context.vm().analysis(AnalysisType::TRACE) else {
        return Action::Continue;
    };
    let address = analysis.address();
    if door.trace_end != 0 && address == door.trace_end {
        door.last_inst = false;
        context.registers.set(Reg::Pc, address);
        return Action::Stop;
    }
    let kind = policy::classify(
        analysis.is_call(),
        analysis.is_return(),
        analysis.is_branch(),
        analysis.is_predicable(),
    );
    door.kind = kind;
    if door.call {
        door.inst_path = door
            .index
            .lookup(address)
            .map(|place| place.path.clone())
            .unwrap_or_else(|| Arc::from(""));
    }
    if !door.inst {
        door.last_inst = false;
        return Action::Continue;
    }
    let (reads, writes) = split_regs(&analysis);
    let mut text = inst_text(&door.index, address, &analysis);
    let read_text = fmt_regs(context.registers, &reads);
    if !read_text.is_empty() {
        text.push(' ');
        text.push_str(&read_text);
    }
    if door.mode == PrintMode::Bin {
        text.push_str(&inst_bytes(address, analysis.size()));
    }
    let size = u16::try_from(analysis.size()).unwrap_or(u16::MAX);
    // Only a stored event can receive the post-instruction register suffix.
    door.last_inst = door.ring.push(TraceEvent::inst(address, size, text));
    door.reads = reads;
    door.writes = writes;
    Action::Continue
}

fn on_post_inst(context: &mut InstContext<'_>) -> Action {
    let target = context.registers.get(Reg::Pc);
    let sp = context.registers.get(Reg::Sp);
    let args = context.registers.args();
    // SAFETY: same thread and session as on_pre_inst.
    let Some(pointer) = session() else {
        return Action::Continue;
    };
    // SAFETY: installed by run() on this thread, valid for the callback.
    let door = unsafe { &mut *pointer };
    if door.last_inst {
        let extra = fmt_regs(context.registers, &door.writes);
        if !extra.is_empty() {
            if let Some(last) = door.ring.last_mut() {
                last.text.push(' ');
                last.text.push_str(&extra);
            }
        }
    }
    if door.mode == PrintMode::Bin || !door.call || !matches!(door.kind, InstKind::Call | InstKind::Jmp) {
        return Action::Continue;
    }
    let Some(place) = door.index.lookup(target).cloned() else {
        return Action::Continue;
    };
    if door.kind == InstKind::Jmp && place.path == door.inst_path {
        return Action::Continue;
    }
    let offset = target.wrapping_sub(place.base);
    let symbol = door
        .symbols
        .resolve(&place.path, place.base, target)
        .unwrap_or_else(|| format!("{offset:#x}"));
    let mut text = format!("call {}:{} base:{:#x}", place.name, symbol, place.base);
    if door.mode == PrintMode::TraceArgs {
        text.push('\n');
        text.push_str(&crate::args::format_call(&symbol, &args, sp));
    }
    let _ = door.ring.push(TraceEvent::call(target, text));
    Action::Continue
}

fn on_memory_access(context: &mut InstContext<'_>) -> Action {
    // SAFETY: same thread and session as on_pre_inst.
    let Some(pointer) = session() else {
        return Action::Continue;
    };
    // SAFETY: installed by run() on this thread, valid for the callback.
    let door = unsafe { &mut *pointer };
    if !door.mem || door.mode == PrintMode::Bin || door.kind == InstKind::Call {
        return Action::Continue;
    }
    let printable = door.printable;
    for access in context.vm().memory_accesses() {
        let text = if printable == 0 {
            String::new()
        } else {
            // SAFETY: the guest just accessed this address, so it is mapped.
            unsafe { policy::printable_text(access.address(), printable) }.unwrap_or_default()
        };
        let _ = door.ring.push(TraceEvent::mem(
            access.instruction_address(),
            access.size(),
            access.address(),
            access.value(),
            access.is_write(),
            text,
        ));
    }
    Action::Continue
}

fn on_transfer_call(context: &mut VmContext<'_>) -> Action {
    // SAFETY: same thread and session as on_pre_inst.
    let Some(pointer) = session() else {
        return Action::Continue;
    };
    // SAFETY: installed by run() on this thread, valid for the callback.
    let door = unsafe { &mut *pointer };
    if !door.call || door.mode != PrintMode::Debug {
        return Action::Continue;
    }
    let pc = context.registers.get(Reg::Pc);
    let at = match door.index.lookup(pc) {
        Some(place) => format!("{}:{:#x}", place.name, pc.wrapping_sub(place.base)),
        None => format!("{pc:#x}"),
    };
    let disasm = crate::disasm::disassemble(pc).unwrap_or_default();
    let _ = door.ring.push(TraceEvent::call(
        pc,
        format!("transfer call {pc:#x}:{disasm}\ncall {at}"),
    ));
    Action::Continue
}

fn inst_text(index: &ModuleIndex, address: u64, analysis: &InstAnalysis<'_>) -> String {
    let at = match index.lookup(address) {
        Some(place) => format!("{}:{:#x}", place.name, address.wrapping_sub(place.base)),
        None => format!("{address:#x}"),
    };
    match analysis.disassembly() {
        Some(disassembly) if !disassembly.is_empty() => format!("{at} {disassembly}"),
        _ => at,
    }
}

fn split_regs(analysis: &InstAnalysis<'_>) -> (Vec<i16>, Vec<i16>) {
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for operand in analysis.operands() {
        let Some(index) = operand.register_index() else {
            continue;
        };
        match operand.access() {
            RegisterAccess::Read => reads.push(index),
            RegisterAccess::Write => writes.push(index),
            RegisterAccess::ReadWrite => writes.push(index),
            RegisterAccess::Unused => {}
        }
    }
    (reads, writes)
}

fn fmt_regs(registers: &Registers, indexes: &[i16]) -> String {
    indexes
        .iter()
        .rev()
        .filter_map(|index| {
            let reg = Reg::from_index(*index)?;
            Some(format!("{}={:#x}", reg.name(), registers.get(reg)))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn inst_bytes(addr: u64, size: u32) -> String {
    let size = size as usize;
    if size == 0 || size > 16 {
        return String::new();
    }
    let ptr = addr as *const u8;
    let mut text = String::from("(");
    for index in 0..size {
        let byte = unsafe { ptr.add(index).read_unaligned() };
        text.push_str(&format!("{byte:02x}"));
    }
    text.push(')');
    text
}
