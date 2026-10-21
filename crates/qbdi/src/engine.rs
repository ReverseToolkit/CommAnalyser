//! One-shot function replacement. The first invocation runs in QBDI; later
//! invocations tail-call Gum's original trampoline. Guest execution starts
//! only after the dispatcher has left the guest stack, and the result resumes
//! at the VM's final PC without executing the original function again.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use arch_arm64::writer::CodeWriter;
use qbdi_rs::HostStack;
use runtime::{Error, Result};

use crate::load::{self, GuestRegs};
use crate::session::TraceConfig;

const DISPATCH_STACK_SIZE: usize = 16 << 20;
static TARGET: Mutex<Option<TraceHook>> = Mutex::new(None);
static REAPER: OnceLock<Sender<TraceHook>> = OnceLock::new();

struct TraceState {
    original: u64,
    armed: AtomicBool,
    stack: HostStack,
    resume: Option<ResumeStub>,
}

#[repr(C)]
struct ResumeFrame {
    context: gum_sys::GumCpuContext,
    fpcr: u64,
    fpsr: u64,
}

impl TraceState {
    fn frame(&self) -> *mut ResumeFrame {
        let top = (self.stack.base() as usize + self.stack.size()) & !15;
        (top - std::mem::size_of::<ResumeFrame>()) as *mut ResumeFrame
    }
}

// A direct B into the original instruction preserves x16/x17, which may be
// live at an arbitrary TAL trace_end. An indirect return alone would clobber
// one of them to hold its destination. The page remains live through Gum's
// leave trampoline and is freed only after the reaper's flush succeeds.
struct ResumeStub {
    address: usize,
    target: u64,
    size: usize,
}

impl ResumeStub {
    fn new(target: u64, frame: *mut ResumeFrame) -> Result<Self> {
        let address = usize::try_from(target)
            .map_err(|_| Error::Parse("Trace.function: until does not fit".into()))?;
        let mapping = runtime::maps::self_mapping_containing(address)?
            .ok_or_else(|| Error::Parse("Trace.function: until is not mapped".into()))?;
        if address & 3 != 0 || !mapping.perms.exec {
            return Err(Error::Parse(
                "Trace.function: until must be an aligned code address".into(),
            ));
        }
        let size = runtime::process::page_size();
        let memory = gum::memory::alloc_near(size, address, (1 << 27) - size)
            .map_err(|error| Error::Parse(error.to_string()))?;
        let stub = Self {
            address: memory as usize,
            target,
            size,
        };
        let mut writer = CodeWriter::new();
        writer.bti_jc();
        if !writer.ldr_literal_x(17, 12) {
            return Err(Error::Parse(
                "Trace.function: invalid resume literal".into(),
            ));
        }
        writer.ldp(16, 17, 17, 152);
        let branch = i64::try_from(address)
            .ok()
            .zip(i64::try_from(stub.address + writer.len()).ok())
            .and_then(|(target, pc)| target.checked_sub(pc))
            .ok_or_else(|| Error::Parse("Trace.function: resume branch overflow".into()))?;
        if !writer.b_imm(branch) {
            return Err(Error::Parse(
                "Trace.function: resume branch out of range".into(),
            ));
        }
        writer.put_u64(frame as u64);
        unsafe { ptr::copy_nonoverlapping(writer.bytes().as_ptr(), memory, writer.len()) };
        runtime::patch::flush_icache(stub.address, writer.len());
        gum::memory::protect(stub.address, size, libc::PROT_READ | libc::PROT_EXEC)
            .map_err(|error| Error::Parse(error.to_string()))?;
        Ok(stub)
    }
}

impl Drop for ResumeStub {
    fn drop(&mut self) {
        gum::memory::free(self.address as *mut u8, self.size);
    }
}

struct TraceHook {
    target: usize,
    interceptor: *mut gum_sys::GumInterceptor,
    state: Box<TraceState>,
}

// SAFETY: Gum permits reverting/flushing on another thread. The state has a
// stable address and is freed only after Gum reports all invocations finished.
unsafe impl Send for TraceHook {}

fn lock_target() -> std::sync::MutexGuard<'static, Option<TraceHook>> {
    TARGET.lock().unwrap_or_else(|error| error.into_inner())
}

pub fn install(config: TraceConfig) -> Result<u32> {
    let target = usize::try_from(config.target)
        .map_err(|_| Error::Parse("Trace.function: target does not fit".into()))?;
    if target == 0 {
        return Err(Error::Parse("Trace.function: null target".into()));
    }
    ensure_reaper()?;
    let mut current = lock_target();
    if current.is_some() {
        return Err(Error::Parse(
            "Trace.function: a trace is already armed or running".into(),
        ));
    }
    let stack =
        HostStack::new(DISPATCH_STACK_SIZE).map_err(|error| Error::Parse(error.to_string()))?;
    let mut state = Box::new(TraceState {
        original: 0,
        armed: AtomicBool::new(true),
        stack,
        resume: None,
    });
    if let Some(until) = config.until.filter(|until| *until != 0) {
        state.resume = Some(ResumeStub::new(until, state.frame())?);
    }
    load::prepare(&config)?;
    let _ = gum::Gum::init();
    // SAFETY: Gum is initialized; its obtain reference is owned by TraceHook.
    let interceptor = unsafe { gum_sys::gum_interceptor_obtain() };
    if interceptor.is_null() {
        return Err(Error::Parse(
            "Trace.function: Gum interceptor unavailable".into(),
        ));
    }
    // Zero selects Gum's default instrumentation options.
    let mut options: gum_sys::GumReplaceOptions = unsafe { std::mem::zeroed() };
    options.replacement_data = (&mut *state as *mut TraceState).cast();
    let mut original = ptr::null_mut();
    // Publish the original trampoline before end_transaction makes the redirect
    // executable. A competing replacement is refused, never reverted for us.
    let code = unsafe {
        gum_sys::gum_interceptor_begin_transaction(interceptor);
        let code = gum_sys::gum_interceptor_replace(
            interceptor,
            target as *mut c_void,
            trace_entry as *const () as *mut c_void,
            &mut original,
            &options,
        );
        state.original = original as u64;
        gum_sys::gum_interceptor_end_transaction(interceptor);
        code
    };
    if code != gum_sys::GumReplaceReturn_GUM_REPLACE_OK {
        unsafe { gum_sys::g_object_unref(interceptor.cast()) };
        return Err(Error::Parse(format!(
            "Trace.function: Gum replacement failed ({code})"
        )));
    }
    *current = Some(TraceHook {
        target,
        interceptor,
        state,
    });
    Ok(0)
}

fn ensure_reaper() -> Result<()> {
    if REAPER.get().is_some() {
        return Ok(());
    }
    let (tx, rx) = mpsc::channel::<TraceHook>();
    std::thread::Builder::new()
        .name("trace-reaper".into())
        .spawn(move || {
            for hook in rx {
                // The dispatcher still has to restore registers and return
                // through Gum's leave trampoline. Merely changing threads is
                // not sufficient to make its state or stack safe to free.
                while unsafe {
                    gum_sys::gum_interceptor_flush_function(
                        hook.interceptor,
                        hook.target as *const c_void,
                    )
                } == 0
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                unsafe { gum_sys::g_object_unref(hook.interceptor.cast()) };
                drop(hook.state);
            }
        })
        .map_err(Error::Io)?;
    let _ = REAPER.set(tx);
    Ok(())
}

#[repr(C)]
struct Dispatch {
    context: *mut gum_sys::GumCpuContext,
    state: *const TraceState,
}

// Gum supplies a heap-owned snapshot of the entry registers for replacements.
// Preparing the dispatch uses the guest stack, but returns before QBDI touches
// it. Only the winning invocation uses the session's dedicated dispatch stack.
unsafe extern "C" fn prepare_dispatch() -> Dispatch {
    let invocation = unsafe { gum_sys::gum_interceptor_get_current_invocation() };
    let context = unsafe { (*invocation).cpu_context };
    let state = unsafe {
        &*gum_sys::gum_invocation_context_get_replacement_data(invocation).cast::<TraceState>()
    };
    unsafe { (*context).pc = state.original };
    if !state.armed.swap(false, Ordering::AcqRel) {
        return Dispatch {
            context,
            state: ptr::null(),
        };
    }
    let frame = state.frame();
    // SAFETY: the stack is private to the one winning invocation; this frame
    // remains above the downward-growing Rust dispatcher stack.
    unsafe {
        ptr::copy_nonoverlapping(context, ptr::addr_of_mut!((*frame).context), 1);
        core::arch::asm!(
            "mrs {fpcr}, fpcr",
            "mrs {fpsr}, fpsr",
            fpcr = out(reg)(*frame).fpcr,
            fpsr = out(reg)(*frame).fpsr,
            options(nostack, preserves_flags)
        );
    };
    Dispatch {
        context: frame.cast(),
        state,
    }
}

unsafe extern "C" fn dispatch(context: *mut gum_sys::GumCpuContext, state: *const TraceState) {
    runtime::ffi::guard("Trace.dispatch", || unsafe {
        dispatch_inner(context, &*state)
    });
    let mut current = lock_target();
    if current
        .as_ref()
        .is_some_and(|hook| ptr::eq(&*hook.state, state))
    {
        if let Some(hook) = current.take() {
            // Revert while holding the install lock, then keep the state alive
            // until the reaper observes the current invocation leaving Gum.
            unsafe {
                gum_sys::gum_interceptor_revert(hook.interceptor, hook.target as *mut c_void)
            };
            if let Some(reaper) = REAPER.get() {
                if let Err(error) = reaper.send(hook) {
                    std::mem::forget(error.0);
                }
            } else {
                std::mem::forget(hook);
            }
        }
    }
}

unsafe fn dispatch_inner(context: *mut gum_sys::GumCpuContext, state: &TraceState) {
    let frame = unsafe { &mut *context.cast::<ResumeFrame>() };
    let context = &mut frame.context;
    let start = strip_pac(context.pc);
    let stop = strip_pac(context.lr);
    let mut guest = GuestRegs {
        x: context.x,
        q: std::array::from_fn(|index| u128::from_ne_bytes(unsafe { context.v[index].q })),
        fp: context.fp,
        lr: stop,
        sp: context.sp,
        nzcv: context.nzcv,
        pc: start,
        fpcr: frame.fpcr,
        fpsr: frame.fpsr,
    };
    let result = load::run(&mut guest, start, stop);
    context.x = guest.x;
    context.fp = guest.fp;
    context.lr = guest.lr;
    context.sp = guest.sp;
    context.nzcv = guest.nzcv;
    context.pc = guest.pc;
    frame.fpcr = guest.fpcr;
    frame.fpsr = guest.fpsr;
    if let Some(resume) = state
        .resume
        .as_ref()
        .filter(|resume| resume.target == guest.pc)
    {
        context.pc = resume.address as u64;
    }
    for (vector, value) in context.v.iter_mut().zip(guest.q) {
        vector.q = value.to_ne_bytes();
    }
    if let Err(error) = result {
        eprintln!("[comm-analyser] trace failed: {error}");
    }
}

fn strip_pac(pointer: u64) -> u64 {
    let mut x16 = pointer;
    unsafe {
        core::arch::asm!(".inst 0xdac143f0", inout("x16") x16, options(nostack, preserves_flags));
    }
    x16
}

extern "C" {
    fn trace_entry();
}

// GumCpuContext's AArch64 layout is checked below. The final RET resumes at
// the selected PC (original trampoline or completed VM), preserving stack
// arguments and both return-register banks. x16/x17 are ABI scratch registers.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .type {entry}, %function
{entry}:
    bti c
    bl {prepare}
    cbz x1, 2f
    mov sp, x0
    bl {dispatch}
    mov x0, sp
    ldr x16, [x0, #784]
    msr fpcr, x16
    ldr x16, [x0, #792]
    msr fpsr, x16
2:
    mov x17, x0
    ldr x16, [x17, #8]
    mov sp, x16
    ldr x16, [x17, #16]
    msr nzcv, x16
    ldp q0, q1, [x17, #272]
    ldp q2, q3, [x17, #304]
    ldp q4, q5, [x17, #336]
    ldp q6, q7, [x17, #368]
    ldp q8, q9, [x17, #400]
    ldp q10, q11, [x17, #432]
    ldp q12, q13, [x17, #464]
    ldp q14, q15, [x17, #496]
    ldp q16, q17, [x17, #528]
    ldp q18, q19, [x17, #560]
    ldp q20, q21, [x17, #592]
    ldp q22, q23, [x17, #624]
    ldp q24, q25, [x17, #656]
    ldp q26, q27, [x17, #688]
    ldp q28, q29, [x17, #720]
    ldp q30, q31, [x17, #752]
    ldp x0, x1, [x17, #24]
    ldp x2, x3, [x17, #40]
    ldp x4, x5, [x17, #56]
    ldp x6, x7, [x17, #72]
    ldp x8, x9, [x17, #88]
    ldp x10, x11, [x17, #104]
    ldp x12, x13, [x17, #120]
    ldp x14, x15, [x17, #136]
    ldp x18, x19, [x17, #168]
    ldp x20, x21, [x17, #184]
    ldp x22, x23, [x17, #200]
    ldp x24, x25, [x17, #216]
    ldp x26, x27, [x17, #232]
    ldp x28, x29, [x17, #248]
    ldr x30, [x17, #264]
    ldr x16, [x17, #0]
    .inst 0xdac143f0
    ret x16
    .size {entry}, .-{entry}
"#,
    entry = sym trace_entry,
    prepare = sym prepare_dispatch,
    dispatch = sym dispatch,
);

const _: () = {
    assert!(std::mem::size_of::<ResumeFrame>() == 800);
    assert!(std::mem::size_of::<gum_sys::GumCpuContext>() == 784);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, pc) == 0);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, sp) == 8);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, nzcv) == 16);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, x) == 24);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, fp) == 256);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, lr) == 264);
    assert!(std::mem::offset_of!(gum_sys::GumCpuContext, v) == 272);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_executes_side_effects_once_and_preserves_stack_arguments() {
        let page = runtime::process::page_size();
        // x0 points to a counter. Argument nine is on the caller's stack.
        // The padded prologue gives Gum room to emit its redirect.
        let words = [
            0xd503_245fu32, // bti c
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0xf940_0001, // ldr x1, [x0]
            0x9100_0421, // add x1, x1, #1
            0xf900_0001, // str x1, [x0]
            0xf940_03e2, // ldr x2, [sp]
            0x8b02_0020, // add x0, x1, x2
            0xd65f_03c0, // ret
        ];
        let float_words = [
            0xd503_245fu32,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0x1e61_2800, // fadd d0, d0, d1
            0xd65f_03c0,
        ];
        let resume_words = [
            0xd503_245fu32,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0xd280_0070, // mov x16, #3
            0xd280_00f1, // mov x17, #7
            0x8b11_0200, // add x0, x16, x17 (native resume point)
            0xd65f_03c0,
        ];
        let memory = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        unsafe { ptr::copy_nonoverlapping(words.as_ptr(), memory.cast(), words.len()) };
        let float_address = unsafe { memory.byte_add(64) };
        unsafe {
            ptr::copy_nonoverlapping(
                float_words.as_ptr(),
                float_address.cast(),
                float_words.len(),
            )
        };
        let resume_address = unsafe { memory.byte_add(128) };
        unsafe {
            ptr::copy_nonoverlapping(
                resume_words.as_ptr(),
                resume_address.cast(),
                resume_words.len(),
            )
        };
        runtime::patch::flush_icache(memory as usize, 128 + resume_words.len() * 4);
        assert_eq!(
            unsafe { libc::mprotect(memory, page, libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        type Function =
            unsafe extern "C" fn(*mut u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
        let function: Function = unsafe { std::mem::transmute(memory) };
        let mut count = 0;
        assert_eq!(unsafe { function(&mut count, 0, 0, 0, 0, 0, 0, 0, 40) }, 41);
        assert_eq!(count, 1);
        let mut config = TraceConfig::new(memory as u64);
        // Anonymous executable fixtures have no file-backed module name.
        config.trace_all = true;
        config.events = crate::session::EventMask {
            inst: true,
            mem: false,
            call: false,
        };
        install(config).unwrap();
        assert_eq!(unsafe { function(&mut count, 0, 0, 0, 0, 0, 0, 0, 40) }, 42);
        assert_eq!(
            count, 2,
            "the traced invocation must increment exactly once"
        );
        assert!(!load::take_events().is_empty());
        assert_eq!(unsafe { function(&mut count, 0, 0, 0, 0, 0, 0, 0, 40) }, 43);
        assert_eq!(
            count, 3,
            "later invocations must call the original normally"
        );

        let mut config = TraceConfig::new(memory as u64);
        config.trace_all = true;
        config.until = Some(memory as u64 + 28);
        install(config).unwrap();
        assert_eq!(unsafe { function(&mut count, 0, 0, 0, 0, 0, 0, 0, 40) }, 44);
        assert_eq!(
            count, 4,
            "until must still finish the function exactly once"
        );
        let events = load::take_events();
        assert!(!events.is_empty());
        assert!(!events
            .iter()
            .any(|event| event.kind == crate::EventKind::Inst
                && (memory as u64 + 28..memory as u64 + 40).contains(&event.pc)));

        let mut config = TraceConfig::new(float_address as u64);
        config.trace_all = true;
        install(config).unwrap();
        let float_function: unsafe extern "C" fn(f64, f64) -> f64 =
            unsafe { std::mem::transmute(float_address) };
        assert_eq!(unsafe { float_function(1.25, 2.5) }, 3.75);
        assert!(!load::take_events().is_empty());
        let mut config = TraceConfig::new(resume_address as u64);
        config.trace_all = true;
        config.until = Some(resume_address as u64 + 24);
        install(config).unwrap();
        let resume_function: unsafe extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(resume_address) };
        assert_eq!(
            unsafe { resume_function() },
            10,
            "native resume must preserve live x16/x17"
        );
        assert!(!load::take_events().is_empty());
        // Reverting and flushing must complete before freeing the code fixture.
        if let Some(hook) = lock_target().take() {
            unsafe {
                gum_sys::gum_interceptor_revert(hook.interceptor, hook.target as *mut c_void)
            };
            while unsafe { gum_sys::gum_interceptor_flush_function(hook.interceptor, memory) } == 0
            {
                std::thread::yield_now();
            }
            unsafe { gum_sys::g_object_unref(hook.interceptor.cast()) };
        }
        unsafe { libc::munmap(memory, page) };
    }
}
