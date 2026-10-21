//! ART ScopedObjectAccess window.
//!
//! Frida recompiles `JNI::ExceptionClear` to run a callback while its
//! `ScopedObjectAccess` is alive.  We take a smaller step: patch the single
//! `str xzr, [thread, #exception]` instruction that clears the pending
//! exception.  At that point ART has already transitioned the thread to
//! Runnable and holds the mutator lock, which is exactly what AddGlobalRef
//! needs.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use arch_arm64::writer::CodeWriter;
use runtime::{Error, Result};

const PAGE: usize = 0x1000;
const EXCEPTION_CLEAR_VTABLE_INDEX: usize = 17;
const MAX_BRANCH: isize = 0x07FF_FFFF;

type ExceptionClear = unsafe extern "C" fn(*mut jni::sys::JNIEnv);
type AddGlobalRef =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> jni::sys::jobject;

thread_local! {
    static PENDING_RAW: Cell<usize> = const { Cell::new(0) };
    static CONVERTED_GLOBAL: Cell<usize> = const { Cell::new(0) };
    static ACTION: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

static TARGET: AtomicUsize = AtomicUsize::new(0);
static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
static STORE: AtomicUsize = AtomicUsize::new(0);
static CALLED: AtomicUsize = AtomicUsize::new(0);

/// Runs inside the patched `JNI::ExceptionClear`, while ART holds the
/// mutator lock.
///
/// The pending exception is cleared by the trampoline itself, using the
/// offset decoded from the instruction being replaced -- this callback never
/// assumes a Thread layout, so the `0x98` Android-15 constant is gone.
fn callback(thread: usize) {
    // Panicking here would unwind through a hand-written ARM64 frame with no
    // unwind information.
    runtime::ffi::guard("SOA callback", || {
        CALLED.fetch_add(1, Ordering::Relaxed);
        if let Some(action) = ACTION.with(|slot| slot.borrow_mut().take()) {
            action();
        }
        convert_pending(thread);
    });
}

fn convert_pending(thread: usize) {
    let raw = PENDING_RAW.with(Cell::get);
    if raw == 0 {
        return;
    }
    let Some(add) = add_global_ref() else {
        return;
    };
    let Some(vm) = crate::java::JavaVm::get().ok() else {
        return;
    };
    // SAFETY: SOA guarantees a Runnable thread and the raw reference belongs
    // to the current managed frame.
    let global = unsafe {
        add(
            vm.vm_raw() as *mut c_void,
            thread as *mut c_void,
            raw as *mut c_void,
        )
    };
    CONVERTED_GLOBAL.with(|slot| slot.set(global as usize));
}

/// Turn a quick-ABI raw object pointer into a global JNI reference by invoking
/// `JNI::ExceptionClear` and intercepting its SOA-protected clear.
pub fn words() -> Vec<u32> {
    let target = TARGET.load(Ordering::Relaxed);
    if target == 0 {
        return Vec::new();
    }
    let Some(count) = readable_words(target, 256) else {
        return Vec::new();
    };
    // SAFETY: count is bounded by the mapping that contains target.
    unsafe { std::slice::from_raw_parts(target as *const u32, count).to_vec() }
}

/// How many whole words can be read from `address` without leaving its
/// mapping.  Diagnostic reads used to walk a fixed 1 KiB window and could
/// fault on the last page of libart.
fn readable_words(address: usize, want: usize) -> Option<usize> {
    let mapping = runtime::maps::self_mapping_containing(address).ok()??;
    let available = (mapping.range.end.saturating_sub(address)) / 4;
    (available > 0).then(|| available.min(want))
}

type DecodeGlobalJObject = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type CurrentThread = unsafe extern "C" fn() -> *mut c_void;

/// Turn a JNI global reference back into a quick-ABI raw object pointer.
///
/// Runs on the hooking Java thread, which is Runnable at this point.
pub fn global_to_raw(handle: usize) -> Result<usize> {
    if handle == 0 {
        return Ok(0);
    }
    let decode_address = resolve_libart_symbol("_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject")
        .ok_or_else(|| Error::NotFound("Thread::DecodeGlobalJObject".into()))?;
    let current_address = resolve_libart_symbol("_ZN3art6Thread14CurrentFromGdbEv")
        .ok_or_else(|| Error::NotFound("Thread::Current".into()))?;
    // SAFETY: both addresses come from libart's dynamic symbol table.
    let decode: DecodeGlobalJObject = unsafe { std::mem::transmute(decode_address) };
    let current: CurrentThread = unsafe { std::mem::transmute(current_address) };
    let thread = unsafe { current() };
    if thread.is_null() {
        return Err(Error::NotFound("current ART thread".into()));
    }
    // SAFETY: thread is current and handle is a live global reference.
    let raw = unsafe { decode(thread, handle as *mut c_void) };
    if raw.is_null() {
        return Err(Error::Parse("DecodeGlobalJObject returned null".into()));
    }
    Ok(raw as usize)
}

pub fn debug_state() -> (usize, usize, usize, usize, usize) {
    (
        TARGET.load(Ordering::Relaxed),
        STORE.load(Ordering::Relaxed),
        TRAMPOLINE.load(Ordering::Relaxed),
        CALLED.load(Ordering::Relaxed),
        CONVERTED_GLOBAL.with(Cell::get),
    )
}

fn trigger() -> Result<()> {
    install()?;
    let target = TARGET.load(Ordering::Acquire);
    if target == 0 {
        return Err(Error::NotFound("ExceptionClear target".into()));
    }
    // Force the exception path before invoking the patched clear.  The jni
    // wrapper catches the exception afterwards, but ThrowNew has already made
    // ExceptionClear take its pending-exception path.
    let _ = crate::java::JavaVm::get()?.with_env(|env| {
        let class = jni::strings::JNIString::from("java/lang/RuntimeException");
        let message = jni::strings::JNIString::from("CommAnalyser SOA");
        let _ = env.throw_new(class, message);
        Ok(())
    });
    // SAFETY: the vtable entry is JNI::ExceptionClear for this process.
    let exception_clear: ExceptionClear = unsafe { std::mem::transmute(target) };
    let vm = crate::java::JavaVm::get()?;
    vm.with_env(|env| {
        // SAFETY: JNIEnv is valid and the patched function only adds one
        // callback around its exception store.
        unsafe { exception_clear(env.get_raw()) };
        Ok(())
    })?;
    Ok(())
}

/// Run a closure while the current thread is inside ART's ScopedObjectAccess.
pub fn with_soa(f: impl FnOnce() + 'static) -> Result<()> {
    ACTION.with(|slot| *slot.borrow_mut() = Some(Box::new(f)));
    trigger()?;
    if ACTION.with(|slot| slot.borrow().is_some()) {
        ACTION.with(|slot| *slot.borrow_mut() = None);
        return Err(Error::Parse("SOA action did not run".into()));
    }
    Ok(())
}

pub fn convert(raw: usize) -> Result<usize> {
    if raw == 0 {
        return Ok(0);
    }
    PENDING_RAW.with(|slot| slot.set(raw));
    CONVERTED_GLOBAL.with(|slot| slot.set(0));
    trigger()?;
    PENDING_RAW.with(|slot| slot.set(0));
    let global = CONVERTED_GLOBAL.with(Cell::get);
    if global == 0 {
        return Err(Error::Parse("SOA conversion did not run".into()));
    }
    Ok(global)
}

pub fn install() -> Result<()> {
    // Cache success only: a failure during an early probe (plain JavaVM not
    // ready yet) must not poison every later conversion.
    static INSTALLED: Mutex<Option<()>> = Mutex::new(None);
    let mut installed = INSTALLED.lock().unwrap_or_else(|error| error.into_inner());
    if installed.is_some() {
        return Ok(());
    }
    install_inner()?;
    *installed = Some(());
    Ok(())
}

fn install_inner() -> Result<()> {
    let target = crate::java::JavaVm::get()?
        .with_env(|env| {
            // SAFETY: JNIEnv points at the standard JNI function table.
            let table = unsafe { *(env.get_raw() as *mut *const usize) };
            if table.is_null() {
                return Err(jni::errors::Error::NullPtr("JNIEnv table"));
            }
            // SAFETY: the standard table has at least 18 entries.
            let entry = unsafe { *table.add(EXCEPTION_CLEAR_VTABLE_INDEX) };
            Ok(entry)
        })
        .map_err(|error| Error::Parse(format!("ExceptionClear: {error}")))?;
    if target == 0 {
        return Err(Error::NotFound("ExceptionClear".into()));
    }
    TARGET.store(target, Ordering::Release);
    let (store, base, offset) = find_exception_store(target)?;
    let trampoline = alloc_near(store)?;
    let mut w = CodeWriter::with_capacity(256);
    emit_trampoline(&mut w, base, offset, store + 4, trampoline);
    // SAFETY: alloc_near returned a writable page of PAGE bytes.
    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), trampoline as *mut u8, w.len());
    }
    runtime::patch::flush_icache(trampoline, w.len());
    if unsafe { libc::mprotect(trampoline as *mut c_void, PAGE, libc::PROT_READ | libc::PROT_EXEC) }
        != 0
    {
        let error = std::io::Error::last_os_error();
        // SAFETY: trampoline is the mapping allocated above.
        unsafe { libc::munmap(trampoline as *mut c_void, PAGE) };
        return Err(Error::Io(error));
    }

    let branch = (trampoline as isize) - (store as isize);
    if !(-MAX_BRANCH..=MAX_BRANCH).contains(&branch) {
        // SAFETY: trampoline is the mapping allocated above and not yet used.
        unsafe { libc::munmap(trampoline as *mut c_void, PAGE) };
        return Err(Error::Unsupported("ExceptionClear branch out of range"));
    }
    let mut patch = CodeWriter::with_capacity(4);
    if !patch.b_imm(branch as i64) {
        return Err(Error::Unsupported("ExceptionClear branch encoding"));
    }
    // Restore whatever protection libart's text actually has; asking for RWX on
    // a file-backed executable page is exactly what hardened Android rejects.
    runtime::patch::with_writable(store, 4, || {
        // SAFETY: with_writable verified the range and made it writable.
        unsafe { ptr::copy_nonoverlapping(patch.bytes().as_ptr(), store as *mut u8, 4) };
    })?;
    TARGET.store(target, Ordering::Release);
    STORE.store(store, Ordering::Release);
    TRAMPOLINE.store(trampoline, Ordering::Release);
    Ok(())
}

fn find_exception_store(target: usize) -> Result<(usize, u8, u32)> {
    let count = readable_words(target, 256)
        .ok_or_else(|| Error::NotFound("ExceptionClear is not mapped".into()))?;
    // SAFETY: count is bounded by the mapping that contains target.
    let words = unsafe { std::slice::from_raw_parts(target as *const u32, count) };
    for (index, word) in words.iter().enumerate() {
        // STR (immediate, unsigned offset), 64-bit, Rt == XZR.
        if word & 0xFFC0_0000 != 0xF900_0000 || word & 0x1F != 31 {
            continue;
        }
        let base = ((word >> 5) & 0x1F) as u8;
        let offset = ((word >> 10) & 0xFFF) * 8;
        if base == 31 || offset > 0x800 {
            continue;
        }
        return Ok((target + index * 4, base, offset));
    }
    Err(Error::NotFound("ExceptionClear str xzr".into()))
}

fn emit_trampoline(w: &mut CodeWriter, base: u8, offset: u32, resume: usize, trampoline: usize) {
    w.sub_sp(160);
    for index in 0..9u8 {
        w.stp(index * 2, index * 2 + 1, 31, (index as i64) * 16);
    }
    w.stp(18, 30, 31, 144);
    if base == 31 {
        w.put(0x9100_03E0); // add x0, sp, #0
    } else {
        w.put(0xAA00_03E0 | ((base as u32) << 16)); // mov x0, xN
    }
    // Clear the pending exception with the offset decoded from the replaced
    // instruction, before the callback asks ART for anything.  This is the
    // store the patch displaced; reusing its operands removes the last
    // hard-coded Thread layout constant.
    w.str_imm(31, base, offset);
    w.abs_bl(callback as *const () as usize);
    for index in 0..9u8 {
        w.ldp(index * 2, index * 2 + 1, 31, (index as i64) * 16);
    }
    w.ldp(18, 30, 31, 144);
    w.add_sp(160);
    w.abs_b(resume);
    let _ = trampoline;
}

fn alloc_near(target: usize) -> Result<usize> {
    for delta in (0x0100_0000..=0x0700_0000).step_by(0x0010_0000) {
        for direction in [1isize, -1isize] {
            let hint = (target as isize + direction * delta) as usize;
            let page = hint & !(PAGE - 1);
            let address = unsafe {
                libc::mmap(
                    page as *mut c_void,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x100000,
                    -1,
                    0,
                )
            };
            if address != libc::MAP_FAILED {
                return Ok(address as usize);
            }
        }
    }
    Err(Error::Unsupported("no near page for ExceptionClear"))
}

fn add_global_ref() -> Option<AddGlobalRef> {
    static SYMBOL: OnceLock<Option<usize>> = OnceLock::new();
    let address = (*SYMBOL.get_or_init(|| {
        resolve_libart_symbol(
            "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE",
        )
    }))?;
    // SAFETY: address comes from libart's dynamic symbol table.
    let function: AddGlobalRef = unsafe { std::mem::transmute(address) };
    Some(function)
}

fn resolve_libart_symbol(name: &str) -> Option<usize> {
    let base = crate::libart_base().ok()?;
    for path in [
        "/apex/com.android.art/lib64/libart.so",
        "/system/lib64/libart.so",
    ] {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(elf) = goblin::elf::Elf::parse(&bytes) else {
            continue;
        };
        let Some(symbol) = elf
            .dynsyms
            .iter()
            .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(name))
        else {
            continue;
        };
        if symbol.st_value != 0 {
            return Some(base + symbol.st_value as usize);
        }
    }
    None
}
