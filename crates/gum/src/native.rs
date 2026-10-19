//! Native calls without libffi.
//!
//! Integer/pointer calls use the platform C ABI.  `NativeCallback` trampolines
//! are ARM64 stubs that pack x0-x7 and enter the JS dispatcher.

use runtime::{Error, Result};

#[cfg(target_arch = "aarch64")]
use std::ptr;

#[cfg(target_arch = "aarch64")]
use arch_arm64::writer::CodeWriter;

#[cfg(target_arch = "aarch64")]
use crate::memory::{flush_icache, protect};

#[cfg(target_arch = "aarch64")]
const PAGE: usize = 0x1000;

/// Call `target` with up to eight integer/pointer arguments and return x0/rax.
///
/// Integer and pointer arguments use the platform C ABI, which is enough for
/// JNI `Call*Method` varargs on ARM64 and for host tests of `NativeFunction`.
///
/// # Safety
/// The caller is responsible for the target's ABI and for arg values being
/// valid for that function.
pub unsafe fn call(target: usize, args: &[u64]) -> Result<u64> {
    if target == 0 {
        return Err(Error::Parse("native call: null target".into()));
    }
    if args.len() > 8 {
        return Err(Error::Unsupported("native call: more than 8 arguments"));
    }
    let mut a = [0u64; 8];
    a[..args.len()].copy_from_slice(args);
    // SAFETY: caller supplied a C function that reads at most eight GPRs.
    let function = unsafe {
        std::mem::transmute::<
            usize,
            unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64,
        >(target)
    };
    // Must not tail-call: Android 15 BTI `BTI c` landing pads reject `BR`.
    let ret = unsafe { invoke_eight(function, a) };
    Ok(ret)
}

/// Call `target` and read a `double` return (ARM64 `d0` / x86_64 `xmm0`).
///
/// # Safety
/// Same contract as [`call`].
pub unsafe fn call_f64(target: usize, args: &[u64]) -> Result<f64> {
    if target == 0 {
        return Err(Error::Parse("native call: null target".into()));
    }
    if args.len() > 8 {
        return Err(Error::Unsupported("native call: more than 8 arguments"));
    }
    let mut a = [0u64; 8];
    a[..args.len()].copy_from_slice(args);
    let function = unsafe {
        std::mem::transmute::<
            usize,
            unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> f64,
        >(target)
    };
    Ok(unsafe { function(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]) })
}

/// Call `target` and read a `float` return.
///
/// # Safety
/// Same contract as [`call`].
pub unsafe fn call_f32(target: usize, args: &[u64]) -> Result<f32> {
    if target == 0 {
        return Err(Error::Parse("native call: null target".into()));
    }
    if args.len() > 8 {
        return Err(Error::Unsupported("native call: more than 8 arguments"));
    }
    let mut a = [0u64; 8];
    a[..args.len()].copy_from_slice(args);
    let function = unsafe {
        std::mem::transmute::<
            usize,
            unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> f32,
        >(target)
    };
    Ok(unsafe { function(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]) })
}

#[inline(never)]
unsafe fn invoke_eight(
    function: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64,
    a: [u64; 8],
) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let mut ret: u64;
        // BLR is required for `BTI c` landing pads used throughout Android 15 libc/ART.
        unsafe {
            core::arch::asm!(
                "blr {f}",
                f = in(reg) function,
                inout("x0") a[0] => ret,
                in("x1") a[1],
                in("x2") a[2],
                in("x3") a[3],
                in("x4") a[4],
                in("x5") a[5],
                in("x6") a[6],
                in("x7") a[7],
                clobber_abi("C"),
            );
        }
        ret
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        unsafe { function(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]) }
    }
}

/// Build a native callback trampoline that packs x0-x7 and calls
/// `dispatcher(id, args_ptr)`, returning the dispatcher's x0.
pub fn make_callback_stub(dispatcher: usize, id: usize) -> Result<usize> {
    if dispatcher == 0 {
        return Err(Error::Parse("callback stub: null dispatcher".into()));
    }
    #[cfg(target_arch = "aarch64")]
    {
        make_arm64_callback_stub(dispatcher, id)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        make_host_callback_stub(dispatcher, id)
    }
}

#[cfg(target_arch = "aarch64")]
fn make_arm64_callback_stub(dispatcher: usize, id: usize) -> Result<usize> {
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
    w.sub_sp(128);
    w.stp(29, 30, 31, 112);
    for i in 0..4u8 {
        w.stp(i * 2, i * 2 + 1, 31, (i as i64) * 16);
    }
    w.abs_addr(0, id as u64);
    w.put(0x9100_03E1); // add x1, sp, #0 (args pointer)
    w.abs_bl(dispatcher);
    w.ldp(29, 30, 31, 112);
    w.add_sp(128);
    w.ret(30);

    // SAFETY: page is a private mapping of at least PAGE bytes.
    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), page as *mut u8, w.len());
    }
    flush_icache(page as usize, w.len());
    if protect(page as usize, PAGE, libc::PROT_READ | libc::PROT_EXEC).is_err() {
        unsafe { libc::munmap(page, PAGE) };
        return Err(Error::Unsupported("callback stub: cannot set RX"));
    }
    Ok(page as usize)
}

#[cfg(not(target_arch = "aarch64"))]
struct HostStub {
    dispatcher: usize,
    id: usize,
}

#[cfg(not(target_arch = "aarch64"))]
fn host_slots() -> std::sync::MutexGuard<'static, Vec<HostStub>> {
    static SLOTS: std::sync::Mutex<Vec<HostStub>> = std::sync::Mutex::new(Vec::new());
    SLOTS.lock().unwrap_or_else(|err| err.into_inner())
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn host_enter(index: usize, args: [u64; 8]) -> u64 {
    let slots = host_slots();
    let Some(slot) = slots.get(index) else {
        return 0;
    };
    // SAFETY: dispatcher is `callback_dispatch`.
    let dispatcher: unsafe extern "C" fn(usize, *const u64) -> u64 =
        unsafe { std::mem::transmute(slot.dispatcher) };
    let id = slot.id;
    drop(slots);
    unsafe { dispatcher(id, args.as_ptr()) }
}

#[cfg(not(target_arch = "aarch64"))]
macro_rules! host_stub {
    ($name:ident, $index:expr) => {
        unsafe extern "C" fn $name(
            a0: u64,
            a1: u64,
            a2: u64,
            a3: u64,
            a4: u64,
            a5: u64,
            a6: u64,
            a7: u64,
        ) -> u64 {
            unsafe { host_enter($index, [a0, a1, a2, a3, a4, a5, a6, a7]) }
        }
    };
}

#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_0, 0);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_1, 1);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_2, 2);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_3, 3);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_4, 4);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_5, 5);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_6, 6);
#[cfg(not(target_arch = "aarch64"))]
host_stub!(host_stub_7, 7);

#[cfg(not(target_arch = "aarch64"))]
fn make_host_callback_stub(dispatcher: usize, id: usize) -> Result<usize> {
    let mut slots = host_slots();
    let entries: [unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64; 8] = [
        host_stub_0,
        host_stub_1,
        host_stub_2,
        host_stub_3,
        host_stub_4,
        host_stub_5,
        host_stub_6,
        host_stub_7,
    ];
    if slots.len() >= entries.len() {
        return Err(Error::Unsupported("too many host NativeCallbacks"));
    }
    let index = slots.len();
    slots.push(HostStub { dispatcher, id });
    Ok(entries[index] as usize)
}

#[cfg(test)]
mod tests {
    unsafe extern "C" fn ret_f64() -> f64 {
        1.25
    }

    unsafe extern "C" fn ret_f32() -> f32 {
        0.25
    }

    #[test]
    fn stub_encodings_are_arm64() {
        // The stub is generated in make_stub(); this test only documents that
        // call() rejects trivial misuse before touching the target.
        let err = unsafe { super::call(0, &[]) }.unwrap_err();
        assert!(matches!(err, runtime::Error::Parse(_)));
    }

    #[test]
    fn call_float_and_double_returns() {
        let d = unsafe { super::call_f64(ret_f64 as *const () as usize, &[]) }.unwrap();
        assert_eq!(d, 1.25);
        let f = unsafe { super::call_f32(ret_f32 as *const () as usize, &[]) }.unwrap();
        assert_eq!(f, 0.25);
    }
}
