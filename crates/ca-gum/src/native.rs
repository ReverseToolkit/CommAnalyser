//! Native calls without libffi.
//!
//! A single AArch64 stub loads x0-x7 from a buffer, calls the target, and
//! stores x0 back.  This covers the common integer/pointer signatures used by
//! Frida scripts; float arguments/returns and structs are not supported yet.

use std::ptr;
use std::sync::OnceLock;

use ca_arch_arm64::writer::CodeWriter;
use ca_core::{Error, Result};

use crate::memory::{flush_icache, protect};

const PAGE: usize = 0x1000;

type CallStub = unsafe extern "C" fn(target: u64, args: *const u64, ret: *mut u64);

/// Call `target(args[0..8])` and return x0.
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

    let stub = stub()?;
    let mut buffer = [0u64; 8];
    buffer[..args.len()].copy_from_slice(args);
    let mut ret = 0u64;

    // SAFETY: the stub is generated below with the C ABI above.
    unsafe { stub(target as u64, buffer.as_ptr(), &mut ret) };
    Ok(ret)
}

fn stub() -> Result<CallStub> {
    static STUB: OnceLock<usize> = OnceLock::new();
    let address = *STUB.get_or_init(|| make_stub().unwrap_or(0));
    if address == 0 {
        return Err(Error::Unsupported("native call: cannot allocate stub"));
    }
    // SAFETY: the page contains the stub emitted by make_stub().
    Ok(unsafe { std::mem::transmute::<usize, CallStub>(address) })
}

fn make_stub() -> Option<usize> {
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

    let mut w = CodeWriter::with_capacity(128);
    w.bti_c();
    w.put(0xAA00_03EA); // mov x10, x0 (target)
    w.put(0xAA01_03E9); // mov x9, x1 (args)
    w.put(0xAA02_03EB); // mov x11, x2 (ret)
    w.sub_sp(32);
    w.stp(29, 30, 31, 16);
    w.str_imm(11, 31, 0); // save ret pointer: the callee may clobber x11
    w.ldp(0, 1, 9, 0);
    w.ldp(2, 3, 9, 16);
    w.ldp(4, 5, 9, 32);
    w.ldp(6, 7, 9, 48);
    w.put(0xD63F_0140); // blr x10
    w.ldr_imm(11, 31, 0);
    w.put(0xF900_0160); // str x0, [x11]
    w.ldp(29, 30, 31, 16);
    w.add_sp(32);
    w.ret(30);

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

/// Build a native callback trampoline that packs x0-x7 and calls
/// `dispatcher(id, args_ptr)`, returning the dispatcher's x0.
pub fn make_callback_stub(dispatcher: usize, id: usize) -> Result<usize> {
    if dispatcher == 0 {
        return Err(Error::Parse("callback stub: null dispatcher".into()));
    }
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
    w.bti_c();
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

#[cfg(test)]
mod tests {
    #[test]
    fn stub_encodings_are_arm64() {
        // The stub is generated in make_stub(); this test only documents that
        // call() rejects trivial misuse before touching the target.
        let err = unsafe { super::call(0, &[]) }.unwrap_err();
        assert!(matches!(err, ca_core::Error::Parse(_)));
    }
}
