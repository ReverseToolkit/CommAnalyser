//! Java method entrypoint hooking.
//!
//! Android 15 `ArtMethod` stores the quick entrypoint at offset 24.  The stub
//! below replaces it with a tiny ARM64 trampoline that calls a Rust dispatcher
//! with a per-hook id; the dispatcher bridges into the JS worker.

use std::ffi::c_void;
use std::ptr;

use arch_arm64::writer::CodeWriter;
use runtime::{Error, Result};

use crate::java::MethodId;

const PAGE: usize = 0x1000;
const ENTRYPOINT_OFFSET: usize = 24;

pub struct JavaHook {
    art_method: usize,
    original: usize,
    active: bool,
}

impl JavaHook {
    pub fn detach(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        write_pointer(self.art_method + ENTRYPOINT_OFFSET, self.original);
        self.active = false;
        Ok(())
    }
}

impl Drop for JavaHook {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub fn install(method: MethodId, dispatcher: usize, id: usize) -> Result<JavaHook> {
    let art_method = method.raw();
    if art_method == 0 {
        return Err(Error::Parse("Java hook: null ArtMethod".into()));
    }
    let stub = make_stub(dispatcher, id)?;
    let entry = art_method + ENTRYPOINT_OFFSET;
    let original = read_pointer(entry);
    if original == 0 {
        return Err(Error::Parse("Java hook: null entrypoint".into()));
    }
    write_pointer(entry, stub);
    Ok(JavaHook {
        art_method,
        original,
        active: true,
    })
}

fn make_stub(dispatcher: usize, id: usize) -> Result<usize> {
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

    let mut w = CodeWriter::with_capacity(160);
    w.bti_c();
    w.sub_sp(96);
    w.stp(29, 30, 31, 80);
    w.stp(0, 1, 31, 0);
    w.stp(2, 3, 31, 16);
    w.stp(4, 5, 31, 32);
    w.stp(6, 7, 31, 48);
    w.abs_addr(0, id as u64);
    w.put(0x9100_03E1); // add x1, sp, #0 (saved x0-x7)
    w.abs_bl(dispatcher);
    w.ldp(29, 30, 31, 80);
    w.add_sp(96);
    w.ret(30);

    // SAFETY: the page is a private mapping of at least PAGE bytes.
    unsafe {
        ptr::copy_nonoverlapping(w.bytes().as_ptr(), page as *mut u8, w.len());
    }
    flush_icache(page as usize, w.len());
    Ok(page as usize)
}

fn read_pointer(address: usize) -> usize {
    unsafe { ptr::read_unaligned(address as *const usize) }
}

fn write_pointer(address: usize, value: usize) {
    let page_size = runtime::process::page_size();
    let page = address & !(page_size - 1);
    unsafe {
        libc::mprotect(
            page as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        ptr::write_unaligned(address as *mut usize, value);
        libc::mprotect(
            page as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    flush_icache(address, std::mem::size_of::<usize>());
}

fn flush_icache(address: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        let start = address & !63;
        let end = (address + len + 63) & !63;
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (address, len);
    }
}
