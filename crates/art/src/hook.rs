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
const DATA_OFFSET: usize = 16;
const ACCESS_FLAGS_OFFSET: usize = 4;
const ACC_NATIVE: u32 = 0x0000_0100;
const ACC_FAST_NATIVE: u32 = 0x0008_0000;
const ACC_CRITICAL_NATIVE: u32 = 0x0020_0000;
const ACC_NTERP_FAST: u32 = 0x0010_0000;
const ACC_COMPILE_DONT_BOTHER: u32 = 0x0200_0000;

pub struct JavaHook {
    art_method: usize,
    original: usize,
    stub: usize,
    original_flags: u32,
    original_data: usize,
    native_mode: bool,
    active: bool,
}

impl JavaHook {
    pub fn is_native_mode(&self) -> bool {
        self.native_mode
    }

    /// Temporarily route calls back to the original method.
    pub fn suspend(&self) {
        if self.native_mode {
            write_pointer(self.art_method + DATA_OFFSET, self.original_data);
            write_u32(self.art_method + ACCESS_FLAGS_OFFSET, self.original_flags);
        }
        write_pointer(self.art_method + ENTRYPOINT_OFFSET, self.original);
    }

    /// Reinstall the hook after an original() call.
    pub fn resume(&self) {
        write_pointer(self.art_method + ENTRYPOINT_OFFSET, self.stub);
        if self.native_mode {
            write_pointer(self.art_method + DATA_OFFSET, self.stub);
            write_u32(self.art_method + ACCESS_FLAGS_OFFSET, self.patched_flags());
        }
    }

    fn patched_flags(&self) -> u32 {
        (self.original_flags & !(ACC_FAST_NATIVE | ACC_CRITICAL_NATIVE | ACC_NTERP_FAST))
            | ACC_NATIVE
            | ACC_COMPILE_DONT_BOTHER
    }

    pub fn detach(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.suspend();
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
    let original_flags = read_u32(art_method + ACCESS_FLAGS_OFFSET);
    let original_data = read_pointer(art_method + DATA_OFFSET);
    let native_trampoline = generic_jni_trampoline().unwrap_or(0);
    let native_mode = native_trampoline != 0;
    let hook = JavaHook {
        art_method,
        original,
        stub,
        original_flags,
        original_data,
        native_mode,
        active: true,
    };
    if native_mode {
        write_pointer(art_method + DATA_OFFSET, stub);
        write_pointer(entry, native_trampoline);
        write_u32(art_method + ACCESS_FLAGS_OFFSET, hook.patched_flags());
    } else {
        write_pointer(entry, stub);
    }
    Ok(hook)
}

fn generic_jni_trampoline() -> Option<usize> {
    let address = resolve_libart_symbol("_ZNK3art11ClassLinker29GetRuntimeQuickGenericJniStubEv")?;
    type GetStub = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    // SAFETY: exported ClassLinker getter; it ignores its `this` argument.
    let get_stub: GetStub = unsafe { std::mem::transmute(address) };
    let stub = unsafe { get_stub(ptr::null_mut()) };
    (!stub.is_null()).then_some(stub as usize)
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

fn read_u32(address: usize) -> u32 {
    // SAFETY: caller passes a valid ArtMethod field address.
    unsafe { ptr::read_unaligned(address as *const u32) }
}

fn write_u32(address: usize, value: u32) {
    let page_size = runtime::process::page_size();
    let page = address & !(page_size - 1);
    // SAFETY: ArtMethod fields live in writable ART memory.
    unsafe {
        libc::mprotect(
            page as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        ptr::write_unaligned(address as *mut u32, value);
    }
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

    let mut w = CodeWriter::with_capacity(224);
    w.bti_c();
    w.sub_sp(192);
    w.stp(29, 30, 31, 176);
    w.stp(0, 1, 31, 0);
    w.stp(2, 3, 31, 16);
    w.stp(4, 5, 31, 32);
    w.stp(6, 7, 31, 48);
    w.stp_d(0, 1, 31, 64);
    w.stp_d(2, 3, 31, 80);
    w.stp_d(4, 5, 31, 96);
    w.stp_d(6, 7, 31, 112);
    w.abs_addr(0, id as u64);
    w.put(0x9100_03E1); // add x1, sp, #0 (saved x0-x7)
    w.put(0x9101_03E2); // add x2, sp, #64 (saved d0-d7)
    w.put(0x9103_03E3); // add x3, sp, #192 (caller SP / stack args)
    w.abs_bl(dispatcher);
    w.put(0x9E67_0020); // fmov d0, x1
    w.ldp(29, 30, 31, 176);
    w.add_sp(192);
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
