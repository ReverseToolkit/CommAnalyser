//! Attach orchestration: stop threads, map the agent with the 自定义linker.

use std::fs;

use runtime::maps;
use runtime::{Error, Result};

use crate::elf::{self, SymbolCache};
use crate::loader::{self, Image};
use crate::ptrace::{self, UserPtRegs};
use crate::remote::RemoteMemory;
use crate::AttachOptions;

const SCRATCH_SIZE: usize = 0x1_0000;
const STACK_OFF: usize = 0x8000;
const CONFIG_OFF: usize = 0x9000;
const PAGE: usize = 0x1000;
const PROT_RW: u64 = 3;
const PROT_RWX: u64 = 7;
const PROT_RX: u64 = 5;
const PROT_BTI: u64 = 0x10;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
const BRK_0: u32 = 0xD420_0000;
const WRITE_CHUNK: usize = 0x4_0000;

#[derive(Debug)]
pub struct Session {
    pub pid: u32,
    threads: Vec<u32>,
    scratch: usize,
    resumed: bool,
}

impl Session {
    /// Resume all threads and detach.  Idempotent.
    pub fn resume(&mut self) {
        if !self.resumed {
            ptrace::resume_all(&self.threads);
            self.resumed = true;
        }
    }

    pub fn scratch(&self) -> usize {
        self.scratch
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.resume();
    }
}

/// Attach to `pid`, load the agent, and leave the target stopped.
///
/// The caller must wait for the agent's hello and then call
/// [`Session::resume`].  Dropping the session also resumes.
pub fn attach(options: &AttachOptions) -> Result<Session> {
    if options.pid == 0 {
        return Err(Error::Parse("attach: pid 0".into()));
    }
    if !crate::pid_alive(options.pid) {
        return Err(Error::NotFound(format!("pid {}", options.pid)));
    }
    if options.config.is_empty() {
        return Err(Error::Parse("attach: empty control config".into()));
    }

    let threads = ptrace::stop_all(options.pid, 0).map_err(Error::Io)?;
    match inject_locked(options, &threads) {
        Ok(session) => Ok(session),
        Err(err) => {
            ptrace::resume_all(&threads);
            Err(err)
        }
    }
}

fn inject_locked(options: &AttachOptions, threads: &[u32]) -> Result<Session> {
    let pid = options.pid;
    let remote = RemoteMemory::new(pid);
    let maps = maps::read_maps(pid)?;

    let libc_path =
        elf::find_module_path(&maps, "libc.so").ok_or_else(|| Error::NotFound("libc.so".into()))?;
    let linker_path = elf::find_module_path(&maps, "linker64")
        .or_else(|| elf::find_module_path(&maps, "linker"))
        .ok_or_else(|| Error::NotFound("linker64/linker".into()))?;
    let libc_base = elf::module_base(&maps, &libc_path)
        .ok_or_else(|| Error::NotFound("libc load bias".into()))?;
    let linker_base = elf::module_base(&maps, &linker_path)
        .ok_or_else(|| Error::NotFound("linker load bias".into()))?;

    let mut cache = SymbolCache::default();
    let mut resolve = |path: &str, base: usize, name: &str| -> Result<u64> {
        cache
            .resolve(path, name)?
            .map(|value| (base + value as usize) as u64)
            .ok_or_else(|| Error::NotFound(format!("{name} in {path}")))
    };

    let mmap = resolve(&libc_path, libc_base, "mmap")?;
    let mprotect = resolve(&libc_path, libc_base, "mprotect")?;
    let dlsym = resolve(&linker_path, linker_base, "__loader_dlsym")
        .or_else(|_| resolve(&libc_path, libc_base, "dlsym"))?;

    let mut regs = UserPtRegs::get(pid).map_err(Error::Io)?;
    let caller_addr = (libc_base + PAGE) as u64;

    // The first mmap has to use the target's current stack because we do not
    // have scratch memory yet.  The return address is 0, so the thread faults
    // at PC 0 and we read x0.
    let first_stack = ((regs.sp.saturating_sub(0x8000)) & !0xF) as usize;
    if first_stack == 0 {
        return Err(Error::Unsupported("target SP is too low for bootstrap"));
    }
    let tri = |prot: u64| {
        [
            0,
            SCRATCH_SIZE as u64,
            prot,
            MAP_PRIVATE_ANONYMOUS,
            u64::MAX,
            0,
        ]
    };

    let mut scratch = remote_call(
        pid,
        &remote,
        &mut regs,
        mmap,
        &tri(PROT_RWX),
        first_stack,
        0,
    )?;
    let mut executable = true;
    if is_error(scratch) {
        // Android may reject anonymous RWX; fall back to RW + mprotect(RX).
        scratch = remote_call(pid, &remote, &mut regs, mmap, &tri(PROT_RW), first_stack, 0)?;
        if is_error(scratch) {
            return Err(Error::Io(std::io::Error::from_raw_os_error(
                (-(scratch as i64)) as i32,
            )));
        }
        executable = false;
    }

    let scratch = scratch as usize;
    let sentinel = scratch;
    let stack = scratch + STACK_OFF;
    let config_ptr = scratch + CONFIG_OFF;

    // Write the sentinel first so it is present before the page becomes RX.
    remote.write(scratch, &BRK_0.to_le_bytes())?;
    if !executable {
        let ret = remote_call(
            pid,
            &remote,
            &mut regs,
            mprotect,
            &[scratch as u64, PAGE as u64, PROT_RX],
            stack,
            0,
        )?;
        if is_error(ret) {
            return Err(Error::Io(std::io::Error::from_raw_os_error(
                (-(ret as i64)) as i32,
            )));
        }
    }

    remote.write_cstr(config_ptr, &options.config)?;

    let agent = fs::read(&options.agent).map_err(Error::Io)?;
    let image = Image::parse(&agent)?;
    let page = target_page_size(pid).unwrap_or(PAGE);
    let span = image.span(page);
    let load_start = loader::align_down(image.load_start, page as u64);

    let map = remote_call(
        pid,
        &remote,
        &mut regs,
        mmap,
        &[0, span as u64, PROT_RW, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
        stack,
        sentinel,
    )?;
    if is_error(map) || map == 0 {
        return Err(Error::Io(std::io::Error::from_raw_os_error(
            (-(map as i64)) as i32,
        )));
    }
    let map = map as usize;
    eprintln!("[inject] custom linker map={map:#x} span={span:#x} (no dlopen)");

    for segment in &image.segments {
        let dest = map.wrapping_add((segment.vaddr - load_start) as usize);
        let filesz = segment.filesz as usize;
        if filesz == 0 {
            continue;
        }
        let start = segment.offset as usize;
        let src = agent
            .get(start..start + filesz)
            .ok_or_else(|| Error::Parse("PT_LOAD truncated".into()))?;
        write_chunks(&remote, dest, src)?;
    }

    let name_ptr = config_ptr + 0x100;
    let mut imports = std::collections::HashMap::new();
    for reloc in &image.relocs {
        let Some(name) = reloc.symbol.as_deref() else {
            continue;
        };
        if name.is_empty() || image.symbols.contains_key(name) || imports.contains_key(name) {
            continue;
        }
        remote.write_cstr(name_ptr, name)?;
        let addr = remote_call(
            pid,
            &remote,
            &mut regs,
            dlsym,
            &[0, name_ptr as u64, caller_addr],
            stack,
            sentinel,
        )?;
        if addr == 0 && !reloc.weak {
            return Err(Error::NotFound(format!("dlsym({name})")));
        }
        imports.insert(name.to_owned(), addr);
    }
    loader::apply_relocs(
        map,
        load_start,
        &image,
        &mut |name| {
            imports
                .get(name)
                .copied()
                .ok_or_else(|| Error::NotFound(format!("import {name}")))
        },
        |slot, value| remote.write(slot, &value.to_le_bytes()),
        |fn_addr| remote_call(pid, &remote, &mut regs, fn_addr, &[], stack, sentinel),
    )?;

    for segment in &image.segments {
        let start =
            loader::align_down(map as u64 + segment.vaddr - load_start, page as u64) as usize;
        let end = loader::align_up(
            map as u64 + segment.vaddr + segment.memsz - load_start,
            page as u64,
        ) as usize;
        let len = end.saturating_sub(start);
        if len == 0 {
            continue;
        }
        let mut prot = loader::prot_from_flags(segment.flags, false) as u64;
        let rc = remote_call(
            pid,
            &remote,
            &mut regs,
            mprotect,
            &[start as u64, len as u64, prot],
            stack,
            sentinel,
        )?;
        if is_error(rc) && prot & PROT_BTI != 0 {
            prot &= !PROT_BTI;
            let rc = remote_call(
                pid,
                &remote,
                &mut regs,
                mprotect,
                &[start as u64, len as u64, prot],
                stack,
                sentinel,
            )?;
            if is_error(rc) {
                return Err(Error::Io(std::io::Error::from_raw_os_error(
                    (-(rc as i64)) as i32,
                )));
            }
        }
    }
    if let Some((vaddr, memsz)) = image.relro {
        let start = loader::align_down(map as u64 + vaddr - load_start, page as u64) as usize;
        let end = loader::align_up(map as u64 + vaddr + memsz - load_start, page as u64) as usize;
        let len = end.saturating_sub(start);
        if len > 0 {
            let _ = remote_call(
                pid,
                &remote,
                &mut regs,
                mprotect,
                &[start as u64, len as u64, 1],
                stack,
                sentinel,
            );
        }
    }

    let constructors = remote_constructors(&remote, map, load_start, &image)?;
    for addr in constructors {
        let rc = remote_call(pid, &remote, &mut regs, addr, &[], stack, sentinel)?;
        if is_error(rc) {
            eprintln!("[inject] init {addr:#x} returned {rc:#x}");
        }
    }

    let entry_off = image
        .symbol_value(&options.entrypoint)
        .ok_or_else(|| Error::NotFound(options.entrypoint.clone()))?;
    let entry = map as u64 + entry_off - load_start;
    let rc = remote_call(
        pid,
        &remote,
        &mut regs,
        entry,
        &[config_ptr as u64],
        stack,
        sentinel,
    )?;
    if rc != 0 {
        return Err(Error::Parse(format!("agent_main returned {rc:#x}")));
    }

    let _ = executable;
    Ok(Session {
        pid,
        threads: threads.to_vec(),
        scratch,
        resumed: false,
    })
}

fn write_chunks(remote: &RemoteMemory, mut dest: usize, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(WRITE_CHUNK) {
        remote.write(dest, chunk)?;
        dest += chunk.len();
    }
    Ok(())
}

fn remote_constructors(
    remote: &RemoteMemory,
    map: usize,
    load_start: u64,
    image: &Image,
) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    if let Some(init) = image.init {
        if init != 0 {
            out.push(map as u64 + init - load_start);
        }
    }
    if let Some((addr, count)) = image.init_array {
        let start = map.wrapping_add((addr - load_start) as usize);
        let bytes = remote.read(start, count * 8)?;
        for chunk in bytes.chunks_exact(8) {
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            if value != 0 && value != u64::MAX {
                out.push(value);
            }
        }
    }
    Ok(out)
}

fn target_page_size(pid: u32) -> Result<usize> {
    let buf = fs::read(format!("/proc/{pid}/auxv")).map_err(Error::Io)?;
    for chunk in buf.chunks_exact(16) {
        let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let val = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        if tag == 6 {
            return Ok(val as usize);
        }
    }
    Ok(PAGE)
}

/// Call an arbitrary function in the stopped target.  Restores registers even
/// when the call fails.
fn remote_call(
    pid: u32,
    _remote: &RemoteMemory,
    regs: &mut UserPtRegs,
    function: u64,
    args: &[u64],
    stack: usize,
    sentinel: usize,
) -> Result<u64> {
    if args.len() > 8 {
        return Err(Error::Unsupported("remote call: more than 8 arguments"));
    }
    let saved = *regs;

    for (i, value) in args.iter().enumerate() {
        regs.set_arg(i, *value);
    }
    regs.pc = function;
    regs.regs[30] = sentinel as u64;
    regs.sp = stack as u64;

    regs.set(pid).map_err(Error::Io)?;
    let result = (|| -> Result<u64> {
        ptrace::cont(pid, 0).map_err(Error::Io)?;
        let signal =
            ptrace::wait_stop(pid, std::time::Duration::from_secs(5)).map_err(Error::Io)?;
        let now = UserPtRegs::get(pid).map_err(Error::Io)?;
        let returned = if sentinel == 0 {
            signal == libc::SIGSEGV && now.pc == 0
        } else {
            signal == libc::SIGTRAP
                && (now.pc == sentinel as u64 || now.pc == (sentinel + 4) as u64)
        };
        if !returned {
            return Err(Error::Parse(format!(
                "remote call {function:#x} stopped with signal {signal}, pc={:#x}",
                now.pc
            )));
        }
        Ok(now.ret())
    })();

    if result.is_err() {
        // The thread may still be running (e.g. wait timeout).  Stop it again
        // before restoring registers so we do not write to a running thread.
        let _ = ptrace::interrupt(pid);
        let _ = ptrace::wait_stop(pid, std::time::Duration::from_millis(500));
    }
    *regs = saved;
    let _ = regs.set(pid);
    result
}

fn is_error(value: u64) -> bool {
    let signed = value as i64;
    signed < 0 && signed > -4096
}

#[cfg(test)]
mod tests {
    use super::target_page_size;

    #[test]
    fn reads_self_page_size() {
        let page = target_page_size(std::process::id()).unwrap();
        assert!(page == 0x1000 || page == 0x4000, "page={page}");
    }
}
