//! Attach orchestration: stop threads, remote-call libc/linker, load the agent.

use std::fs;
use std::os::fd::AsRawFd;

use ca_core::maps;
use ca_core::{Error, Result};

use crate::elf::{self, SymbolCache};
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
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
const RTLD_NOW: u64 = 2;
const BRK_0: u32 = 0xD420_0000;

/// `ANDROID_DLEXT_USE_LIBRARY_FD` from bionic's `android/dlext.h`.
const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;

/// Build `struct android_dlextinfo` with only `USE_LIBRARY_FD` set.
///
/// bionic layout (64-bit):
///   uint64 flags; void* reserved_addrs; size_t reserved_size;
///   int relro_fd; int library_fd; off64 library_fd_offset;
///   android_namespace_t* library_namespace;
fn dlextinfo_for_fd(fd: i32) -> [u8; 48] {
    let mut ext = [0u8; 48];
    ext[0..8].copy_from_slice(&ANDROID_DLEXT_USE_LIBRARY_FD.to_le_bytes());
    ext[28..32].copy_from_slice(&fd.to_le_bytes());
    ext
}

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
    let memfd_create = resolve(&libc_path, libc_base, "memfd_create")?;
    let close = resolve(&libc_path, libc_base, "close")?;
    let dlopen = resolve(&linker_path, linker_base, "__loader_dlopen")?;
    let android_dlopen_ext = resolve(&linker_path, linker_base, "__loader_android_dlopen_ext").ok();
    let dlsym = resolve(&linker_path, linker_base, "__loader_dlsym")?;
    let dlerror = resolve(&linker_path, linker_base, "__loader_dlerror").ok();

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

    let name_ptr = config_ptr + 0x100;
    remote.write_cstr(name_ptr, "ca-agent")?;
    let fd = remote_call(
        pid,
        &remote,
        &mut regs,
        memfd_create,
        &[name_ptr as u64, 0],
        stack,
        sentinel,
    )?;
    if is_error(fd) || fd == 0 {
        return Err(Error::Io(std::io::Error::from_raw_os_error(
            (-(fd as i64)) as i32,
        )));
    }
    let fd = fd as i32;

    let agent = fs::read(&options.agent).map_err(Error::Io)?;
    {
        let mut file = remote.open_target_fd(fd, true)?;
        use std::io::Write;
        file.write_all(&agent).map_err(Error::Io)?;
        file.flush().map_err(Error::Io)?;
        // dlopen() requires an executable-looking memfd on some bionic
        // versions.  fchmod on the procfs-opened fd changes the memfd inode.
        // SAFETY: file owns a valid fd for the duration of the call.
        unsafe {
            libc::fchmod(file.as_raw_fd(), 0o700);
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } == 0 {
            eprintln!(
                "[ca-inject] memfd {fd}: size={} mode={:o}",
                st.st_size, st.st_mode
            );
        }
    }

    let path_ptr = config_ptr + 0x200;
    remote.write_cstr(path_ptr, &format!("/proc/self/fd/{fd}"))?;
    let mut handle = remote_call(
        pid,
        &remote,
        &mut regs,
        dlopen,
        &[path_ptr as u64, RTLD_NOW, caller_addr],
        stack,
        sentinel,
    )?;

    // Some bionic versions need `android_dlopen_ext` with USE_LIBRARY_FD for
    // memfd loads, especially when the caller is not in a library namespace.
    if handle == 0 {
        let path_error = read_dlerror(pid, &remote, &mut regs, dlerror, stack, sentinel);
        eprintln!("[ca-inject] __loader_dlopen(path) failed: {path_error}");
        if let Some(android_dlopen_ext) = android_dlopen_ext {
            let ext_ptr = config_ptr + 0x400;
            remote.write(ext_ptr, &dlextinfo_for_fd(fd))?;
            handle = remote_call(
                pid,
                &remote,
                &mut regs,
                android_dlopen_ext,
                &[path_ptr as u64, RTLD_NOW, ext_ptr as u64, caller_addr],
                stack,
                sentinel,
            )?;
            if handle == 0 {
                let ext_error = read_dlerror(pid, &remote, &mut regs, dlerror, stack, sentinel);
                eprintln!("[ca-inject] android_dlopen_ext(fd) failed: {ext_error}");
            }
        }
    }

    if handle == 0 {
        // Last attempt: use the linker's own address as caller.
        handle = remote_call(
            pid,
            &remote,
            &mut regs,
            dlopen,
            &[path_ptr as u64, RTLD_NOW, (linker_base + PAGE) as u64],
            stack,
            sentinel,
        )?;
    }

    if handle == 0 {
        let reason = if let Some(dlerror) = dlerror {
            match remote_call(pid, &remote, &mut regs, dlerror, &[], stack, sentinel) {
                Ok(ptr) if ptr != 0 => remote
                    .read_cstr(ptr as usize, 512)
                    .unwrap_or_else(|_| "<unreadable dlerror>".to_owned()),
                _ => "<no dlerror>".to_owned(),
            }
        } else {
            "<dlerror unavailable>".to_owned()
        };
        let _ = remote_call(
            pid,
            &remote,
            &mut regs,
            close,
            &[fd as u64],
            stack,
            sentinel,
        );
        return Err(Error::Parse(format!("dlopen(memfd) failed: {reason}")));
    }

    finish_session(
        pid,
        threads,
        scratch,
        executable,
        handle,
        &remote,
        &mut regs,
        dlsym,
        close,
        fd,
        stack,
        sentinel,
        caller_addr,
    )
}

fn read_dlerror(
    pid: u32,
    remote: &RemoteMemory,
    regs: &mut UserPtRegs,
    dlerror: Option<u64>,
    stack: usize,
    sentinel: usize,
) -> String {
    let Some(dlerror) = dlerror else {
        return "<dlerror unavailable>".to_owned();
    };
    match remote_call(pid, remote, regs, dlerror, &[], stack, sentinel) {
        Ok(ptr) if ptr != 0 => remote
            .read_cstr(ptr as usize, 512)
            .unwrap_or_else(|_| "<unreadable dlerror>".to_owned()),
        Ok(_) => "<no dlerror>".to_owned(),
        Err(err) => format!("<dlerror call failed: {err}>"),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_session(
    pid: u32,
    threads: &[u32],
    scratch: usize,
    _executable: bool,
    handle: u64,
    remote: &RemoteMemory,
    regs: &mut UserPtRegs,
    dlsym: u64,
    close: u64,
    fd: i32,
    stack: usize,
    sentinel: usize,
    caller_addr: u64,
) -> Result<Session> {
    let config_ptr = scratch + CONFIG_OFF;
    let sym_ptr = config_ptr + 0x300;
    remote.write_cstr(sym_ptr, "ca_agent_main")?;
    let entry = remote_call(
        pid,
        remote,
        regs,
        dlsym,
        &[handle, sym_ptr as u64, caller_addr],
        stack,
        sentinel,
    )?;
    if entry == 0 {
        let _ = remote_call(pid, remote, regs, close, &[fd as u64], stack, sentinel);
        return Err(Error::Unsupported("dlsym(ca_agent_main) failed"));
    }

    let rc = remote_call(
        pid,
        remote,
        regs,
        entry,
        &[config_ptr as u64],
        stack,
        sentinel,
    )?;
    let _ = remote_call(pid, remote, regs, close, &[fd as u64], stack, sentinel);
    if rc != 0 {
        return Err(Error::Parse(format!("ca_agent_main returned {rc:#x}")));
    }

    Ok(Session {
        pid,
        threads: threads.to_vec(),
        scratch,
        resumed: false,
    })
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
    use super::dlextinfo_for_fd;

    #[test]
    fn dlextinfo_layout() {
        let ext = dlextinfo_for_fd(152);
        assert_eq!(u64::from_le_bytes(ext[0..8].try_into().unwrap()), 0x10);
        assert_eq!(i32::from_le_bytes(ext[8..12].try_into().unwrap()), 0);
        assert_eq!(i32::from_le_bytes(ext[28..32].try_into().unwrap()), 152);
        assert_eq!(u64::from_le_bytes(ext[32..40].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(ext[40..48].try_into().unwrap()), 0);
    }
}
