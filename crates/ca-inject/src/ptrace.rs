//! Thin, explicit ptrace wrapper for aarch64 Android/Linux.
//!
//! We deliberately avoid a high-level crate here: the injector needs exact
//! control over SEIZE/INTERRUPT/GETREGSET and over which threads are stopped.

use std::io;
use std::os::raw::{c_int, c_void};
use std::time::{Duration, Instant};

pub const NT_PRSTATUS: usize = 1;
pub const PTRACE_CONT: c_int = 7;
pub const PTRACE_DETACH: c_int = 17;
pub const PTRACE_SETOPTIONS: c_int = 0x4200;
pub const PTRACE_GETREGSET: c_int = 0x4204;
pub const PTRACE_SETREGSET: c_int = 0x4205;
pub const PTRACE_SEIZE: c_int = 0x4206;
pub const PTRACE_INTERRUPT: c_int = 0x4207;

pub const PTRACE_O_TRACECLONE: usize = 0x0000_0008;
pub const PTRACE_O_TRACEEXIT: usize = 0x0000_0040;

const WALL: c_int = 0x4000_0000;

/// `struct user_pt_regs` for AArch64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UserPtRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl UserPtRegs {
    #[inline]
    pub fn arg(&self, n: usize) -> u64 {
        self.regs.get(n).copied().unwrap_or(0)
    }

    #[inline]
    pub fn set_arg(&mut self, n: usize, value: u64) {
        if let Some(slot) = self.regs.get_mut(n) {
            *slot = value;
        }
    }

    #[inline]
    pub fn ret(&self) -> u64 {
        self.regs[0]
    }

    pub fn get(tid: u32) -> io::Result<Self> {
        let mut regs = Self::default();
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut Self as *mut c_void,
            iov_len: std::mem::size_of::<Self>(),
        };
        ptrace(
            PTRACE_GETREGSET,
            tid,
            NT_PRSTATUS,
            &mut iov as *mut libc::iovec as usize,
        )?;
        Ok(regs)
    }

    pub fn set(&self, tid: u32) -> io::Result<()> {
        let mut copy = *self;
        let mut iov = libc::iovec {
            iov_base: &mut copy as *mut Self as *mut c_void,
            iov_len: std::mem::size_of::<Self>(),
        };
        ptrace(
            PTRACE_SETREGSET,
            tid,
            NT_PRSTATUS,
            &mut iov as *mut libc::iovec as usize,
        )?;
        Ok(())
    }
}

fn ptrace(request: c_int, tid: u32, addr: usize, data: usize) -> io::Result<()> {
    // SAFETY: all call sites provide the argument shapes required by ptrace.
    let rc = unsafe {
        libc::ptrace(
            request as _,
            tid as libc::pid_t,
            addr as *mut c_void,
            data as *mut c_void,
        )
    };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn seize(tid: u32, options: usize) -> io::Result<()> {
    ptrace(PTRACE_SEIZE, tid, 0, options)
}

pub fn set_options(tid: u32, options: usize) -> io::Result<()> {
    ptrace(PTRACE_SETOPTIONS, tid, 0, options)
}

pub fn interrupt(tid: u32) -> io::Result<()> {
    ptrace(PTRACE_INTERRUPT, tid, 0, 0)
}

pub fn cont(tid: u32, signal: c_int) -> io::Result<()> {
    ptrace(PTRACE_CONT, tid, 0, signal as usize)
}

pub fn detach(tid: u32, signal: c_int) -> io::Result<()> {
    ptrace(PTRACE_DETACH, tid, 0, signal as usize)
}

/// Wait until `tid` reports a ptrace stop.  Returns the stop signal.
pub fn wait_stop(tid: u32, timeout: Duration) -> io::Result<c_int> {
    let start = Instant::now();
    loop {
        let mut status: c_int = 0;
        // SAFETY: waitpid writes one int into status.
        let rc = unsafe { libc::waitpid(tid as libc::pid_t, &mut status, WALL | libc::WNOHANG) };
        if rc == tid as libc::pid_t {
            if libc::WIFSTOPPED(status) {
                return Ok(libc::WSTOPSIG(status));
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("thread {tid} exited while stopped"),
                ));
            }
        } else if rc == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.raw_os_error() == Some(libc::ECHILD) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("thread {tid} is not our tracee"),
                ));
            }
            return Err(err);
        }
        if start.elapsed() > timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out stopping thread {tid}"),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Enumerate tids of a process through `/proc/<pid>/task`.
pub fn enumerate_tids(pid: u32) -> io::Result<Vec<u32>> {
    let mut tids = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = entry?;
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

/// Stop every thread of `pid`, returning the tids that are now stopped.
///
/// The caller must eventually call [`resume_all`] (or detach) on success.
pub fn stop_all(pid: u32, options: usize) -> io::Result<Vec<u32>> {
    let tids = enumerate_tids(pid)?;
    let mut stopped = Vec::with_capacity(tids.len());

    for &tid in &tids {
        match seize(tid, options) {
            Ok(()) => {
                // A thread may already be group-stopped; EIO is harmless.
                let _ = interrupt(tid);
                stopped.push(tid);
            }
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(err) => {
                resume_all(&stopped);
                return Err(err);
            }
        }
    }

    for &tid in &stopped {
        if let Err(err) = wait_stop(tid, Duration::from_secs(2)) {
            resume_all(&stopped);
            return Err(err);
        }
    }
    Ok(stopped)
}

/// Detach every stopped thread.  Errors are ignored: this is used on cleanup
/// paths where the original error matters more.
pub fn resume_all(tids: &[u32]) {
    for &tid in tids {
        let _ = detach(tid, 0);
    }
}
