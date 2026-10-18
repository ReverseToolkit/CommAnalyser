//! Remote process memory access.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::raw::c_void;
use std::os::unix::fs::FileExt;

use runtime::{Error, Result};

pub struct RemoteMemory {
    pid: u32,
    mem: Option<File>,
}

impl RemoteMemory {
    pub fn new(pid: u32) -> Self {
        let mem = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .ok();
        Self { pid, mem }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn read(&self, addr: usize, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut out = vec![0u8; len];
        let local = libc::iovec {
            iov_base: out.as_mut_ptr() as *mut c_void,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut c_void,
            iov_len: len,
        };
        // SAFETY: both iovecs point to valid memory for the duration of the call.
        let n =
            unsafe { libc::process_vm_readv(self.pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if n == len as isize {
            return Ok(out);
        }

        if let Some(mem) = &self.mem {
            // SAFETY: buffer is valid; pread may fail for unmapped addresses.
            let n = mem.read_at(&mut out, addr as u64).map_err(Error::Io)?;
            if n == len {
                return Ok(out);
            }
        }
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("remote read {addr:#x}+{len:#x} failed"),
        )))
    }

    pub fn write(&self, addr: usize, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: data.as_ptr() as *mut c_void,
            iov_len: data.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut c_void,
            iov_len: data.len(),
        };
        // SAFETY: both iovecs point to valid memory for the duration of the call.
        let n =
            unsafe { libc::process_vm_writev(self.pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if n == data.len() as isize {
            return Ok(());
        }

        if let Some(mem) = &self.mem {
            mem.write_at(data, addr as u64).map_err(Error::Io)?;
            return Ok(());
        }
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("remote write {addr:#x}+{:#x} failed", data.len()),
        )))
    }

    pub fn write_cstr(&self, addr: usize, text: &str) -> Result<()> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        self.write(addr, &bytes)
    }

    pub fn read_cstr(&self, addr: usize, max: usize) -> Result<String> {
        let bytes = self.read(addr, max)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Re-open `/proc/<pid>/fd/<fd>` (used to write the agent into a target
    /// memfd).  The returned file shares the memfd's underlying object.
    pub fn open_target_fd(&self, fd: i32, write: bool) -> Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        if write {
            options.write(true);
        }
        options
            .open(format!("/proc/{}/fd/{fd}", self.pid))
            .map_err(Error::Io)
    }

    pub fn seek_len(&self, fd: i32) -> Result<u64> {
        let mut file = self.open_target_fd(fd, false)?;
        file.seek(SeekFrom::End(0)).map_err(Error::Io)
    }

    pub fn read_file_from_fd(&self, fd: i32, len: usize) -> Result<Vec<u8>> {
        let mut file = self.open_target_fd(fd, false)?;
        let mut out = vec![0u8; len];
        file.read_exact(&mut out).map_err(Error::Io)?;
        Ok(out)
    }

    pub fn write_file_to_fd(&self, fd: i32, data: &[u8]) -> Result<()> {
        let mut file = self.open_target_fd(fd, true)?;
        file.write_all(data).map_err(Error::Io)?;
        file.flush().map_err(Error::Io)?;
        Ok(())
    }
}
