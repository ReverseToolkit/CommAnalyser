//! Abstract-Unix-socket listener used to receive the agent hello.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct Listener {
    fd: RawFd,
}

impl Listener {
    pub fn bind(name: &str) -> std::io::Result<Self> {
        if name.len() + 1 > 108 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "abstract socket name too long",
            ));
        }

        // SAFETY: socket(2) returns a fresh fd or -1.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        addr.sun_path[0] = 0;
        let bytes = name.as_bytes();
        for (dst, src) in addr.sun_path[1..].iter_mut().zip(bytes.iter()) {
            *dst = *src as libc::c_char;
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as libc::socklen_t;

        // SAFETY: addr/len describe the abstract name above.
        if unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                len,
            )
        } != 0
        {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // SAFETY: fd is a bound Unix stream socket.
        if unsafe { libc::listen(fd, 4) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(Self { fd })
    }

    pub fn accept_timeout(&self, timeout: Duration) -> std::io::Result<Option<UnixStream>> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one pollfd, valid fd.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc == 0 {
            return Ok(None);
        }
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: accept returns a fresh fd.
        let client = unsafe { libc::accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: client is a connected stream socket.
        Ok(Some(unsafe { UnixStream::from_raw_fd(client) }))
    }

    pub fn read_hello(stream: &UnixStream, timeout: Duration) -> std::io::Result<String> {
        stream.set_read_timeout(Some(timeout))?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Ok(line.trim().to_owned())
    }

    pub fn send_bye(stream: &mut UnixStream) {
        let _ = stream.write_all(b"{\"op\":\"bye\"}\n");
        let _ = stream.flush();
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own the listener fd.
            unsafe { libc::close(self.fd) };
        }
    }
}
