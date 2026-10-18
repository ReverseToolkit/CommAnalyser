//! Minimal agent control channel over an abstract Unix socket.
//!
//! Wire format is line-delimited JSON.  M1 only needs `hello`, `ping` and
//! `bye`; script evaluation is added in M2.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn connect_abstract(name: &str) -> std::io::Result<UnixStream> {
    if name.len() + 1 > 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract socket name too long",
        ));
    }

    // SAFETY: socket(2) returns a fresh fd or -1.
    let fd: RawFd =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
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
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is owned by us and not used after this point on failure.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: fd is a connected stream socket and ownership is transferred.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn run(name: &str) -> std::io::Result<()> {
    let stream = connect_abstract(name)?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let hello = format!(
        "{{\"op\":\"hello\",\"pid\":{},\"abi\":{}}}\n",
        std::process::id(),
        crate::ca_agent_abi_version()
    );
    writer.write_all(hello.as_bytes())?;
    writer.flush()?;

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let command = line.trim();
        if command.contains("\"bye\"") || command.contains("\"exit\"") {
            break;
        }
        let response = if command.contains("\"ping\"") {
            "{\"ok\":true,\"pong\":true}\n"
        } else {
            "{\"ok\":false,\"error\":\"unsupported\"}\n"
        };
        writer.write_all(response.as_bytes())?;
        writer.flush()?;
    }
    Ok(())
}

pub fn spawn(name: String) {
    std::thread::spawn(move || {
        // Retry briefly: the daemon must already be listening, but giving it
        // a few milliseconds hides scheduler races during spawn.
        let mut last = None;
        for _ in 0..50 {
            match run(&name) {
                Ok(()) => return,
                Err(err) => {
                    last = Some(err);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        if let Some(err) = last {
            eprintln!("[ca-agent] control channel failed: {err}");
        }
    });
}
