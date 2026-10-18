//! Resident agent control channel over an abstract Unix socket.
//!
//! Wire format is line-delimited JSON.  Commands are intentionally small:
//! `ping`, `hook_getpid`, and `eval` (QuickJS).

use std::ffi::c_void;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use ca_gum::InlineHook;
use ca_js::JsWorker;

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

    let worker = match JsWorker::spawn() {
        Ok(worker) => Some(worker),
        Err(err) => {
            eprintln!("[ca-agent] QuickJS init failed: {err}");
            None
        }
    };

    let hello = json!({
        "op": "hello",
        "pid": std::process::id(),
        "abi": crate::ca_agent_abi_version(),
        "quickjs": worker.is_some(),
    });
    writeln!(writer, "{hello}")?;
    writer.flush()?;

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let request: Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(err) => {
                let response = json!({"ok": false, "error": format!("bad json: {err}")});
                writeln!(writer, "{response}")?;
                writer.flush()?;
                continue;
            }
        };

        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        let response = match op {
            "ping" => json!({"ok": true, "pong": true}),
            "bye" | "exit" => break,
            "hook_getpid" => hook_getpid(),
            "eval" => {
                let code = request.get("code").and_then(Value::as_str).unwrap_or("");
                match worker.as_ref() {
                    Some(worker) => match worker.eval(code) {
                        Ok(value) => json!({"ok": true, "value": value}),
                        Err(err) => json!({"ok": false, "error": err.to_string()}),
                    },
                    None => json!({"ok": false, "error": "QuickJS unavailable"}),
                }
            }
            "call_getpid" => {
                for _ in 0..5 {
                    // SAFETY: plain libc call; deliberately on this (non-JS) thread
                    // so a JS Interceptor hook can run on its own thread.
                    unsafe {
                        libc::getpid();
                    }
                }
                json!({"ok": true, "pid": std::process::id()})
            }
            other => json!({"ok": false, "error": format!("unknown command: {other}")}),
        };

        writeln!(writer, "{response}")?;
        writer.flush()?;
    }
    Ok(())
}

pub fn spawn(name: String) {
    std::thread::spawn(move || {
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

static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn on_getpid(_regs: *mut ca_gum::SavedRegs, _data: *mut c_void) {
    HOOK_HITS.fetch_add(1, Ordering::SeqCst);
}

fn hook_getpid() -> Value {
    HOOK_HITS.store(0, Ordering::SeqCst);
    // SAFETY: dlsym with a NUL-terminated symbol name.
    let target = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"getpid".as_ptr()) } as usize;
    if target == 0 {
        return json!({"ok": false, "error": "dlsym(getpid) failed"});
    }

    // SAFETY: user_data is null; the callback only touches an atomic.
    let hook = unsafe { InlineHook::attach(target, on_getpid, ptr::null_mut()) };
    let mut hook = match hook {
        Ok(hook) => hook,
        Err(err) => return json!({"ok": false, "error": format!("attach: {err}")}),
    };

    for _ in 0..5 {
        // SAFETY: plain libc call.
        unsafe {
            libc::getpid();
        }
    }
    let hits = HOOK_HITS.load(Ordering::SeqCst);
    let detached = hook.detach().is_ok();
    json!({"ok": hits >= 5 && detached, "hits": hits, "detach": detached})
}
