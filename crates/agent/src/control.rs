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
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use gum::InlineHook;
use js::JsWorker;

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
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = BufReader::new(stream);

    let (event_tx, event_rx) = mpsc::channel::<String>();
    let event_writer = writer.clone();
    std::thread::spawn(move || {
        for line in event_rx {
            let Ok(mut output) = event_writer.lock() else {
                break;
            };
            if output.write_all(line.as_bytes()).is_err()
                || output.write_all(b"\n").is_err()
                || output.flush().is_err()
            {
                break;
            }
        }
    });

    let worker = match JsWorker::spawn(event_tx) {
        Ok(worker) => Some(worker),
        Err(err) => {
            eprintln!("[agent] QuickJS init failed: {err}");
            None
        }
    };

    let hello = json!({
        "op": "hello",
        "pid": std::process::id(),
        "abi": crate::agent_abi_version(),
        "quickjs": worker.is_some(),
    });
    {
        let mut output = writer.lock().expect("agent writer poisoned");
        writeln!(output, "{hello}")?;
        output.flush()?;
    }

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
                let mut output = writer.lock().expect("agent writer poisoned");
                writeln!(output, "{response}")?;
                output.flush()?;
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
            "java_hook_install_test" => match art::java::hook_install_test() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_entrypoint" => match art::java::length_entrypoint() {
                Ok(value) => json!({"ok": true, "value": format!("{value:#x}")}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_ctor_helper" => match art::java::helper_ctor() {
                Ok(value) => json!({"ok": true, "value": value}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_ctor_highlevel" => match art::java::high_level_ctor() {
                Ok(value) => json!({"ok": true, "value": value}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_ctors" => match art::java::ctor_list() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_ref_debug" => match art::java::ref_debug() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_char_at" => match art::java::call_char_at() {
                Ok(value) => json!({"ok": true, "value": value}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_bit_count" => match art::java::call_bit_count() {
                Ok(value) => json!({"ok": true, "value": value}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_length" => match art::java::call_length() {
                Ok(value) => json!({"ok": true, "value": value}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_stub_info" => match art::stub_info() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_hook_probe" => match art::probe_hook() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "java_probe" => match art::probe() {
                Ok(text) => serde_json::from_str::<Value>(&text)
                    .unwrap_or_else(|_| json!({"ok": true, "raw": text})),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            },
            "rpc" => {
                let name = request.get("name").and_then(Value::as_str).unwrap_or("");
                let args = request
                    .get("args")
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "[]".to_owned());
                match worker.as_ref() {
                    Some(worker) => match worker.rpc(name, &args) {
                        Ok(text) => match serde_json::from_str::<Value>(&text) {
                            Ok(value) => json!({"ok": true, "value": value}),
                            Err(_) => json!({"ok": true, "value": text}),
                        },
                        Err(err) => json!({"ok": false, "error": err.to_string()}),
                    },
                    None => json!({"ok": false, "error": "QuickJS unavailable"}),
                }
            }
            "call_int1" => {
                let address = request.get("address").and_then(Value::as_u64).unwrap_or(0) as usize;
                let arg = request.get("arg").and_then(Value::as_i64).unwrap_or(0) as u64;
                if address == 0 {
                    json!({"ok": false, "error": "null callback"})
                } else {
                    // SAFETY: the caller passes a NativeCallback stub with this ABI.
                    let function: unsafe extern "C" fn(u64) -> u64 =
                        unsafe { std::mem::transmute(address) };
                    let result = unsafe { function(arg) };
                    json!({"ok": true, "result": result})
                }
            }
            "call_getpid" => {
                let mut last = 0;
                for _ in 0..5 {
                    // SAFETY: plain libc call; deliberately on this (non-JS) thread
                    // so a JS Interceptor hook can run on its own thread.
                    last = unsafe { libc::getpid() };
                }
                json!({"ok": true, "pid": last})
            }
            other => json!({"ok": false, "error": format!("unknown command: {other}")}),
        };

        let mut output = writer.lock().expect("agent writer poisoned");
        writeln!(output, "{response}")?;
        output.flush()?;
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
            eprintln!("[agent] control channel failed: {err}");
        }
    });
}

static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn on_getpid(_regs: *mut gum::SavedRegs, _data: *mut c_void) {
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
