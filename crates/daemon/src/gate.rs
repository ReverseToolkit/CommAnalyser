//! Zygisk companion asks this gate whether a specializing app should load the agent.
//!
//! The companion runs as root inside `zygiskd` and connects to the abstract
//! socket `ca-gate`. The app process itself never opens TCP.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::control_server::Listener;

pub const SOCKET_NAME: &str = "ca-gate";

struct Pending {
    socket: String,
    pid: u32,
    hello: Sender<Result<(u32, String), String>>,
}

fn armed() -> &'static Mutex<HashMap<String, Sender<Result<(u32, String), String>>>> {
    static ARMED: OnceLock<Mutex<HashMap<String, Sender<Result<(u32, String), String>>>>> =
        OnceLock::new();
    ARMED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Listen for companion claims. A bind failure is logged and the thread exits.
pub fn serve() {
    let listener = match Listener::bind(SOCKET_NAME) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("ca-gate bind: {err}");
            return;
        }
    };
    loop {
        let Ok(Some(stream)) = listener.accept_timeout(Duration::from_secs(60)) else {
            continue;
        };
        thread::spawn(move || {
            if let Err(err) = handle_client(stream) {
                eprintln!("ca-gate: {err}");
            }
        });
    }
}

/// Mark `package` so the next specialize loads the agent, start it, and wait
/// until that agent says hello.
pub fn launch(package: &str) -> Result<(u32, String), String> {
    let (tx, rx) = mpsc::channel();
    {
        let mut table = armed().lock().map_err(|_| "gate lock poisoned".to_owned())?;
        table.insert(package.to_owned(), tx);
    }
    if let Err(err) = inject::launch_package(package) {
        let _ = armed().lock().map(|mut table| table.remove(package));
        return Err(err.to_string());
    }
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(result) => result,
        Err(_) => {
            let _ = armed().lock().map(|mut table| table.remove(package));
            Err(format!("zygisk gate timed out for {package}"))
        }
    }
}

fn handle_client(stream: std::os::unix::net::UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|err| err.to_string())?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| err.to_string())?;
    eprintln!("ca-gate claim: {}", line.trim());
    let request: Value = serde_json::from_str(line.trim()).map_err(|err| err.to_string())?;
    let package = request
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or("");
    let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
    let reply = match prepare_claim(package, pid) {
        Some((pending, listener)) => {
            let socket = pending.socket.clone();
            thread::spawn(move || finish_pending(pending, listener));
            json!({"load": true, "socket": socket})
        }
        None => json!({"load": false}),
    };
    let mut writer = stream;
    writeln!(writer, "{reply}").map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())?;
    Ok(())
}

fn prepare_claim(package: &str, pid: u32) -> Option<(Pending, Listener)> {
    if package.is_empty() || pid == 0 {
        return None;
    }
    let tx = armed().lock().ok()?.remove(package)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        & 0xffff_ffff;
    let pending = Pending {
        socket: format!("agent-{pid}-{nonce:x}"),
        pid,
        hello: tx,
    };
    let listener = Listener::bind(&pending.socket).ok()?;
    Some((pending, listener))
}

fn finish_pending(pending: Pending, listener: Listener) {
    let result = (|| {
        let stream = listener
            .accept_timeout(Duration::from_secs(10))
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "agent did not connect".to_owned())?;
        let hello = crate::adopt_agent(pending.pid, stream)?;
        Ok((pending.pid, hello))
    })();
    let _ = pending.hello.send(result);
}

/// Answer one claim line. Used by tests; the socket server calls the same path.
pub fn claim_loads(package: &str) -> bool {
    armed()
        .lock()
        .map(|table| table.contains_key(package))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_package_is_not_armed() {
        assert!(!claim_loads("com.example.missing"));
    }
}
