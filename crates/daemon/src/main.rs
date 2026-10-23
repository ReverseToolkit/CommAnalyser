//! CommAnalyser device daemon.
//!
//! M0 speaks a line-delimited JSON protocol and implements `ping`, `version`
//! and `ps`.  Script/attach operations are added in M1.

mod control_server;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use flate2::read::GzDecoder;

use inject::AttachOptions;

include!(concat!(env!("OUT_DIR"), "/agent_blob.rs"));

struct AgentChannel {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

// An I/O failure invalidates framing. Keep that state on the channel itself
// so requests already waiting for its mutex cannot reuse a stale response.
type SharedChannel = Arc<Mutex<Option<AgentChannel>>>;

fn agents() -> &'static Mutex<HashMap<u32, SharedChannel>> {
    static AGENTS: OnceLock<Mutex<HashMap<u32, SharedChannel>>> = OnceLock::new();
    AGENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct AgentReply {
    value: Value,
    messages: Vec<Value>,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
// The worker allows 10 seconds for eval/rpc, including its 8-second JS budget.
const AGENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

fn main() -> ExitCode {
    let mut addr = "127.0.0.1:17321".to_owned();
    let mut token: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => match args.next() {
                Some(v) => addr = v,
                None => {
                    eprintln!("missing --addr value");
                    return ExitCode::from(2);
                }
            },
            "--token" => token = args.next(),
            "-h" | "--help" => {
                println!("usage: daemon [--addr 127.0.0.1:17321] [--token TOKEN]");
                println!("  the agent is the gzip blob embedded in this binary");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let listener = match TcpListener::bind(&addr) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("bind {addr}: {err}");
            return ExitCode::from(1);
        }
    };
    println!("LISTEN {addr}");
    let _ = std::io::stdout().flush();

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let token = token.clone();
                std::thread::spawn(move || {
                    if let Err(err) = serve(stream, token.as_deref()) {
                        eprintln!("connection: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept: {err}"),
        }
    }
    ExitCode::SUCCESS
}

fn serve(stream: TcpStream, token: Option<&str>) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_request(&line, token);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

/// Handle one JSON request and return one JSON response line.
pub fn handle_request(line: &str, token: Option<&str>) -> String {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(err) => return error_response(format!("invalid json: {err}")),
    };

    if let Some(expected) = token {
        let got = request.get("token").and_then(Value::as_str);
        if got != Some(expected) {
            return error_response("unauthorized".to_owned());
        }
    }

    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    match op {
        "ping" => json!({"ok": true, "pong": true}).to_string(),
        "version" => {
            json!({"ok": true, "version": VERSION, "arch": runtime::process::arch()}).to_string()
        }
        "ps" => {
            let processes: Vec<Value> = list_processes()
                .into_iter()
                .map(|p| json!({"pid": p.pid, "name": p.name}))
                .collect();
            json!({"ok": true, "processes": processes}).to_string()
        }
        "attach" => error_response("attach: use inject".to_owned()),
        "detach" => error_response("detach: M2".to_owned()),
        "inject" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            match inject(pid) {
                Ok(hello) => json!({"ok": true, "pid": pid, "hello": hello}).to_string(),
                Err(err) => error_response(format!("inject: {err}")),
            }
        }
        "spawn" => {
            let package = request.get("package").and_then(Value::as_str);
            let exec = request.get("exec").and_then(Value::as_str);
            let args = request
                .get("args")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            match spawn(package, exec, &args) {
                Ok((pid, hello)) => json!({
                    "ok": true,
                    "pid": pid,
                    "hello": hello,
                    "spawn": true
                })
                .to_string(),
                Err(err) => error_response(format!("spawn: {err}")),
            }
        }
        "agent" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let command = request.get("command").and_then(Value::as_str).unwrap_or("");
            match agent_command(pid, command) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response.value,
                    "messages": response.messages,
                })
                .to_string(),
                Err(err) => error_response(format!("agent: {err}")),
            }
        }
        "rpc" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let name = request.get("name").and_then(Value::as_str).unwrap_or("");
            let args = request.get("args").cloned().unwrap_or_else(|| json!([]));
            match agent_request(pid, &json!({"op": "rpc", "name": name, "args": args})) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response.value,
                    "messages": response.messages,
                })
                .to_string(),
                Err(err) => error_response(format!("rpc: {err}")),
            }
        }
        "selftest" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let suite = request.get("suite").and_then(Value::as_str);
            let mut body = json!({"op": "selftest"});
            if let Some(suite) = suite {
                body["suite"] = Value::String(suite.to_owned());
            }
            match agent_request(pid, &body) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response.value,
                    "messages": response.messages,
                })
                .to_string(),
                Err(err) => error_response(format!("selftest: {err}")),
            }
        }
        "dumpso" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let module = request.get("module").and_then(Value::as_str).unwrap_or("");
            let path = request.get("path").and_then(Value::as_str).unwrap_or("");
            if module.is_empty() || path.is_empty() {
                error_response("dumpso: module and path are required".to_owned())
            } else {
                match sofix::dump_pid(pid, module, path) {
                    Ok(report) => json!({
                        "ok": true,
                        "pid": pid,
                        "base": report.base,
                        "size": report.size,
                        "path": report.path,
                    })
                    .to_string(),
                    Err(err) => error_response(format!("dumpso: {err}")),
                }
            }
        }
        "eval" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let code = request.get("code").and_then(Value::as_str).unwrap_or("");
            match agent_request(pid, &json!({"op": "eval", "code": code})) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response.value,
                    "messages": response.messages,
                })
                .to_string(),
                Err(err) => error_response(format!("eval: {err}")),
            }
        }
        "" => error_response("missing op".to_owned()),
        other => error_response(format!("unknown op: {other}")),
    }
}

fn spawn(
    package: Option<&str>,
    exec: Option<&str>,
    args: &[String],
) -> Result<(u32, String), String> {
    let pid = if let Some(package) = package {
        inject::start_package(package).map_err(|err| format!("{err}"))?
    } else if let Some(path) = exec {
        inject::start_executable(path, args).map_err(|err| format!("{err}"))?
    } else {
        return Err("package or exec required".to_owned());
    };
    let hello = inject(pid)?;
    Ok((pid, hello))
}

fn embedded_agent() -> Result<Vec<u8>, String> {
    if AGENT_GZ.is_empty() {
        return Err("embedded agent is empty (build the android daemon after the agent)".into());
    }
    let mut decoder = GzDecoder::new(AGENT_GZ);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|err| format!("inflate agent: {err}"))?;
    if bytes.is_empty() {
        return Err("embedded agent is empty".into());
    }
    Ok(bytes)
}

fn inject(pid: u32) -> Result<String, String> {
    if pid == 0 {
        return Err("invalid pid".to_owned());
    }

    let socket_name = format!(
        "agent-{pid}-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            & 0xffff_ffff
    );
    let listener = control_server::Listener::bind(&socket_name)
        .map_err(|err| format!("bind {socket_name}: {err}"))?;

    // The agent is the gzip blob linked into this binary. Byte injection
    // requires every DT_NEEDED soname to already be mapped in the target.
    let options = AttachOptions::from_bytes(pid, embedded_agent()?)
        .with_config(socket_name.clone());
    let mut session = inject::attach(&options).map_err(|err| format!("{err}"))?;

    let stream = listener
        .accept_timeout(std::time::Duration::from_secs(5))
        .map_err(|err| format!("accept: {err}"))?
        .ok_or_else(|| "agent did not connect".to_owned())?;

    let hello = control_server::Listener::read_hello(&stream, std::time::Duration::from_secs(2))
        .map_err(|err| format!("hello: {err}"))?;

    stream
        .set_read_timeout(Some(AGENT_REQUEST_TIMEOUT))
        .map_err(|err| format!("set timeout: {err}"))?;
    stream
        .set_write_timeout(Some(AGENT_REQUEST_TIMEOUT))
        .map_err(|err| format!("set write timeout: {err}"))?;
    let reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|err| format!("clone agent stream: {err}"))?,
    );
    agents()
        .lock()
        .map_err(|_| "agent registry poisoned".to_owned())?
        .insert(
            pid,
            Arc::new(Mutex::new(Some(AgentChannel {
                writer: stream,
                reader,
            }))),
        );

    session.resume();
    Ok(hello)
}

fn agent_command(pid: u32, command: &str) -> Result<AgentReply, String> {
    if command.is_empty()
        || command.len() > 64
        || !command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err("invalid command".to_owned());
    }
    agent_request(pid, &json!({"op": command}))
}

fn agent_request(pid: u32, request: &Value) -> Result<AgentReply, String> {
    agent_request_with_timeout(pid, request, AGENT_REQUEST_TIMEOUT)
}

fn agent_request_with_timeout(
    pid: u32,
    request: &Value,
    timeout: Duration,
) -> Result<AgentReply, String> {
    let channel = agents()
        .lock()
        .map_err(|_| "agent registry poisoned".to_owned())?
        .get(&pid)
        .cloned()
        .ok_or_else(|| format!("no agent for pid {pid}"))?;
    let mut slot = channel
        .lock()
        .map_err(|_| "agent channel poisoned".to_owned())?;
    let live = slot
        .as_mut()
        .ok_or_else(|| "agent channel closed".to_owned())?;
    let response = live.request(request, timeout);
    if response.is_err() {
        // There is no request id on this protocol. A late or partial response
        // cannot safely be paired with another request on the same stream.
        if let Some(closed) = slot.take() {
            let _ = closed.writer.shutdown(std::net::Shutdown::Both);
        }
        let mut registry = agents()
            .lock()
            .map_err(|_| "agent registry poisoned".to_owned())?;
        if registry
            .get(&pid)
            .is_some_and(|current| Arc::ptr_eq(current, &channel))
        {
            registry.remove(&pid);
        }
    }
    response
}

impl AgentChannel {
    fn request(&mut self, request: &Value, timeout: Duration) -> Result<AgentReply, String> {
        let deadline = Instant::now() + timeout;
        let mut messages = Vec::new();
        let mut line = serde_json::to_string(request).map_err(|err| format!("encode: {err}"))?;
        line.push('\n');
        self.writer
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("set write timeout: {err}"))?;
        self.writer
            .write_all(line.as_bytes())
            .and_then(|_| self.writer.flush())
            .map_err(|err| format!("send: {err}"))?;

        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| "agent request timed out".to_owned())?;
            self.reader
                .get_ref()
                .set_read_timeout(Some(remaining))
                .map_err(|err| format!("set timeout: {err}"))?;
            let mut response = String::new();
            let n = self
                .reader
                .read_line(&mut response)
                .map_err(|err| format!("recv: {err}"))?;
            if n == 0 {
                return Err("agent closed the channel".to_owned());
            }
            let value: Value = serde_json::from_str(response.trim())
                .map_err(|err| format!("invalid agent response: {err}"))?;
            if value.get("op").and_then(Value::as_str) == Some("send") {
                messages.push(value.get("payload").cloned().unwrap_or(Value::Null));
                continue;
            }
            return Ok(AgentReply { value, messages });
        }
    }
}

fn error_response(message: String) -> String {
    json!({"ok": false, "error": message}).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInfo {
    pid: u32,
    name: String,
}

fn list_processes() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim_end().to_owned())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(ProcessInfo { pid, name });
    }
    out.sort_by_key(|p| p.pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_agent(pid: u32) -> (SharedChannel, UnixStream) {
        let (client, peer) = UnixStream::pair().unwrap();
        let channel = Arc::new(Mutex::new(Some(AgentChannel {
            reader: BufReader::new(client.try_clone().unwrap()),
            writer: client,
        })));
        agents().lock().unwrap().insert(pid, channel.clone());
        (channel, peer)
    }

    #[test]
    fn timeout_discards_the_channel_before_a_late_response() {
        let pid = 4_000_001;
        let (channel, mut peer) = fake_agent(pid);
        assert!(
            agent_request_with_timeout(pid, &json!({"op":"eval"}), Duration::from_millis(20))
                .is_err()
        );
        assert!(channel.lock().unwrap().is_none());
        assert!(!agents().lock().unwrap().contains_key(&pid));
        let _ = peer.write_all(b"{\"ok\":true,\"value\":\"first\"}\n");
        assert!(agent_request(pid, &json!({"op":"ping"})).is_err());
    }

    #[test]
    fn waiting_for_one_agent_does_not_block_another() {
        let slow_pid = 4_000_002;
        let fast_pid = 4_000_003;
        let (_, slow_peer) = fake_agent(slow_pid);
        let (_, mut fast_peer) = fake_agent(fast_pid);
        let slow = std::thread::spawn(move || {
            agent_request_with_timeout(slow_pid, &json!({"op":"eval"}), Duration::from_secs(2))
        });
        // Seeing the request proves the slow thread is inside its I/O path.
        let mut slow_reader = BufReader::new(slow_peer);
        slow_reader.read_line(&mut String::new()).unwrap();
        fast_peer
            .write_all(b"{\"op\":\"send\",\"payload\":\"fast\"}\n{\"ok\":true}\n")
            .unwrap();
        let (done, received) = std::sync::mpsc::channel();
        let fast = std::thread::spawn(move || {
            done.send(agent_request(fast_pid, &json!({"op":"ping"})))
                .ok();
        });
        let response = received.recv_timeout(Duration::from_secs(1));
        slow_reader
            .get_ref()
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
        assert!(slow.join().unwrap().is_err());
        fast.join().unwrap();
        agents().lock().unwrap().remove(&fast_pid);
        let response = response
            .expect("different agents must progress independently")
            .unwrap();
        assert_eq!(response.value["ok"], true);
        assert_eq!(response.messages, vec![json!("fast")]);
    }

    #[test]
    fn invalid_response_discards_channel() {
        let pid = 4_000_004;
        let (channel, mut peer) = fake_agent(pid);
        peer.write_all(b"not-json\n").unwrap();
        assert!(agent_request(pid, &json!({"op":"ping"})).is_err());
        assert!(channel.lock().unwrap().is_none());
        assert!(!agents().lock().unwrap().contains_key(&pid));
    }

    #[test]
    fn ping_works() {
        let response = handle_request(r#"{"op":"ping"}"#, None);
        let value: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["pong"], true);
    }

    #[test]
    fn unknown_op_is_error() {
        let response = handle_request(r#"{"op":"nope"}"#, None);
        let value: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["ok"], false);
    }

    #[test]
    fn token_is_enforced() {
        let response = handle_request(r#"{"op":"ping"}"#, Some("secret"));
        let value: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["ok"], false);

        let response = handle_request(r#"{"op":"ping","token":"secret"}"#, Some("secret"));
        let value: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn ps_includes_self() {
        let response = handle_request(r#"{"op":"ps"}"#, None);
        let value: Value = serde_json::from_str(&response).unwrap();
        let wanted = std::process::id() as u64;
        assert!(value["processes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["pid"] == wanted));
    }

    fn parsed(line: &str) -> Value {
        serde_json::from_str(&handle_request(line, None)).unwrap()
    }

    #[test]
    fn version_reports_package_and_arch() {
        let value = parsed(r#"{"op":"version"}"#);
        assert_eq!(value["ok"], true);
        assert_eq!(value["version"], VERSION);
        assert_eq!(value["arch"], runtime::process::arch());
        assert!(!value["arch"].as_str().unwrap().is_empty());
    }

    #[test]
    fn missing_op_and_invalid_json_are_structured_errors() {
        let missing = parsed("{}");
        assert_eq!(missing["ok"], false);
        assert_eq!(missing["error"], "missing op");

        let bad: Value = serde_json::from_str(&handle_request("not-json", None)).unwrap();
        assert_eq!(bad["ok"], false);
        assert!(
            bad["error"].as_str().unwrap().contains("invalid json"),
            "{bad}"
        );
    }

    #[test]
    fn attach_is_redirected_to_inject() {
        let value = parsed(r#"{"op":"attach","pid":1}"#);
        assert_eq!(value["ok"], false);
        assert!(
            value["error"].as_str().unwrap().contains("use inject"),
            "{value}"
        );
    }

    #[test]
    fn ops_without_session_return_ok_false() {
        for (line, needle) in [
            (
                r#"{"op":"inject","pid":1}"#,
                "inject:",
            ),
            (r#"{"op":"spawn"}"#, "spawn:"),
            (r#"{"op":"agent","pid":1,"command":"ping"}"#, "agent:"),
            (r#"{"op":"eval","pid":1,"code":"1"}"#, "eval:"),
            (r#"{"op":"rpc","pid":1,"name":"add","args":[]}"#, "rpc:"),
            (
                r#"{"op":"selftest","pid":1,"suite":"runtime"}"#,
                "selftest:",
            ),
            (
                r#"{"op":"dumpso","pid":1,"module":"libc.so","path":"/tmp/a.so"}"#,
                "dumpso:",
            ),
        ] {
            let value = parsed(line);
            assert_eq!(value["ok"], false, "{line} -> {value}");
            let error = value["error"].as_str().unwrap();
            assert!(error.contains(needle), "{line} -> {error}");
        }
    }
}
