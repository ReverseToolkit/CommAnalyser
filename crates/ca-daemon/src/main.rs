//! CommAnalyser device daemon.
//!
//! M0 speaks a line-delimited JSON protocol and implements `ping`, `version`
//! and `ps`.  Script/attach operations are added in M1.

mod control_server;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use ca_inject::AttachOptions;

struct AgentChannel {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

fn agents() -> &'static Mutex<HashMap<u32, AgentChannel>> {
    static AGENTS: OnceLock<Mutex<HashMap<u32, AgentChannel>>> = OnceLock::new();
    AGENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn messages() -> &'static Mutex<Vec<Value>> {
    static MESSAGES: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
    MESSAGES.get_or_init(|| Mutex::new(Vec::new()))
}

fn take_messages() -> Vec<Value> {
    messages()
        .lock()
        .map(|mut queue| std::mem::take(&mut *queue))
        .unwrap_or_default()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
                println!("usage: ca-daemon [--addr 127.0.0.1:17321] [--token TOKEN]");
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
            json!({"ok": true, "version": VERSION, "arch": ca_core::process::arch()}).to_string()
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
            let agent = request
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or("/data/local/tmp/libca_agent.so");
            match inject(pid, agent) {
                Ok(hello) => {
                    json!({"ok": true, "pid": pid, "agent": agent, "hello": hello}).to_string()
                }
                Err(err) => error_response(format!("inject: {err}")),
            }
        }
        "agent" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let command = request.get("command").and_then(Value::as_str).unwrap_or("");
            match agent_command(pid, command) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response,
                    "messages": take_messages(),
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
                    "response": response,
                    "messages": take_messages(),
                })
                .to_string(),
                Err(err) => error_response(format!("rpc: {err}")),
            }
        }
        "call" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let address = request.get("address").and_then(Value::as_u64).unwrap_or(0);
            let arg = request.get("arg").and_then(Value::as_i64).unwrap_or(0);
            match agent_request(
                pid,
                &json!({"op": "call_int1", "address": address, "arg": arg}),
            ) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response,
                    "messages": take_messages(),
                })
                .to_string(),
                Err(err) => error_response(format!("call: {err}")),
            }
        }
        "eval" => {
            let pid = request.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
            let code = request.get("code").and_then(Value::as_str).unwrap_or("");
            match agent_request(pid, &json!({"op": "eval", "code": code})) {
                Ok(response) => json!({
                    "ok": true,
                    "pid": pid,
                    "response": response,
                    "messages": take_messages(),
                })
                .to_string(),
                Err(err) => error_response(format!("eval: {err}")),
            }
        }
        "" => error_response("missing op".to_owned()),
        other => error_response(format!("unknown op: {other}")),
    }
}

fn inject(pid: u32, agent: &str) -> Result<String, String> {
    if pid == 0 {
        return Err("invalid pid".to_owned());
    }
    if !std::path::Path::new(agent).exists() {
        return Err(format!("agent not found: {agent}"));
    }

    let socket_name = format!(
        "ca-agent-{pid}-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            & 0xffff_ffff
    );
    let listener = control_server::Listener::bind(&socket_name)
        .map_err(|err| format!("bind {socket_name}: {err}"))?;

    let options = AttachOptions::new(pid, agent).with_config(socket_name.clone());
    let mut session = ca_inject::attach(&options).map_err(|err| format!("{err}"))?;

    let stream = listener
        .accept_timeout(std::time::Duration::from_secs(5))
        .map_err(|err| format!("accept: {err}"))?
        .ok_or_else(|| "agent did not connect".to_owned())?;

    let hello = control_server::Listener::read_hello(&stream, std::time::Duration::from_secs(2))
        .map_err(|err| format!("hello: {err}"))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|err| format!("set timeout: {err}"))?;
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
            AgentChannel {
                writer: stream,
                reader,
            },
        );

    session.resume();
    Ok(hello)
}

fn agent_command(pid: u32, command: &str) -> Result<Value, String> {
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

fn agent_request(pid: u32, request: &Value) -> Result<Value, String> {
    let mut registry = agents()
        .lock()
        .map_err(|_| "agent registry poisoned".to_owned())?;
    let channel = registry
        .get_mut(&pid)
        .ok_or_else(|| format!("no agent for pid {pid}"))?;

    let line = serde_json::to_string(request).map_err(|err| format!("encode: {err}"))?;
    channel
        .writer
        .write_all(line.as_bytes())
        .and_then(|_| channel.writer.write_all(b"\n"))
        .and_then(|_| channel.writer.flush())
        .map_err(|err| format!("send: {err}"))?;

    loop {
        let mut response = String::new();
        let n = channel
            .reader
            .read_line(&mut response)
            .map_err(|err| format!("recv: {err}"))?;
        if n == 0 {
            registry.remove(&pid);
            return Err("agent closed the channel".to_owned());
        }
        let value: Value = serde_json::from_str(response.trim())
            .unwrap_or_else(|_| json!({"raw": response.trim()}));
        if value.get("op").and_then(Value::as_str) == Some("send") {
            if let Ok(mut queue) = messages().lock() {
                queue.push(value.get("payload").cloned().unwrap_or(Value::Null));
            }
            continue;
        }
        return Ok(value);
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
}
