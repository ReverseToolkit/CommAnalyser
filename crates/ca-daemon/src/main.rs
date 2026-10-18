//! CommAnalyser device daemon.
//!
//! M0 speaks a line-delimited JSON protocol and implements `ping`, `version`
//! and `ps`.  Script/attach operations are added in M1.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use serde_json::{json, Value};

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
        "attach" => error_response("attach: M1".to_owned()),
        "detach" => error_response("detach: M1".to_owned()),
        "" => error_response("missing op".to_owned()),
        other => error_response(format!("unknown op: {other}")),
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
