//! CommAnalyser host CLI (M0: ping/version/ps).

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::ExitCode;

use serde_json::{json, Value};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut addr = "127.0.0.1:17321".to_owned();
    let mut token: Option<String> = None;
    let mut command: Option<String> = None;
    let mut rest = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next().ok_or("missing --addr value")?,
            "--token" => token = args.next(),
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other if command.is_none() && !other.starts_with('-') => {
                command = Some(other.to_owned())
            }
            other => rest.push(other.to_owned()),
        }
    }

    let command = command.ok_or_else(|| {
        "usage: ca [--addr HOST:PORT] [--token TOKEN] <ping|version|ps|attach|inject|agent|eval|call|rpc>"
            .to_owned()
    })?;

    let request = match command.as_str() {
        "ping" => json!({"op": "ping"}),
        "version" => json!({"op": "version"}),
        "ps" => json!({"op": "ps"}),
        "attach" => {
            let pid = rest
                .first()
                .ok_or("usage: ca attach <pid>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            json!({"op": "attach", "pid": pid})
        }
        "inject" => {
            let pid = rest
                .first()
                .ok_or("usage: ca inject <pid> [--agent PATH]")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let agent = rest
                .iter()
                .position(|v| v == "--agent")
                .and_then(|i| rest.get(i + 1))
                .map(String::as_str)
                .unwrap_or("/data/local/tmp/libca_agent.so");
            json!({"op": "inject", "pid": pid, "agent": agent})
        }
        "agent" => {
            let pid = rest
                .first()
                .ok_or("usage: ca agent <pid> <command>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let command = rest.get(1).ok_or("usage: ca agent <pid> <command>")?;
            json!({"op": "agent", "pid": pid, "command": command})
        }
        "rpc" => {
            let pid = rest
                .first()
                .ok_or("usage: ca rpc <pid> <name> [json-args]")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let name = rest
                .get(1)
                .ok_or("usage: ca rpc <pid> <name> [json-args]")?;
            let args = rest
                .get(2)
                .map(|text| serde_json::from_str::<Value>(text))
                .transpose()
                .map_err(|err| format!("invalid args: {err}"))?
                .unwrap_or_else(|| json!([]));
            json!({"op": "rpc", "pid": pid, "name": name, "args": args})
        }
        "call" => {
            let pid = rest
                .first()
                .ok_or("usage: ca call <pid> <address> <arg>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let address = rest.get(1).ok_or("usage: ca call <pid> <address> <arg>")?;
            let address = address
                .strip_prefix("0x")
                .or_else(|| address.strip_prefix("0X"))
                .unwrap_or(address);
            let address =
                u64::from_str_radix(address, 16).map_err(|_| "invalid address".to_owned())?;
            let arg = rest
                .get(2)
                .map(String::as_str)
                .unwrap_or("0")
                .parse::<i64>()
                .map_err(|_| "invalid arg".to_owned())?;
            json!({"op": "call", "pid": pid, "address": address, "arg": arg})
        }
        "eval" => {
            let pid = rest
                .first()
                .ok_or("usage: ca eval <pid> <expression>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let code = rest[1..].join(" ");
            if code.is_empty() {
                return Err("usage: ca eval <pid> <expression>".to_owned());
            }
            json!({"op": "eval", "pid": pid, "code": code})
        }
        other => return Err(format!("unknown command: {other}")),
    };

    let mut request = request;
    if let Some(token) = token {
        request["token"] = Value::String(token);
    }

    let response = call(&addr, &request)?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("request failed");
        return Err(err.to_owned());
    }

    if let Some(messages) = response.get("messages").and_then(Value::as_array) {
        for message in messages {
            eprintln!("[send] {message}");
        }
    }

    match command.as_str() {
        "ps" => {
            if let Some(processes) = response.get("processes").and_then(Value::as_array) {
                for p in processes {
                    let pid = p.get("pid").and_then(Value::as_u64).unwrap_or(0);
                    let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                    if let Err(err) = writeln!(io::stdout(), "{pid:>7}  {name}") {
                        if err.kind() == io::ErrorKind::BrokenPipe {
                            return Ok(());
                        }
                        return Err(err.to_string());
                    }
                }
            }
        }
        "version" => {
            let text = format!(
                "ca-daemon {} ({})",
                response
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                response.get("arch").and_then(Value::as_str).unwrap_or("?")
            );
            let _ = writeln!(io::stdout(), "{text}");
        }
        "rpc" => {
            let value = response
                .get("response")
                .and_then(|response| response.get("value"))
                .cloned()
                .unwrap_or(Value::Null);
            let _ = writeln!(io::stdout(), "{value}");
        }
        _ => {
            let _ = writeln!(io::stdout(), "{response}");
        }
    }
    Ok(())
}

fn call(addr: &str, request: &Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect(addr).map_err(|err| format!("connect {addr}: {err}"))?;
    let line = serde_json::to_string(request).map_err(|err| err.to_string())?;
    stream
        .write_all(line.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|err| format!("send: {err}"))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("recv: {err}"))?;
    if response.trim().is_empty() {
        return Err("empty response".to_owned());
    }
    serde_json::from_str(&response).map_err(|err| format!("bad response: {err}"))
}

fn print_help() {
    println!(
        "usage: ca [--addr HOST:PORT] [--token TOKEN] <command>\n\
         \n\
         commands:\n\
           ping              check daemon liveness\n\
           version           daemon version/arch\n\
           ps                list processes\n\
           attach <pid>      attach to a process (M1)\n"
    );
}
