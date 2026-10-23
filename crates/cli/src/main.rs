//! CommAnalyser host CLI (M0: ping/version/ps).

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::ExitCode;

use serde_json::{json, Value};

const USAGE: &str = "usage: comm-analyser [--addr HOST:PORT] [--token TOKEN] <ping|version|ps|attach|inject|spawn|agent|eval|rpc|selftest|dumpso>";

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

    let command = command.ok_or_else(|| USAGE.to_owned())?;

    let request = command_to_json(&command, &rest)?;

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
                "daemon {} ({})",
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
        "selftest" => print_selftest(&response)?,
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
        "usage: comm-analyser [--addr HOST:PORT] [--token TOKEN] <command>\n\
         \n\
         commands:\n\
           ping              check daemon liveness\n\
           version           daemon version/arch\n\
           ps                list processes\n\
           attach <pid>      attach to a process (M1)\n\
           inject <pid>      inject agent into a running pid\n\
           spawn --package P | --exec PATH [args]   start then inject\n\
           agent <pid> <command>  send a command to an injected agent\n\
           eval <pid> <expression>  evaluate JS in the agent\n\
           rpc <pid> <name> [json-args]  invoke rpc.exports\n\
           selftest <pid> [suite]  run in-process agent tests\n\
           dumpso <pid> <module> <path>  dump a loaded so and repair the ELF\n"
    );
}

fn print_selftest(response: &Value) -> Result<(), String> {
    let body = response.get("response").unwrap_or(response);
    let cases = body
        .get("cases")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for case in &cases {
        let layer = case.get("layer").and_then(Value::as_str).unwrap_or("?");
        let name = case.get("name").and_then(Value::as_str).unwrap_or("?");
        let detail = case.get("detail").and_then(Value::as_str).unwrap_or("");
        let status = match case.get("ok") {
            Some(Value::Bool(true)) => "PASS",
            Some(Value::Bool(false)) => "FAIL",
            _ => "SKIP",
        };
        let _ = writeln!(io::stdout(), "{status:4}  {layer}.{name}  {detail}");
    }
    let passed = body.get("passed").and_then(Value::as_u64).unwrap_or(0);
    let failed = body.get("failed").and_then(Value::as_u64).unwrap_or(0);
    let skipped = body.get("skipped").and_then(Value::as_u64).unwrap_or(0);
    let _ = writeln!(
        io::stdout(),
        "summary  passed={passed} failed={failed} skipped={skipped}"
    );
    if body.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("{failed} selftest case(s) failed"));
    }
    Ok(())
}

/// Map a CLI command and remaining argv into the daemon JSON request body.
fn command_to_json(command: &str, rest: &[String]) -> Result<Value, String> {
    match command {
        "ping" => Ok(json!({"op": "ping"})),
        "version" => Ok(json!({"op": "version"})),
        "ps" => Ok(json!({"op": "ps"})),
        "attach" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser attach <pid>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            Ok(json!({"op": "attach", "pid": pid}))
        }
        "inject" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser inject <pid>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            if rest.len() != 1 {
                return Err("usage: comm-analyser inject <pid>".to_owned());
            }
            Ok(json!({"op": "inject", "pid": pid}))
        }
        "spawn" => spawn_request(rest),
        "agent" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser agent <pid> <command>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let command = rest
                .get(1)
                .ok_or("usage: comm-analyser agent <pid> <command>")?;
            Ok(json!({"op": "agent", "pid": pid, "command": command}))
        }
        "rpc" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser rpc <pid> <name> [json-args]")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let name = rest
                .get(1)
                .ok_or("usage: comm-analyser rpc <pid> <name> [json-args]")?;
            let args = rest
                .get(2)
                .map(|text| serde_json::from_str::<Value>(text))
                .transpose()
                .map_err(|err| format!("invalid args: {err}"))?
                .unwrap_or_else(|| json!([]));
            Ok(json!({"op": "rpc", "pid": pid, "name": name, "args": args}))
        }
        "eval" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser eval <pid> <expression>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let code = rest[1..].join(" ");
            if code.is_empty() {
                return Err("usage: comm-analyser eval <pid> <expression>".to_owned());
            }
            Ok(json!({"op": "eval", "pid": pid, "code": code}))
        }
        "dumpso" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser dumpso <pid> <module> <path>")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let module = rest
                .get(1)
                .ok_or("usage: comm-analyser dumpso <pid> <module> <path>")?;
            let path = rest
                .get(2)
                .ok_or("usage: comm-analyser dumpso <pid> <module> <path>")?;
            Ok(json!({"op": "dumpso", "pid": pid, "module": module, "path": path}))
        }
        "selftest" => {
            let pid = rest
                .first()
                .ok_or("usage: comm-analyser selftest <pid> [suite]")?
                .parse::<u32>()
                .map_err(|_| "invalid pid".to_owned())?;
            let mut request = json!({"op": "selftest", "pid": pid});
            if let Some(suite) = rest.get(1) {
                request["suite"] = Value::String(suite.clone());
            }
            Ok(request)
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn spawn_request(rest: &[String]) -> Result<Value, String> {
    let mut package = None;
    let mut exec = None;
    let mut args = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--package" => {
                i += 1;
                package = Some(rest.get(i).ok_or("usage: spawn --package NAME")?.clone());
            }
            "--exec" => {
                i += 1;
                exec = Some(rest.get(i).ok_or("usage: spawn --exec PATH")?.clone());
            }
            "--" => {
                args.extend(rest[i + 1..].iter().cloned());
                break;
            }
            other if package.is_none() && exec.is_none() => {
                if other.contains('.') && !other.contains('/') {
                    package = Some(other.to_owned());
                } else {
                    exec = Some(other.to_owned());
                }
            }
            other => args.push(other.to_owned()),
        }
        i += 1;
    }
    if package.is_none() && exec.is_none() {
        return Err(
            "usage: spawn --package NAME | --exec PATH [-- args]".to_owned(),
        );
    }
    Ok(json!({
        "op": "spawn",
        "package": package,
        "exec": exec,
        "args": args
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn every_usage_command_maps_to_json_op() {
        assert_eq!(command_to_json("ping", &[]).unwrap()["op"], "ping");
        assert_eq!(command_to_json("version", &[]).unwrap()["op"], "version");
        assert_eq!(command_to_json("ps", &[]).unwrap()["op"], "ps");

        let attach = command_to_json("attach", &args(&["42"])).unwrap();
        assert_eq!(attach["op"], "attach");
        assert_eq!(attach["pid"], 42);

        let inject = command_to_json("inject", &args(&["7"])).unwrap();
        assert_eq!(inject["op"], "inject");
        assert_eq!(inject["pid"], 7);
        assert!(inject.get("agent").is_none());
        assert!(command_to_json("inject", &args(&["7", "--agent", "/tmp/a.so"])).is_err());

        let spawn = command_to_json("spawn", &args(&["--package", "com.foo"])).unwrap();
        assert_eq!(spawn["op"], "spawn");
        assert_eq!(spawn["package"], "com.foo");

        let spawn_exec =
            command_to_json("spawn", &args(&["--exec", "/bin/sleep", "--", "5"])).unwrap();
        assert_eq!(spawn_exec["exec"], "/bin/sleep");
        assert_eq!(spawn_exec["args"][0], "5");

        let agent = command_to_json("agent", &args(&["9", "ping"])).unwrap();
        assert_eq!(agent["op"], "agent");
        assert_eq!(agent["pid"], 9);
        assert_eq!(agent["command"], "ping");

        let eval = command_to_json("eval", &args(&["3", "1", "+", "2"])).unwrap();
        assert_eq!(eval["op"], "eval");
        assert_eq!(eval["pid"], 3);
        assert_eq!(eval["code"], "1 + 2");

        let rpc = command_to_json("rpc", &args(&["5", "add", "[1,2]"])).unwrap();
        assert_eq!(rpc["op"], "rpc");
        assert_eq!(rpc["name"], "add");
        assert_eq!(rpc["args"][1], 2);

        let selftest = command_to_json("selftest", &args(&["6", "runtime"])).unwrap();
        assert_eq!(selftest["op"], "selftest");
        assert_eq!(selftest["pid"], 6);
        assert_eq!(selftest["suite"], "runtime");
    }

    #[test]
    fn unknown_command_and_missing_fields_are_errors() {
        assert!(command_to_json("nope", &[])
            .unwrap_err()
            .contains("unknown command"));
        assert!(command_to_json("attach", &[]).is_err());
        assert!(command_to_json("eval", &args(&["1"])).is_err());
        assert!(command_to_json("spawn", &[]).is_err());
    }

    #[test]
    fn help_lists_every_usage_command() {
        for command in [
            "ping", "version", "ps", "attach", "inject", "spawn", "agent", "eval", "rpc",
            "selftest", "dumpso",
        ] {
            assert!(USAGE.contains(command), "{command}");
        }
    }
}
