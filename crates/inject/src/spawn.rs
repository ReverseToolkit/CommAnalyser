//! Start a new process (package or executable) so inject can attach it.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use runtime::{Error, Result};

use crate::pid_alive;

/// Start `path` with `args` and return the new pid.  The child is left
/// running; the caller injects then lets it continue.
pub fn start_executable(path: &str, args: &[String]) -> Result<u32> {
    let child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Error::Io)?;
    let pid = child.id();
    std::mem::forget(child);
    wait_for_libc(pid)?;
    Ok(pid)
}

/// Wait until the new process has mapped `libc.so` so inject can resolve mmap.
fn wait_for_libc(pid: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return Err(Error::Parse(format!("spawned pid {pid} died")));
        }
        if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            if text.contains("libc.so") {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(Error::Parse(format!(
        "spawned pid {pid} never mapped libc.so"
    )))
}

/// Force-stop `package`, launch it, and return the new pid.
///
/// Uses `am` / `monkey` which exist on the Android daemon.  This is start +
/// inject of the new pid, not zygote gating.
pub fn start_package(package: &str) -> Result<u32> {
    let before = pids_named(package);
    let _ = Command::new("am").args(["force-stop", package]).status();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        let now = pids_named(package);
        if now.iter().all(|pid| !before.contains(pid)) && now.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let started = Command::new("am")
        .args([
            "start",
            "-W",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
            package,
        ])
        .status();
    if started.as_ref().map(|s| !s.success()).unwrap_or(true) {
        let _ = Command::new("monkey")
            .args(["-p", package, "-c", "android.intent.category.LAUNCHER", "1"])
            .status();
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let now = pids_named(package);
        if let Some(pid) = now
            .into_iter()
            .find(|pid| !before.contains(pid) && pid_alive(*pid))
        {
            wait_for_libc(pid)?;
            return Ok(pid);
        }
        thread::sleep(Duration::from_millis(150));
    }
    Err(Error::Parse(format!(
        "spawn: package {package} did not start a new pid"
    )))
}

/// Pids whose `/proc/<pid>/cmdline` equals `name` or `name` as comm.
pub fn pids_named(name: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            let first = cmdline.split(|b| *b == 0).next().unwrap_or(&[]);
            let text = std::str::from_utf8(first).ok()?;
            if text == name || text.rsplit('/').next() == Some(name) {
                return Some(pid);
            }
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
            (comm.trim() == name).then_some(pid)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_sleep_executable() {
        let pid = start_executable("/bin/sleep", &["30".to_owned()]).unwrap();
        assert!(pid_alive(pid), "sleep pid {pid} should be alive");
        let named = pids_named("sleep");
        assert!(named.contains(&pid), "{named:?}");
        let _ = Command::new("kill").arg(pid.to_string()).status();
        assert!(start_executable("/no/such/commanalyser-exec", &[]).is_err());
        let comm = std::fs::read_to_string("/proc/self/comm").unwrap();
        let self_pids = pids_named(comm.trim());
        assert!(self_pids.contains(&std::process::id()), "{self_pids:?}");
    }
}
