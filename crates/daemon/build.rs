use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let target = env::var("TARGET").unwrap_or_default();
    let gz_path = out.join("agent.so.gz");
    if target.contains("android") {
        let so = env::var("AGENT_SO").map(PathBuf::from).unwrap_or_else(|_| {
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()))
                .join("../../target/aarch64-linux-android/release/libagent.so")
        });
        println!("cargo:rerun-if-changed={}", so.display());
        if !so.is_file() {
            panic!(
                "android daemon embeds {}: not found. Build the agent first with ./build.sh",
                so.display()
            );
        }
        let gz = Command::new("gzip")
            .args(["-c", "-n"])
            .arg(&so)
            .output()
            .unwrap_or_else(|err| panic!("gzip: {err}"));
        if !gz.status.success() {
            panic!(
                "gzip {} failed: {}",
                so.display(),
                String::from_utf8_lossy(&gz.stderr)
            );
        }
        fs::write(&gz_path, gz.stdout).unwrap_or_else(|err| panic!("write agent blob: {err}"));
    } else {
        fs::write(&gz_path, []).unwrap_or_else(|err| panic!("write empty agent blob: {err}"));
    }
    fs::write(
        out.join("agent_blob.rs"),
        "pub static AGENT_GZ: &[u8] = include_bytes!(\"agent.so.gz\");\n",
    )
    .unwrap_or_else(|err| panic!("write agent_blob.rs: {err}"));
}
