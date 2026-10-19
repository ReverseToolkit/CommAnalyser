use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bionic_needed.c");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let obj = out.join("bionic_needed.o");
    let cc = std::env::var("CC")
        .or_else(|_| std::env::var("CC_aarch64_linux_android"))
        .unwrap_or_else(|_| "aarch64-linux-android24-clang".into());
    let status = Command::new(&cc)
        .args(["-c", "bionic_needed.c", "-o"])
        .arg(&obj)
        .status();
    match status {
        Ok(status) if status.success() => {
            println!("cargo:rustc-link-arg={}", obj.display());
        }
        Ok(status) => println!("cargo:warning=bionic_needed.c compile failed: {status}"),
        Err(err) => println!("cargo:warning=bionic_needed.c: {err}"),
    }

    println!("cargo:rerun-if-changed=clear_cache.c");
    let cache_obj = out.join("clear_cache.o");
    match Command::new(&cc)
        .args(["-c", "clear_cache.c", "-fno-builtin", "-O2", "-o"])
        .arg(&cache_obj)
        .status()
    {
        Ok(status) if status.success() => {
            println!("cargo:rustc-link-arg={}", cache_obj.display());
        }
        Ok(status) => println!("cargo:warning=clear_cache.c compile failed: {status}"),
        Err(err) => println!("cargo:warning=clear_cache.c: {err}"),
    }
}
