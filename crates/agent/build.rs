use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }
    // LLVM calls __clear_cache after writing executable pages. Define it here
    // so the cdylib does not pull compiler-rt's .init_array.
    println!("cargo:rerun-if-changed=clear_cache.c");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let obj = out.join("clear_cache.o");
    let cc = ndk_tool("aarch64-linux-android24-clang");
    let status = Command::new(&cc)
        .args(["-c", "clear_cache.c", "-fno-builtin", "-O2", "-o"])
        .arg(&obj)
        .status()
        .unwrap_or_else(|err| panic!("clear_cache.c: failed to run {cc}: {err}"));
    if !status.success() {
        panic!("clear_cache.c compile failed: {status}");
    }
    println!("cargo:rustc-link-arg={}", obj.display());
}

fn ndk_tool(name: &str) -> String {
    let ndk = std::env::var("ANDROID_NDK_HOME")
        .or_else(|_| std::env::var("NDK"))
        .unwrap_or_else(|_| "/root/Android/Sdk/ndk/27.2.12479018".into());
    format!("{ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/{name}")
}
