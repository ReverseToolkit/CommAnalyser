//! Build TinyCC for the crate target and stage `libtcc.a` plus `libtcc1.a`.
//!
//! The compiler library runs in-process and emits code for that same
//! architecture. `libtcc1.a` is the target runtime helpers; on Android it is
//! produced by a host cross-tcc because the device `tcc` binary cannot run here.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("native/tinycc");
    println!("cargo:rerun-if-changed={}", source.display());

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let stage = if target.contains("android") {
        build_android(&source, &out)
    } else {
        build_host(&source, &out)
    };
    println!("cargo:rustc-link-search=native={}", stage.display());
    println!("cargo:rustc-link-lib=static=tcc");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
    if !target.contains("android") {
        println!("cargo:rustc-link-lib=dylib=pthread");
    }
    println!(
        "cargo:rustc-env=CA_LIBTCC1={}",
        stage.join("libtcc1.a").display()
    );
}

fn build_host(source: &Path, out: &Path) -> PathBuf {
    let dir = out.join("tinycc-host");
    copy_tree(source, &dir);
    let status = Command::new("sh")
        .arg("-c")
        .arg("./configure --extra-cflags=-fPIC && make -j$(nproc) libtcc.a libtcc1.a")
        .current_dir(&dir)
        .status()
        .expect("configure host tinycc");
    assert!(status.success(), "host tinycc build failed");
    dir
}

fn build_android(source: &Path, out: &Path) -> PathBuf {
    let ndk = env::var("NDK")
        .or_else(|_| env::var("ANDROID_NDK_HOME"))
        .unwrap_or_else(|_| "/root/Android/Sdk/ndk/27.2.12479018".into());
    let prebuilt = PathBuf::from(&ndk).join("toolchains/llvm/prebuilt/linux-x86_64");
    let cc = prebuilt.join("bin/aarch64-linux-android24-clang");
    let ar = prebuilt.join("bin/llvm-ar");
    let sysroot = prebuilt.join("sysroot");
    assert!(cc.is_file(), "NDK clang missing at {}", cc.display());

    let host = out.join("tinycc-host");
    copy_tree(source, &host);
    let host_status = Command::new("sh")
        .arg("-c")
        .arg("./configure --extra-cflags=-fPIC && make -j$(nproc) arm64-libtcc1.a")
        .current_dir(&host)
        .status()
        .expect("host cross libtcc1");
    assert!(host_status.success(), "arm64 libtcc1 build failed");

    let dir = out.join("tinycc-android");
    copy_tree(source, &dir);
    let cflags = format!("--sysroot={} -fPIC -O2", sysroot.display());
    let script = format!(
        "CC='{cc}' AR='{ar}' CFLAGS='{cflags}' LDFLAGS='--sysroot={sys}' ./configure --cpu=aarch64 && gcc -DC2STR conftest.c -o c2str.exe && ./c2str.exe include/tccdefs.h tccdefs_.h && make -o c2str.exe -j$(nproc) libtcc.a && cp '{host1}' libtcc1.a",
        cc = cc.display(),
        ar = ar.display(),
        sys = sysroot.display(),
        host1 = host.join("arm64-libtcc1.a").display(),
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .current_dir(&dir)
        .status()
        .expect("android tinycc build");
    assert!(status.success(), "android tinycc build failed");
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    let _ = fs::remove_dir_all(to);
    let status = Command::new("cp")
        .args(["-a", &from.display().to_string(), &to.display().to_string()])
        .status()
        .expect("copy tinycc");
    assert!(status.success(), "copy tinycc sources failed");
}
