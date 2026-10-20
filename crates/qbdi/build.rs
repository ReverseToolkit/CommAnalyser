use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=QBDI_LIB_DIR");
    if std::env::var("CARGO_FEATURE_LINK").is_err() {
        return;
    }
    link_qbdi().unwrap_or_else(|err| panic!("QBDI static link: {err}"));
}

fn link_qbdi() -> Result<(), String> {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let root = manifest.join("../..");
    let qbdi = std::env::var("QBDI_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("native/tal/build-android/qbdi-src"));
    if !qbdi.join("libQBDI.a").is_file() {
        return Err(format!("missing {}", qbdi.join("libQBDI.a").display()));
    }

    // Outline-atomic helpers in compiler_builtins read this flag and fall
    // back to LL/SC when it is zero. Defining it here, before that archive
    // is scanned, keeps compiler-rt's aarch64.c.o (and its .init_array
    // getauxval constructor) out of the link.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let flag = lse_flag_archive(&out)?;
    println!(
        "cargo:rustc-link-search=native={}",
        flag.parent().unwrap_or(out.as_path()).display()
    );
    println!("cargo:rustc-link-lib=static:+whole-archive=aarch64_lse_flag");

    println!("cargo:rustc-link-search=native={}", qbdi.display());
    println!("cargo:rustc-link-lib=static=QBDI");
    println!("cargo:rustc-link-lib=static=qbdi-llvm");
    // NDK libc++ and unwind, inside the agent. The system libc++.so uses a
    // different ABI namespace, so it cannot satisfy these symbols.
    // Static libc++_static pulls scudo, and those constructors SIGSEGV
    // during inject. The NDK shared library keeps new/delete on bionic.
    println!("cargo:rustc-link-lib=dylib=c++_shared");
    println!("cargo:rustc-link-lib=dylib=log");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=c");
    Ok(())
}

fn lse_flag_archive(dir: &Path) -> Result<PathBuf, String> {
    let src = dir.join("lse_flag.S");
    let obj = dir.join("lse_flag.o");
    let archive = dir.join("libaarch64_lse_flag.a");
    std::fs::write(
        &src,
        r#"
.section .bss
.global __aarch64_have_lse_atomics
.type __aarch64_have_lse_atomics, %object
.p2align 2
__aarch64_have_lse_atomics:
.skip 1
.size __aarch64_have_lse_atomics, 1
"#,
    )
    .map_err(|err| format!("write lse_flag.S: {err}"))?;
    let cc = ndk_bin("aarch64-linux-android24-clang");
    let status = Command::new(&cc)
        .args(["-c", "-o"])
        .arg(&obj)
        .arg(&src)
        .status()
        .map_err(|err| format!("{cc}: {err}"))?;
    if !status.success() {
        return Err(format!("{cc} failed to assemble lse_flag.S: {status}"));
    }
    let ar = ndk_ar();
    let status = Command::new(&ar)
        .args(["crs", archive.to_str().unwrap_or("libaarch64_lse_flag.a")])
        .arg(&obj)
        .status()
        .map_err(|err| format!("{ar}: {err}"))?;
    if !status.success() {
        return Err(format!("{ar} failed to pack lse_flag: {status}"));
    }
    let _ = std::fs::remove_file(&src);
    Ok(archive)
}

fn ndk_bin(name: &str) -> String {
    let ndk = std::env::var("ANDROID_NDK_HOME")
        .or_else(|_| std::env::var("NDK"))
        .unwrap_or_else(|_| "/root/Android/Sdk/ndk/27.2.12479018".into());
    format!("{ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/{name}")
}

fn ndk_ar() -> String {
    std::env::var("AR")
        .or_else(|_| std::env::var("AR_aarch64_linux_android"))
        .unwrap_or_else(|_| {
            let ndk = std::env::var("ANDROID_NDK_HOME")
                .or_else(|_| std::env::var("NDK"))
                .unwrap_or_else(|_| "/root/Android/Sdk/ndk/27.2.12479018".into());
            format!("{ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar")
        })
}
