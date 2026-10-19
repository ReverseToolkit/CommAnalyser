use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TAL_LIB_DIR");
    println!("cargo:rerun-if-changed=../../native/tal/build-android/CMakeFiles/tal.dir");
    println!("cargo:rerun-if-changed=../../native/tal/android-arm64/libtal.so");
    if std::env::var("CARGO_FEATURE_LINK").is_err() {
        return;
    }
    link_tal_static().unwrap_or_else(|err| panic!("TAL static link: {err}"));
}

fn link_tal_static() -> Result<(), String> {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let root = manifest.join("../..");
    let tal_build = std::env::var("TAL_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("native/tal/build-android"));
    let archive = ensure_tal_static(&tal_build)?;
    let search = archive
        .parent()
        .ok_or_else(|| "tal_static parent".to_owned())?;

    // Outline-atomic helpers in compiler_builtins read this flag and fall
    // back to LL/SC when it is zero. Defining it here, before that archive
    // is scanned, keeps compiler-rt's aarch64.c.o (and its .init_array
    // getauxval constructor) out of the link.
    let flag = lse_flag_archive(&tal_build)?;
    println!(
        "cargo:rustc-link-search=native={}",
        flag.parent().unwrap_or(search).display()
    );
    println!("cargo:rustc-link-lib=static:+whole-archive=aarch64_lse_flag");

    println!("cargo:rustc-link-search=native={}", search.display());
    println!(
        "cargo:rustc-link-search=native={}",
        tal_build.join("qbdi-src").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        tal_build.join("boost-lite/libs/context").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        root.join("native/tal/libs/frida-gum/android").display()
    );

    println!("cargo:rustc-link-lib=static:+whole-archive=tal_static");
    println!("cargo:rustc-link-lib=static=QBDI");
    println!("cargo:rustc-link-lib=static=qbdi-llvm");
    println!("cargo:rustc-link-lib=static=boost_context");
    println!("cargo:rustc-link-lib=static=frida-gum");
    println!("cargo:rustc-link-lib=dylib=c++_shared");
    println!("cargo:rustc-link-lib=dylib=log");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=c");
    Ok(())
}

fn ensure_tal_static(tal_build: &Path) -> Result<PathBuf, String> {
    let archive = tal_build.join("libtal_static.a");
    let mut objs = Vec::new();
    collect_objs(&tal_build.join("CMakeFiles/tal.dir"), &mut objs);
    if objs.is_empty() {
        if archive.exists() {
            return Ok(archive);
        }
        return Err(format!(
            "no TAL objects under {}",
            tal_build.join("CMakeFiles/tal.dir").display()
        ));
    }
    let ar = ndk_ar();
    let status = Command::new(&ar)
        .arg("crs")
        .arg(&archive)
        .args(&objs)
        .status()
        .map_err(|err| format!("{ar}: {err}"))?;
    if !status.success() {
        return Err(format!("{ar} crs libtal_static.a failed: {status}"));
    }
    Ok(archive)
}

fn collect_objs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_objs(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("o") {
            out.push(path);
        }
    }
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
