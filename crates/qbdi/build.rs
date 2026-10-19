fn main() {
    println!("cargo:rerun-if-env-changed=QBDI_LIB_DIR");
    println!("cargo:rerun-if-changed=../../native/qbdi/android-arm64/libQBDI.a");
    if std::env::var("CARGO_FEATURE_LINK").is_err() {
        return;
    }
    let dir = std::env::var("QBDI_LIB_DIR").unwrap_or_else(|_| {
        format!(
            "{}/native/qbdi/android-arm64",
            std::env::var("CARGO_MANIFEST_DIR")
                .map(|manifest| format!("{manifest}/../.."))
                .unwrap_or_else(|_| ".".into())
        )
    });
    let archive = format!("{dir}/libQBDI.a");
    if !std::path::Path::new(&archive).exists() {
        println!("cargo:warning=QBDI static library not found at {archive}; link feature needs it");
    }
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=QBDI");
    let ndk = std::env::var_os("ANDROID_NDK_HOME")
        .or_else(|| std::env::var_os("NDK_PATH"))
        .or_else(|| std::env::var_os("ANDROID_NDK"))
        .unwrap_or_else(|| "/root/Android/Sdk/ndk/27.2.12479018".into());
    let stl = std::path::PathBuf::from(ndk)
        .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android");
    println!("cargo:rustc-link-search=native={}", stl.display());
    println!(
        "cargo:rustc-link-search=native={}",
        stl.join("24").display()
    );
    println!("cargo:rustc-link-lib=static=c++_static");
    println!("cargo:rustc-link-lib=static=c++abi");
    let builtins = std::path::PathBuf::from(
        "/root/Android/Sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/18/lib/linux",
    );
    println!("cargo:rustc-link-search=native={}", builtins.display());
    println!("cargo:rustc-link-lib=static=clang_rt.builtins-aarch64-android");
    println!("cargo:rustc-link-lib=log");
}
