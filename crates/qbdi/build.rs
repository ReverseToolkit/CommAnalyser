use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::Compression;

fn main() {
    println!("cargo:rerun-if-env-changed=TAL_LIB_DIR");
    println!("cargo:rerun-if-changed=../../native/tal/android-arm64/libtal.so");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let blob = out.join("libtal.so.gz");
    let cxx = out.join("libc++_shared.so.gz");
    if std::env::var("CARGO_FEATURE_LINK").is_err() {
        write_empty_blob(&blob);
        write_empty_blob(&cxx);
        return;
    }
    println!("cargo:rustc-link-lib=dylib=dl");
    match compress_tal(&blob) {
        Ok(()) => {}
        Err(err) => {
            println!("cargo:warning=TAL shared payload: {err}");
            write_empty_blob(&blob);
        }
    }
    match compress_cxx(&cxx) {
        Ok(()) => {}
        Err(err) => {
            println!("cargo:warning=libc++_shared payload: {err}");
            write_empty_blob(&cxx);
        }
    }
}

fn write_empty_blob(blob: &Path) {
    let _ = File::create(blob).and_then(|mut f| f.write_all(&[]));
}

fn compress_tal(blob: &Path) -> Result<(), String> {
    let dir = std::env::var("TAL_LIB_DIR").unwrap_or_else(|_| {
        format!(
            "{}/native/tal/android-arm64",
            std::env::var("CARGO_MANIFEST_DIR")
                .map(|manifest| format!("{manifest}/../.."))
                .unwrap_or_else(|_| ".".into())
        )
    });
    let so = PathBuf::from(dir).join("libtal.so");
    if !so.exists() {
        return Err(format!("{} missing", so.display()));
    }
    let input = File::open(&so).map_err(|err| err.to_string())?;
    let output = File::create(blob).map_err(|err| err.to_string())?;
    let mut encoder = GzEncoder::new(BufWriter::new(output), Compression::best());
    std::io::copy(&mut BufReader::new(input), &mut encoder).map_err(|err| err.to_string())?;
    encoder.finish().map_err(|err| err.to_string())?;
    Ok(())
}

fn compress_cxx(blob: &Path) -> Result<(), String> {
    let ndk = PathBuf::from(
        std::env::var_os("ANDROID_NDK_HOME")
            .or_else(|| std::env::var_os("NDK_PATH"))
            .or_else(|| std::env::var_os("ANDROID_NDK"))
            .unwrap_or_else(|| "/root/Android/Sdk/ndk/27.2.12479018".into()),
    );
    let so = ndk.join(
        "toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so",
    );
    if !so.exists() {
        return Err(format!("{} missing", so.display()));
    }
    let input = File::open(&so).map_err(|err| err.to_string())?;
    let output = File::create(blob).map_err(|err| err.to_string())?;
    let mut encoder = GzEncoder::new(BufWriter::new(output), Compression::best());
    std::io::copy(&mut BufReader::new(input), &mut encoder).map_err(|err| err.to_string())?;
    encoder.finish().map_err(|err| err.to_string())?;
    Ok(())
}
