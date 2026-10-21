#!/bin/sh
# Build the arm64 Android agent only. Toolchain paths live in .cargo/config.toml.
set -eu
cd "$(dirname "$0")"

# CommToolkit owns the engine crates; point their build scripts at the
# prebuilt native archives. Override either variable to use another tree.
: "${ANDROID_NDK_HOME:=${NDK:-/root/Android/Sdk/ndk/27.2.12479018}}"
: "${QBDI_PREFIX:=$(cd ../CommToolkit && pwd)/native/qbdi/build-android}"
: "${GUM_PREFIX:=$(cd ../CommToolkit && pwd)/native/gum/deps/sdk-android-arm64}"
export ANDROID_NDK_HOME QBDI_PREFIX GUM_PREFIX
export PKG_CONFIG_PATH="$GUM_PREFIX/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export COMMTOOLKIT_PKG_CONFIG_ARGS=--define-prefix
export BINDGEN_EXTRA_CLANG_ARGS="--target=aarch64-linux-android24 --sysroot=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

cargo build --release --target aarch64-linux-android -p agent --features qbdi-static "$@"
exec cargo build --release --target aarch64-linux-android -p daemon "$@"
