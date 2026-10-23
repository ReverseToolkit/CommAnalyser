#!/bin/sh
# Build the arm64 Zygisk module. The public header comes from CommZygisk.
set -eu
cd "$(dirname "$0")"
: "${ANDROID_NDK_HOME:=${NDK:-/root/Android/Sdk/ndk/27.2.12479018}}"
: "${COMMZYGISK:=$(cd ../../CommZygisk && pwd)}"
PREBUILT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
CXX="$PREBUILT/bin/aarch64-linux-android24-clang++"
SYSROOT="$PREBUILT/sysroot"
mkdir -p out
"$CXX" -std=c++20 -fPIC -shared -fvisibility=hidden \
    -I"$COMMZYGISK/loader/src/include" \
    --sysroot="$SYSROOT" \
    module.cpp -o out/arm64-v8a.so \
    -static-libstdc++ -llog -ldl
echo "built $(pwd)/out/arm64-v8a.so"
