#!/bin/sh
# Build the arm64 Android agent only. Toolchain paths live in .cargo/config.toml.
set -eu
cd "$(dirname "$0")"

exec cargo build --release --target aarch64-linux-android -p agent --features qbdi-static "$@"
