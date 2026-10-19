# Static QBDI for the Android agent

Build `libQBDI.a` from `/root/refs/qbdi` (CMake ≥ 3.28) and place it here:

```
native/qbdi/android-arm64/libQBDI.a
```

Then:

```
cargo build --release --target aarch64-linux-android -p agent --features qbdi-static
```

The `link` feature emits `cargo:rustc-link-lib=static=QBDI`. The agent must not `dlopen("libQBDI.so")`.
