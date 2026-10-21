# QBDI payload for the Android agent

The agent links QBDI **statically**; it does not load TAL. The engine
wrappers live in CommToolkit:

- `../CommToolkit/crates/qbdi-sys` — bindgen C API bindings plus the
  `comm_check_and_break` shim and `clear_cache.c`.
- `../CommToolkit/crates/qbdi-rs` — VM ownership, typed registers, callback
  contexts, memory views, and the 16 MiB host stack.
- `crates/qbdi` in this repo — the CommAnalyser trace session.

Build the agent with the QBDI payload:

```
export NDK=/root/Android/Sdk/ndk/27.2.12479018
export QBDI_PREFIX=/root/Spec/CommToolkit/native/qbdi/build-android
./build.sh
```

`QBDI_PREFIX` points at the QBDI build tree: it must contain `libQBDI.a`,
`include/`, and `include-static/`. If unset, `qbdi-sys` falls back to
`<CommToolkit>/native/qbdi/build-android`, then `build`. The QBDI sources
under `../CommToolkit/native/qbdi` are used to generate the headers and to
compile the private-header shim.

The agent Interceptor is the attach door. On the first `Trace.function` it
installs a one-shot Gum replacement on the target, runs the QBDI VM on a 16 MiB
host stack of its own, and returns to the caller's LR after the trace
completes. `native/qbdi/android-arm64/` holds an older prebuilt payload; it
is not used by the current build.
