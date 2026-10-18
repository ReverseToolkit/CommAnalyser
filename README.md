# CommAnalyser

ARM64 Android dynamic instrumentation framework (Rust).

> Status: M1 (attach injection) done.  Research and plan live in
> [`docs/00-research.md`](docs/00-research.md) and [`docs/01-plan.md`](docs/01-plan.md);
> M1 details in [`docs/02-m1.md`](docs/02-m1.md).

## Layout

- `crates/ca-core` — process/maps/modules/ranges.
- `crates/ca-arch-arm64` — instruction classification, writer, relocator.
- `crates/ca-gum` — Memory/Module/Process/Interceptor primitives.
- `crates/ca-js` — QuickJS runtime (rquickjs).
- `crates/ca-art` — ART engine (planned, M3).
- `crates/ca-qbdi` — QBDI native API (planned, M4).
- `crates/ca-inject` — ptrace/remote-call/memfd loader.
- `crates/ca-agent` — in-process payload (`cdylib`).
- `crates/ca-daemon` / `crates/ca-cli` — device daemon and host CLI.

## Build

```bash
cargo test --workspace
cargo build --workspace
```

Android cross-compile (M1+):

```bash
export NDK=/root/Android/Sdk/ndk/29.0.14206865
export PATH="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
cargo build --target aarch64-linux-android -p ca-agent -p ca-daemon -p ca-cli
```

## Status

- **M0 (done)**: workspace, `/proc` maps + modules, ARM64 instruction
  classification/writer/relocator, QuickJS eval, daemon/CLI JSON protocol.
- **M1 (done)**: ptrace attach, remote calls, memfd agent load via
  `android_dlopen_ext`, abstract-socket agent hello.  Validated on
  `282eb4e4` against `sleep` (shell domain) and `com.android.settings`
  (app domain), with the target alive and `TracerPid=0`.
- **M2 (in progress)**: pure-Rust AArch64 inline hook + resident agent +
  QuickJS eval.  Validated `hook_getpid` (5 hits, clean detach) and
  `eval 1+2` inside both `sleep` and `com.android.settings`.
  Details: [`docs/03-m2.md`](docs/03-m2.md).
- **M2c (done)**: QuickJS Frida-style `NativePointer` / `Memory` /
  `Process` / `Module` / `Thread`; validated against `sleep` and Settings.
  Details: [`docs/04-m2c.md`](docs/04-m2c.md).

Details: [`docs/02-m1.md`](docs/02-m1.md).

## Quick start

```bash
cargo test --workspace
cargo build --workspace

# device side (root shell)
adb push target/aarch64-linux-android/debug/ca-daemon /data/local/tmp/
adb push target/aarch64-linux-android/debug/libca_agent.so /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/ca-daemon; /data/local/tmp/ca-daemon --addr 127.0.0.1:17321 &'
adb forward tcp:17321 tcp:17321
./target/debug/ca --addr 127.0.0.1:17321 ps
./target/debug/ca --addr 127.0.0.1:17321 inject <pid> --agent /data/local/tmp/libca_agent.so
./target/debug/ca --addr 127.0.0.1:17321 eval <pid> '1+2'
./target/debug/ca --addr 127.0.0.1:17321 agent <pid> hook_getpid
```

QuickJS cross-compile needs libclang + the Android sysroot:

```bash
export LIBCLANG_PATH=$NDK/toolchains/llvm/prebuilt/linux-x86_64/lib
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot -target aarch64-linux-android24"
```

## Protocol (M0)

Line-delimited JSON over TCP:

```json
{"op":"ping"}
{"op":"version"}
{"op":"ps"}
{"op":"inject","pid":1234,"agent":"/data/local/tmp/libca_agent.so"}
```

`ca --addr 127.0.0.1:17321 ps` prints the process list.

## Non-goals (v0)

- Frida wire-protocol / `frida` CLI compatibility.
- `Stalker` Frida semantics (QBDI native API instead).
- Zygisk/spawn gating (attach first).
