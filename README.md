# CommAnalyser

ARM64 Android dynamic instrumentation framework (Rust).

> Status: M1 (attach injection) done.  Research and plan live in
> [`docs/00-research.md`](docs/00-research.md) and [`docs/01-plan.md`](docs/01-plan.md);
> M1 details in [`docs/02-m1.md`](docs/02-m1.md).

## Layout

- `crates/runtime` — process/maps/modules/ranges.
- `crates/arch-arm64` — instruction classification, writer, relocator.
- `crates/gum` — Memory/Module/Process/Interceptor primitives.
- `crates/js` — QuickJS runtime (rquickjs).
- `crates/art` — ART engine (planned, M3).
- `crates/qbdi` — QBDI native API (planned, M4).
- `crates/inject` — ptrace/remote-call/memfd loader.
- `crates/agent` — in-process payload (`cdylib`).
- `crates/daemon` / `crates/cli` — device daemon and host CLI.

## Build

```bash
cargo test --workspace
cargo build --workspace
```

Android cross-compile (M1+):

```bash
export NDK=/root/Android/Sdk/ndk/29.0.14206865
export PATH="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
cargo build --target aarch64-linux-android -p agent -p daemon -p cli
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
- **M2d (done)**: dedicated JS worker + `Interceptor.attach` with synchronous
  `onEnter`, `this.context` and `args`; validated in `sleep` and Settings.
  Details: [`docs/05-m2d.md`](docs/05-m2d.md).
- **M2e (done)**: grouped listeners, `onLeave` via a shared return stub, and
  `retval.replace`; validated in `sleep` and Settings.
  Details: [`docs/06-m2e.md`](docs/06-m2e.md).
- **M2f/M2g (done)**: `NativeFunction` + `NativeCallback` via hand-written
  ARM64 stubs (no libffi), signed/pointer args, IFUNC export fix.
  Details: [`docs/07-m2f.md`](docs/07-m2f.md).
- **M2h (done)**: `send` and `rpc.exports` over the agent channel,
  validated in `sleep` and Settings.
  Details: [`docs/08-m2h.md`](docs/08-m2h.md).
- **M3a (done)**: JNI VM discovery, Android 15 ArtMethod layout probing,
  and a minimal `ArtMethod` entrypoint hook validated on Settings.
  Details: [`docs/09-m3a.md`](docs/09-m3a.md).
- **M3b (partial)**: `Java.perform`, `Java.use` with JNI reflection,
  constructors, static/instance calls, string/int/long/boolean marshalling.
  Details: [`docs/10-m3b.md`](docs/10-m3b.md).
- **M3c (partial)**: Java `implementation` via ArtMethod entrypoint hooks and
  the QuickJS worker; validated by replacing `StringBuilder.length()`.
  Details: [`docs/11-m3c.md`](docs/11-m3c.md).
- **M3d (partial)**: Java hook now receives `this` and int/long/bool/char/
  byte/short/String arguments; validated with `charAt` and `bitCount`.
  Details: [`docs/12-m3d.md`](docs/12-m3d.md).
- **M3e (partial)**: `implementation = null` detaches a Java hook; public
  constructor preference and ctor diagnostics. `$new("...")` for
  StringBuilder/StringBuffer remains unresolved.
  Details: [`docs/13-m3e.md`](docs/13-m3e.md).
- **M3f (done)**: `Java.use` falls back to the app `ClassLoader`, so Settings
  and settingslib classes load from the APK.
  Details: [`docs/14-m3f.md`](docs/14-m3f.md).
- **M3g (done)**: fixed `$new("...")` for StringBuilder/StringBuffer by
  preserving the JS-selected constructor; constructors now use the
  high-level signature-based `NewObject`.
  Details: [`docs/15-m3g.md`](docs/15-m3g.md).
- **M3h (partial)**: `Java.use(...).FIELD.value` for public static fields
  (`Integer.MAX_VALUE`, `Build.MODEL`).
  Details: [`docs/16-m3h.md`](docs/16-m3h.md).
- **M3i (done)**: instance/static Java fields with getter and setter
  (`Build.MODEL.value`, `Message.what.value`).
  Details: [`docs/17-m3i.md`](docs/17-m3i.md).

Details: [`docs/02-m1.md`](docs/02-m1.md).

## Quick start

```bash
cargo test --workspace
cargo build --workspace

# device side (root shell)
adb push target/aarch64-linux-android/debug/daemon /data/local/tmp/
adb push target/aarch64-linux-android/debug/libagent.so /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/daemon; /data/local/tmp/daemon --addr 127.0.0.1:17321 &'
adb forward tcp:17321 tcp:17321
./target/debug/comm-analyser --addr 127.0.0.1:17321 ps
./target/debug/comm-analyser --addr 127.0.0.1:17321 inject <pid> --agent /data/local/tmp/libagent.so
./target/debug/comm-analyser --addr 127.0.0.1:17321 eval <pid> '1+2'
./target/debug/comm-analyser --addr 127.0.0.1:17321 agent <pid> hook_getpid
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
{"op":"inject","pid":1234,"agent":"/data/local/tmp/libagent.so"}
```

`comm-analyser --addr 127.0.0.1:17321 ps` prints the process list.

## Non-goals (v0)

- Frida wire-protocol / `frida` CLI compatibility.
- `Stalker` Frida semantics (QBDI native API instead).
- Zygisk/spawn gating (attach first).
