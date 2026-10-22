# CommAnalyser

ARM64 Android dynamic instrumentation framework (Rust).

A host CLI talks newline-delimited JSON to a root daemon on the device.
The daemon stops the target, maps `libagent.so` with an in-tree ELF linker,
and leaves a QuickJS worker inside the process. Hooks go through frida-gum.
Function traces go through QBDI. Both engines live in the sibling
`../CommToolkit` checkout.

> Status: M0–M4b are done. M5 (hardening) is in tree. `Java` `original()`
> walks the quick ABI. `detach` still answers `detach: M2`. Research and the
> milestone notes are in [`docs/`](docs/).

## Layout

- `crates/runtime` — `/proc` maps, modules, threads, page patches, FFI panic guard.
- `crates/arch-arm64` — instruction classification, writer, relocator. `NativeFunction` and `NativeCallback` emit stubs with this writer.
- `crates/js` — QuickJS (rquickjs) and the Frida-shaped API, one worker thread.
- `crates/art` — JNI, ArtMethod hooks, quick-ABI to JNI (SOA).
- `crates/il2cpp` — IL2CPP runtime bridge (`Il2Cpp` in scripts): domain, classes, methods, fields, strings, GC. Port of frida-il2cpp-bridge. It reads `il2cpp_*` from `libil2cpp.so` and does not parse `global-metadata.dat`.
- `crates/qbdi` — the trace session (`Trace.function`). The VM wrapper is `qbdi-rs`.
- `crates/inject` — ptrace, remote calls, custom ELF loader, spawn-then-inject.
- `crates/agent` — in-process payload (`cdylib`, entry `agent_main`).
- `crates/daemon` / `crates/cli` — device daemon and host CLI `comm-analyser`.

The engine wrappers **live in `../CommToolkit`** (path dependency):

- `crates/qbdi-sys` — bindgen QBDI C API bindings, `comm_check_and_break` shim, `clear_cache.c`, build script.
- `crates/qbdi-rs` — safe QBDI wrapper: typed registers, callback contexts, memory views, 16 MiB host stack.
- `crates/gum-rs` — safe frida-gum wrapper: `InlineHook`, replace, memory primitives. `crates/gum` was removed. `../CommToolkit/native/gum` and `../CommToolkit/native/qbdi` must be built (see below).

## Runtime

```
comm-analyser  -- TCP 127.0.0.1:17321, one JSON object per line
    daemon     -- abstract Unix socket  agent-<pid>-<nonce>
    libagent.so
        QuickJS worker
        gum InlineHook / replace
        ART / Java
        QBDI trace session
```

`inject` binds the abstract socket, stops the target's threads, and maps the
agent: `PT_LOAD`, relocations, `DT_INIT` / `init_array`, then a remote call
to `agent_main`. The agent connects back with `hello`. The daemon stores the
channel and resumes the threads. `Session` drop resumes threads and leaves
the mapped image in the target.

The agent is not a file on the device. `crates/daemon/build.rs` gzip-embeds
`libagent.so` into the Android daemon, and `inject` inflates that blob.
`libc++` is archived into the agent. The remaining `DT_NEEDED` entries
(`libc.so`, `libm.so`, `libdl.so`, `liblog.so`) are already in the target.
A host build of the daemon embeds an empty gzip.

`spawn` starts a package (`am`) or an executable, then runs the same inject.
There is no zygote gate.

JS eval, hooks, and `rpc.exports` run on one worker thread. A hook on
another thread posts a job to that worker. `send` payloads ride back on the
same agent reply as `messages`. One pid has one channel; a timeout or a
short read closes it so a late line cannot pair with the next request.

## Build

```bash
# `js` links frida-gum; its unit tests only link for Android (see
# docs/21-hardening.md for the device command).
cargo test --workspace --exclude js
cargo build --workspace
```

Android cross-compile:

```bash
export NDK=/root/Android/Sdk/ndk/27.2.12479018
export PATH="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
./build.sh                       # agent (qbdi-static) then daemon, release
```

The engine build needs a sibling `../CommToolkit` checkout with its native
submodules initialized and built:

```bash
git -C ../CommToolkit submodule update --init native/gum native/qbdi
# frida-gum: cd ../CommToolkit/native/gum && ./configure --host=android-arm64 && make
# QBDI: see ../CommToolkit/README.md
./build.sh    # sets GUM_PREFIX / QBDI_PREFIX and the NDK bindgen env
```

`build.sh` builds the agent with `--features qbdi-static` (QBDI + frida-gum),
then the daemon, which gzip-embeds that `libagent.so`. Host builds do not
link the native engines. Use `cargo test --workspace --exclude js` for host
tests (the JS API needs the frida-gum archive to link).

Release profile: thin LTO, `opt-level = z`, `panic = unwind`, `strip = none`.
Unwind stays on because `agent_main`, Gum trampolines, and QBDI callbacks
catch panics with `runtime::ffi::guard`.

QuickJS cross-compile needs libclang and the Android sysroot:

```bash
export LIBCLANG_PATH=$NDK/toolchains/llvm/prebuilt/linux-x86_64/lib
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot -target aarch64-linux-android24"
```

## Status

- **M0 (done)**: workspace, `/proc` maps + modules, ARM64 instruction classification/writer/relocator, QuickJS eval, daemon/CLI JSON protocol.
- **M1 (done)**: ptrace attach, remote calls, abstract-socket agent hello. Validated on `282eb4e4` against `sleep` (shell domain) and `com.android.settings` (app domain), with the target alive and `TracerPid=0`. That milestone loaded the agent with memfd and `android_dlopen_ext`. Inject now uses the custom ELF linker in `crates/inject`. Details: [`docs/02-m1.md`](docs/02-m1.md).
- **M2 (done)**: resident agent and QuickJS eval. Validated `hook_getpid` (5 hits) and `eval 1+2` inside both `sleep` and `com.android.settings`. The hook backend in this milestone was a pure-Rust trampoline; M4b moved hooks to frida-gum. Details: [`docs/03-m2.md`](docs/03-m2.md).
- **M2c (done)**: QuickJS Frida-style `NativePointer` / `Memory` / `Process` / `Module` / `Thread`; validated against `sleep` and Settings. Details: [`docs/04-m2c.md`](docs/04-m2c.md).
- **M2d (done)**: dedicated JS worker + `Interceptor.attach` with synchronous `onEnter`, `this.context` and `args`; validated in `sleep` and Settings. Details: [`docs/05-m2d.md`](docs/05-m2d.md).
- **M2e (done)**: grouped listeners, `onLeave` via a shared return stub, and `retval.replace`; validated in `sleep` and Settings. Details: [`docs/06-m2e.md`](docs/06-m2e.md).
- **M2f/M2g (done)**: `NativeFunction` + `NativeCallback` via hand-written ARM64 stubs (no libffi), signed/pointer args, IFUNC export fix. Details: [`docs/07-m2f.md`](docs/07-m2f.md).
- **M2h (done)**: `send` and `rpc.exports` over the agent channel, validated in `sleep` and Settings. Details: [`docs/08-m2h.md`](docs/08-m2h.md).
- **M3a (done)**: JNI VM discovery, Android 15 ArtMethod layout probing, and a minimal `ArtMethod` entrypoint hook validated on Settings. Details: [`docs/09-m3a.md`](docs/09-m3a.md).
- **M3b (partial)**: `Java.perform`, `Java.use` with JNI reflection, constructors, static/instance calls, string/int/long/boolean marshalling. Details: [`docs/10-m3b.md`](docs/10-m3b.md).
- **M3c (partial)**: Java `implementation` via ArtMethod entrypoint hooks and the QuickJS worker; validated by replacing `StringBuilder.length()`. Details: [`docs/11-m3c.md`](docs/11-m3c.md).
- **M3d (partial)**: Java hook receives `this` and int/long/bool/char/byte/short/String arguments; validated with `charAt` and `bitCount`. Details: [`docs/12-m3d.md`](docs/12-m3d.md).
- **M3e (partial)**: `implementation = null` detaches a Java hook; public constructor preference and ctor diagnostics. `$new("...")` for StringBuilder/StringBuffer was fixed in M3g. Details: [`docs/13-m3e.md`](docs/13-m3e.md).
- **M3f (done)**: `Java.use` falls back to the app `ClassLoader`, so Settings and settingslib classes load from the APK. Details: [`docs/14-m3f.md`](docs/14-m3f.md).
- **M3g (done)**: `$new("...")` for StringBuilder/StringBuffer keeps the JS-selected constructor; constructors use signature-based `NewObject`. Details: [`docs/15-m3g.md`](docs/15-m3g.md).
- **M3h (partial)**: `Java.use(...).FIELD.value` for public static fields (`Integer.MAX_VALUE`, `Build.MODEL`). Details: [`docs/16-m3h.md`](docs/16-m3h.md).
- **M3i (done)**: instance/static Java fields with getter and setter (`Build.MODEL.value`, `Message.what.value`). Details: [`docs/17-m3i.md`](docs/17-m3i.md).
- **M3j**: an ArtMethod-clone `original()` was blocked on quick-ABI raw object conversion, and the stable hooks were restored. The current `original()` walks that ABI in `crates/js/src/java.rs` (see M5). Details: [`docs/18-m3j.md`](docs/18-m3j.md).
- **M4a (done)**: QBDI Rust split into `qbdi-sys` (raw FFI plus the native shim), `qbdi-rs` (owned VM, typed registers, panic-safe Rust closures as callbacks), and `qbdi` (the CommAnalyser trace session). Details: [`docs/19-m4-qbdi-rs.md`](docs/19-m4-qbdi-rs.md).
- **M4b (done)**: the engine crates moved to `../CommToolkit`. CommAnalyser keeps the trace session and consumes `qbdi-sys` / `qbdi-rs` / `gum-rs` by path. Hooks, patch, and memory go through frida-gum. Validated on `282eb4e4` in `sleep`: `Trace.function` (sqrt/ilogb/hypot), the gum suite, and the JS suite. Details: [`docs/20-m4b-engine-consolidation.md`](docs/20-m4b-engine-consolidation.md).
- **M5 (in tree)**: panic containment at ABI boundaries, one trace session at a time, the target runs once through a Gum replacement, deferred teardown, exact page-protection restore, W^X stubs cached per hook id, bounded event batches, and an interruptible JS worker (timers and pending jobs). Daemon failures invalidate the affected agent channel. `NativeCallback` entries stay for the life of the process. Details: [`docs/21-hardening.md`](docs/21-hardening.md).

## Quick start

```bash
cargo test --workspace --exclude js
cargo build --workspace
./build.sh                       # release agent, then the daemon that embeds it

# device side (root shell). The pushed daemon already contains libagent.so.
adb push target/aarch64-linux-android/release/daemon /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/daemon; /data/local/tmp/daemon --addr 127.0.0.1:17321 &'
adb forward tcp:17321 tcp:17321
./target/debug/comm-analyser --addr 127.0.0.1:17321 ps
./target/debug/comm-analyser --addr 127.0.0.1:17321 inject <pid>
./target/debug/comm-analyser --addr 127.0.0.1:17321 eval <pid> '1+2'
./target/debug/comm-analyser --addr 127.0.0.1:17321 agent <pid> hook_getpid
./target/debug/comm-analyser --addr 127.0.0.1:17321 selftest <pid> js
```

`selftest` suites are `runtime`, `gum`, `js`, `trace`, and `java`. A suite
argument is a layer or a `layer.case` prefix. Failed cases exit 1.

## Protocol

Line-delimited JSON over TCP. Global flags: `--addr HOST:PORT`, `--token TOKEN`.
When the daemon is started with `--token`, every request must carry the same
`token` field.

```json
{"op":"ping"}
{"op":"version"}
{"op":"ps"}
{"op":"inject","pid":1234}
{"op":"spawn","package":"com.android.settings"}
{"op":"spawn","exec":"/system/bin/sleep","args":["30"]}
{"op":"eval","pid":1234,"code":"1+2"}
{"op":"rpc","pid":1234,"name":"add","args":[1,2]}
{"op":"agent","pid":1234,"command":"hook_getpid"}
{"op":"selftest","pid":1234,"suite":"js"}
```

`inject` takes a pid. The agent bytes come from the daemon.
`attach` answers `attach: use inject`. `detach` answers `detach: M2`.

CLI commands: `ping`, `version`, `ps`, `attach`, `inject`, `spawn`, `agent`,
`eval`, `rpc`, `selftest`. `ps`, `version`, `rpc`, and `selftest` are
formatted. The other commands print the daemon JSON. `spawn` is
`--package NAME` or `--exec PATH [-- args]`.

## Script surface

Installed on the worker when the agent is built with `gum-static`:

- `ptr`, `NULL`, `int64`, `uint64`, `Memory`, `Process`, `Module`, `Thread`
- `NativeFunction`, `NativeCallback` (hand-written ARM64 stubs)
- `Interceptor.attach` / `replace` / `revert` / `flush` / `detachAll`
- `Instruction.parse`, `DebugSymbol`, `Arm64Writer`
- `Java` (`perform`, `use`, fields, `implementation`, `original`)
- `Trace.function` / `Trace.exclude`. `file` writes the batch when the traced call returns (`events=` / `dropped=` header, then one line per event)
- `send`, `recv`, `rpc.exports`, `setTimeout` / `setInterval`

`CModule(source[, symbols])` compiles `source` with TinyCC and exposes each global as a `NativePointer`. `dispose()` frees it. Unknown `extern` symbols come from `symbols` or from the process (`malloc`, `strlen`, …). `Script.bindWeak` returns 0.

## Limits

- No unload. `detach` is the M2 error, and a failed inject still leaves the mapped agent after threads resume.
- The host daemon has an empty embedded agent. Android `inject` needs a daemon built by `./build.sh` after the agent.
- `Script.bindWeak` is a stub.
- `NativeCallback` stubs are not freed.
- Spawn does not stop the new process before `Application.onCreate`.

## Non-goals (v0)

- Frida wire-protocol / `frida` CLI compatibility.
- `Stalker.follow` (function-level QBDI via `Trace.function`).
- Zygote spawn gating.
