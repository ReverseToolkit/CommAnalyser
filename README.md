# CommAnalyser

ARM64 Android dynamic instrumentation framework in Rust.

A host CLI talks newline-delimited JSON to a root daemon on the device.
The daemon stops the target, maps `libagent.so` with an in-tree ELF linker,
and leaves a QuickJS worker in the process. Hooks go through frida-gum.
Function traces go through QBDI. Both engines live in the sibling
`../CommToolkit` checkout. Milestone notes are in [`docs/`](docs/).

## Layout

- `crates/runtime` — `/proc` maps, modules, threads, page patches, FFI panic guard.
- `crates/arch-arm64` — instruction classification, writer, relocator. `NativeFunction` and `NativeCallback` emit stubs with this writer.
- `crates/js` — QuickJS (rquickjs) and the Frida-shaped API, one worker thread. `CModule` compiles with the vendored TinyCC.
- `crates/art` — JNI, ArtMethod hooks, quick-ABI to JNI.
- `crates/il2cpp` — IL2CPP bridge (`Il2Cpp` in scripts). It resolves `il2cpp_*` from `libil2cpp.so` and does not parse `global-metadata.dat`.
- `crates/qbdi` — the trace session (`Trace.function`). The VM wrapper is `qbdi-rs`.
- `crates/inject` — ptrace, remote calls, custom ELF loader, spawn-then-inject.
- `crates/agent` — in-process payload (`cdylib`, entry `agent_main`).
- `crates/daemon` / `crates/cli` — device daemon and host CLI `comm-analyser`.

Engine wrappers are path dependencies on `../CommToolkit`:

- `crates/qbdi-sys` — bindgen QBDI C API, `comm_check_and_break`, `clear_cache.c`.
- `crates/qbdi-rs` — safe QBDI wrapper: typed registers, callback contexts, memory views, 16 MiB host stack.
- `crates/gum-rs` — safe frida-gum wrapper: `InlineHook`, replace, memory primitives.

`../CommToolkit/native/gum` and `../CommToolkit/native/qbdi` must already be built.

## Runtime

```
comm-analyser  -- TCP 127.0.0.1:17321, one JSON object per line
    daemon     -- abstract Unix socket  agent-<pid>-<nonce>
    libagent.so
        QuickJS worker
        gum InlineHook / replace
        ART / Java
        IL2CPP
        QBDI trace session
```

`inject` binds the abstract socket, stops the target's threads, and maps the
agent: `PT_LOAD`, relocations, `DT_INIT` / `init_array`, then a remote call
to `agent_main`. The agent connects back with `hello`. The daemon stores the
channel and resumes the threads. Dropping the session resumes threads and
leaves the mapped image in the target.

`libagent.so` is not a file on the device. `crates/daemon/build.rs`
gzip-embeds it into the Android daemon, and `inject` inflates that blob.
`libc++` is archived into the agent (`libc++_static` + `libc++abi`, symbols
kept local). The remaining `DT_NEEDED` entries are `liblog`, `libdl`, `libm`,
and `libc`. A host build of the daemon embeds an empty gzip.

`spawn` starts a package (`am`) or an executable, then runs the same inject.
There is no zygote gate.

JS eval, hooks, and `rpc.exports` run on one worker thread. A hook on
another thread posts a job to that worker. `send` payloads ride back on the
same agent reply as `messages`. One pid has one channel; a timeout or a
short read closes it so a late line cannot pair with the next request.

## Build

Host tests skip `js` because that crate links frida-gum:

```bash
cargo test --workspace --exclude js
cargo build --workspace
```

Android release build (agent with `--features qbdi-static`, then the daemon
that embeds it). `build.sh` points bindgen at the NDK and at the CommToolkit
archives. Override `ANDROID_NDK_HOME`, `GUM_PREFIX`, or `QBDI_PREFIX` when
the defaults do not match this machine.

```bash
git -C ../CommToolkit submodule update --init native/gum native/qbdi
# frida-gum: cd ../CommToolkit/native/gum && ./configure --host=android-arm64 && make
# QBDI: see ../CommToolkit/README.md
./build.sh
```

Release profile: thin LTO, `opt-level = z`, `panic = unwind`, `strip = none`.
Unwind stays on because `agent_main`, Gum trampolines, and QBDI callbacks
catch panics with `runtime::ffi::guard`.

## Quick start

```bash
adb push target/aarch64-linux-android/release/daemon /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/daemon; setsid /data/local/tmp/daemon --addr 127.0.0.1:17321 >/dev/null 2>&1 &'
adb forward tcp:17321 tcp:17321
./target/debug/comm-analyser --addr 127.0.0.1:17321 ps
./target/debug/comm-analyser --addr 127.0.0.1:17321 inject <pid>
./target/debug/comm-analyser --addr 127.0.0.1:17321 eval <pid> '1+2'
./target/debug/comm-analyser --addr 127.0.0.1:17321 selftest <pid> js
```

`selftest` suites are `runtime`, `gum`, `js`, `trace`, and `java`. `il2cpp`
runs only when requested (`selftest <pid> il2cpp`), so a process without
`libil2cpp.so` does not fail the other suites. A suite argument is a layer
or a `layer.case` prefix. Failed cases exit 1.

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
{"op":"dumpso","pid":1234,"module":"libc.so","path":"/data/local/tmp/libc.fix.so"}
```

`inject` takes a pid. The agent bytes come from the daemon.
`attach` answers `attach: use inject`. `detach` answers `detach: M2`.

CLI commands: `ping`, `version`, `ps`, `attach`, `inject`, `spawn`, `agent`,
`eval`, `rpc`, `selftest`, `dumpso`. `ps`, `version`, `rpc`, and `selftest` are
formatted. The other commands print the daemon JSON. `spawn --package` arms the package and lets the Zygisk module load the agent
in `postAppSpecialize`, before `Application.onCreate`. The module lives in
`zygisk/` and is loaded by CommZygisk. `spawn --exec` still injects after the
process is up. `dumpso` reads
`/proc/<pid>/mem` in the daemon and writes a repaired AArch64 ELF. The
script form `Module.dumpSo(path)` does the same read inside the target,
so `path` has to be writable by that process.

## Script surface

Installed on the Android agent (`qbdi-static`, which includes `gum-static`):

- `ptr`, `NULL`, `int64`, `uint64`, `Memory`, `Process`, `Module`, `Thread`
- `NativeFunction`, `NativeCallback` (hand-written ARM64 stubs)
- `Interceptor.attach` / `replace` / `revert` / `flush` / `detachAll`
- `Instruction.parse`, `DebugSymbol`, `Arm64Writer`
- `Java` (`perform`, `use`, fields, `implementation`, `original`)
- `Il2Cpp` (`perform`, classes, methods, fields, strings, `trace`, `gc`, `application`, plus `summary` / `assemblies` / `classes` / `methods` / `dump`)
- `Module.dumpSo(path)` dumps that loaded library and repairs the AArch64 ELF (relative relocations, `DT_RELR`, import slots)
- `Trace.function` / `Trace.exclude`. `file` writes the batch when the traced call returns (`events=` / `dropped=` header, then one line per event)
- `CModule(source[, symbols])` compiles with TinyCC and exposes each global as a `NativePointer`. `dispose()` frees the compiler state. Unknown `extern` symbols come from `symbols` or from the process (`malloc`, `strlen`, …)
- `send`, `recv`, `rpc.exports`, `setTimeout` / `setInterval`

`Script.bindWeak` returns 0.

## Limits

- No unload. `detach` is the M2 error, and a failed inject still leaves the mapped agent after threads resume.
- The host daemon embeds an empty agent. Android `inject` needs a daemon built by `./build.sh`.
- `Script.bindWeak` is a stub. `NativeCallback` stubs are not freed.
- Spawn does not stop the new process before `Application.onCreate`.
- `Il2Cpp` field reads and writes are pointer-sized. `gc.choose` needs `il2cpp_unity_liveness_calculation_begin`.

## Non-goals

- Frida wire protocol or `frida` CLI compatibility.
- `Stalker.follow`. Function traces go through `Trace.function`.
- Zygote spawn gating.
