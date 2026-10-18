# CommAnalyser

ARM64 Android dynamic instrumentation framework (Rust).

> Status: M0 skeleton.  The research and plan live in [`docs/00-research.md`](docs/00-research.md)
> and [`docs/01-plan.md`](docs/01-plan.md).

## Layout

- `crates/ca-core` — process/maps/modules/ranges.
- `crates/ca-arch-arm64` — instruction classification, writer, relocator.
- `crates/ca-gum` — Memory/Module/Process/Interceptor primitives.
- `crates/ca-js` — QuickJS runtime (rquickjs).
- `crates/ca-art` — ART engine (planned, M3).
- `crates/ca-qbdi` — QBDI native API (planned, M4).
- `crates/ca-inject` — ptrace/memfd/PIC loader (M1).
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

## M0 status (2026-10-18)

- Workspace builds on host; `cargo test --workspace` passes 37 tests.
- Android cross-compile works for `ca-agent` (cdylib), `ca-daemon`, `ca-cli`
  with NDK 29.0.14206865 / `aarch64-linux-android24`.
- Device validation on `282eb4e4` (Android 15, arm64): pushed `ca-daemon`,
  started it on `127.0.0.1:17321`, then ran
  `ca ping` / `ca version` / `ca ps` over `adb forward`.
- Implemented so far: `/proc` maps + module aggregation, ARM64 instruction
  classification, absolute-branch writer, B/BL prologue relocation,
  QuickJS eval/console embedding, daemon/CLI JSON protocol.
- Placeholders (explicitly `Unsupported`): Interceptor, NativeFunction,
  ptrace attach, ART, QBDI link.

Next: M1 (ptrace attach + PIC loader + memfd + agent control channel).

## Protocol (M0)

Line-delimited JSON over TCP:

```json
{"op":"ping"}
{"op":"version"}
{"op":"ps"}
```

`ca --addr 127.0.0.1:17321 ps` prints the process list.

## Non-goals (v0)

- Frida wire-protocol / `frida` CLI compatibility.
- `Stalker` Frida semantics (QBDI native API instead).
- Zygisk/spawn gating (attach first).
