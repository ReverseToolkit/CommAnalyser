# TAL payload for the Android agent

`Trace.function` loads **TAL** (`native/tal`), not a hand-rolled QBDI door.

Build `libtal.so` (Android arm64, no Triton):

```
export ANDROID_NDK=/path/to/ndk
cmake -S native/tal -B native/tal/build-android \
  -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=c++_shared -DCMAKE_BUILD_TYPE=Release \
  -DTAL_BUILD_TESTS=OFF -DTAL_ENABLE_TRITON=OFF
cmake --build native/tal/build-android --target tal
cp native/tal/build-android/libtal.so native/tal/android-arm64/libtal.so
```

Then:

```
cargo build --release --target aarch64-linux-android -p agent --features qbdi-static
```

The agent Interceptor is the attach door. On first `Trace.function` it
decompresses `libtal.so` and calls `tal_prepare` / `tal_enter`. TAL's own
`gum_attach` is not used.

Place `libc++_shared.so` next to the extracted `commanalyser-libtal.so`
(`$ORIGIN`), typically `/data/local/tmp/`.
