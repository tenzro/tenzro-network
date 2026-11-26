# tenzro-android-node

The Tenzro light node as an Android library: an app (the Control app) takes
it as a dependency and gets the node, run in the app's own process by a
foreground service, with the node's keys in the Android Keystore.

## What it holds

- `com.tenzro.node.NodeService`: the foreground service. `NodeService.start(context, extraArgs)`
  starts the node and records that the operator left it on; `NodeService.stop(context)` stops
  it and records that it is off. The node runs as a light node (`--roles light`) in
  `NodeService.dataDir(context)` (`files/node`); `extraArgs` follow those and may not set either.
- `com.tenzro.node.BootReceiver`: after a reboot, starts the node when the operator left it on.
- `com.tenzro.node.NodeSettings`: the choice, in the shared preferences file `com.tenzro.node`:
  `run_node` (boolean) and `node_args` (the extra arguments, joined by NUL).
- `com.tenzro.keystore.AndroidKeystoreKey` and `KeystoreBridge`: the Keystore keys the node's
  device-key backend (`crates/tenzro-device-key`, `backend_android`) calls through JNI. A key or
  root the Keystore holds in software is refused.

The service is of the `specialUse` foreground type: a node follows the chain all day, and the
`dataSync` type is capped at six hours a day. Publishing on Play needs the special-use
declaration for it.

## Building

The native library is the crate in `native/` (`libtenzro_android_node.so`), built for
`aarch64-linux-android` (API 28, 16 KB pages) and placed under `src/main/jniLibs/arm64-v8a/`
before Gradle packages the library:

```sh
cargo build --release --locked --target aarch64-linux-android -p tenzro-android-node
mkdir -p src/main/jniLibs/arm64-v8a
cp ../../target/aarch64-linux-android/release/libtenzro_android_node.so src/main/jniLibs/arm64-v8a/
gradle testDebugUnitTest assembleRelease
```

The NDK's clang for API 28 is the linker (`CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`), with
`-Wl,-z,max-page-size=16384`.
