# RetroBridge

RetroBridge is an experimental, rootless-first research project for inspecting and managing legacy ARM32 Android APKs on 64-bit-only Android devices. The repository is at the **foundation/prototype stage**: it includes an Android management shell, an isolated per-app storage model, ELF32/ARM validation, and a CI pipeline. It does **not** currently execute 32-bit Android applications.

## Honest status

- APK metadata import and private per-app storage: prototype implementation. Bundled `.so` files receive bounded ELF header and `PT_LOAD` structural preflight; warnings are stored with the guest record. Passing preflight is not a claim that a library can be linked, loaded, or executed.
- Android/data ZIP import, associated OBB import, and SAF guest-data/OBB-manifest export: implemented with streaming quotas, package/path validation, symlink rejection, and transactional file replacement.
- ARM32 ELF32 segment mapping, bounded ARM relocation, dynamic symbol lookup, and constructor/destructor address validation: implemented and exercised with synthetic native tests.
- A bounded A32/T32 interpreter supports an explicit instruction subset, SVC callbacks, and registered guest-address trampolines. CI executes both hand-authored interpreter tests and a cross-compiled ARM32 ELF fixture.
- A bounded guest heap, app-private POSIX-backed VFS/path translator, and ARM32 EABI syscall subset (file I/O/stat/directory basics, clocks, anonymous mappings, `brk`, and process identity/exit) are tested. A separate partial Bionic/libc/libm/pthread thunk table covers basic allocation, memory/string, math, file-descriptor, mutex, and single-synthetic-thread TLS calls; unsupported thread creation returns `EAGAIN`. Synthetic 32-bit JNI/JavaVM tables and a bounded string/array/reference/`RegisterNatives` subset are also tested. These components are not connected to APK launch: unsupported syscalls fail with `ENOSYS`, unsupported JNI calls set explicit exceptions, and VFS paths have no host-root fallback.
- Host APK UI and compatibility report: prototype implementation.
- NDK `AAssetManager`/`AAsset` thunks read caller-registered immutable blobs; bounded headless `ANativeWindow` thunks expose a 32-bit RGBA pixel buffer. Synthetic `AInputQueue` key/motion records and a nonblocking `ALooper` wake/timeout subset are host-injected only. A software EGL/GLES subset supports window surfaces, color clear, and scissor rendering; it has no draw/shader pipeline. These bridges do not integrate with APK assets, Java `Surface`, Android's input system, or launch. OpenSL ES has only an Android 1.0.1-compatible synthetic engine/player and bounded PCM buffer-queue model; it produces no audible output and dispatches no guest callbacks.
- Complete ARMv7 execution, broad VFP/NEON coverage, full Bionic/libc/libm/pthread coverage and scheduling, broad JNI/system thunks, dependency loading, and guest framework services: **not implemented**. The interpreter now covers a small scalar VFP transfer/arithmetic subset; the current thunk tables are explicit subsets, not general Android ABI compatibility.
- A non-exported Messenger control endpoint in `:guest_runtime` can start/stop bounded inspection-only sessions, validates the private APK identity/hash, and builds a guest-private path context. It never loads or executes the APK. These controls are not guest-app Launch/Stop; arbitrary APK execution and Android framework virtualization remain unavailable.
- No root, privileged system integration, SDK/NDK download, or full-OS virtual machine is required by the source tree.

See the [compatibility matrix](docs/compatibility-matrix.md), [verification matrix](docs/verification-matrix.md), [benchmark notes](docs/benchmark.md), [architecture notes](docs/architecture.md), and [security model](docs/security.md) before treating this as anything more than a prototype.

## Repository layout

- `app/` — Kotlin/Jetpack Compose management UI and APK import flow.
- `core/manager/` — app metadata, persistent registry, and lifecycle state machine.
- `core/fs/` — isolated guest directory layout, guarded guest-path mapping, streaming data/OBB archive import, and guest-data ZIP export.
- `core/services/` — explicit, machine-readable capability reporting.
- `core/runtime/` — Android native-library module, isolated service IPC, inspection-only guest context/path policy, guest-memory/ELF loader, bounded ARM32 interpreter, and lifecycle hooks.
- `native/` — host-side CMake verification tools and tests; ARM32 binaries are generated and exercised in CI, not checked in.
- `.github/workflows/ci.yml` — Android, native host, and cross-compiled fixture verification.

## Build and verify

The supported verification path is GitHub Actions (`CI`). It uses the runner's Android SDK/NDK, builds the `arm64-v8a` management APK and native library, cross-compiles small `armeabi-v7a` ELF fixtures, and runs Gradle tests plus host-side CTest. CTest validates metadata, guest heap/VFS/syscall behavior, and loads/relocates/executes NDK-built ARM32 integer and scalar-VFP fixtures with the bounded interpreter. A non-gating A32 arithmetic/branch microbenchmark reports a host-only baseline. APKs, fixture binaries, test tools, benchmark JSON, and diagnostics are uploaded as workflow artifacts; the [verification matrix](docs/verification-matrix.md) lists exact coverage and gaps.

No Android SDK, NDK, emulator, or heavyweight toolchain is downloaded into the project workspace. A local Gradle/CMake build is optional for contributors, but is not a claim of on-device guest compatibility.
