# RetroBridge

RetroBridge is an experimental, rootless-first research project for inspecting and managing legacy ARM32 Android APKs on 64-bit-only Android devices. The repository is at the **foundation/prototype stage**: it includes an Android management shell, an isolated per-app storage model, ELF32/ARM validation, and a CI pipeline. It does **not** run general 32-bit Android applications; it now has an experimental, narrowly bounded path for selected ARM32 native libraries only.

## Honest status

- APK metadata import and private per-app storage: prototype implementation. Bundled `.so` files receive bounded ELF header and `PT_LOAD` structural preflight; warnings are stored with the guest record. Passing preflight is not a claim that a library can be linked, loaded, or executed.
- Android/data ZIP import, associated OBB import, and SAF guest-data/OBB-manifest export: implemented with streaming quotas, package/path validation, symlink rejection, and transactional file replacement.
- ARM32 ELF32 segment mapping, bounded ARM relocation, dynamic symbol lookup, and constructor/destructor address validation: implemented and exercised with synthetic native tests.
- A bounded A32/T32 interpreter supports an explicit instruction subset, SVC callbacks, and registered guest-address trampolines. CI executes both hand-authored interpreter tests and a cross-compiled ARM32 ELF fixture.
- A bounded guest heap, app-private POSIX VFS, selected ARM32 EABI syscalls, and partial Bionic/libc/libm/pthread thunks are wired into a private interpreter session. A narrow ARM32 C++ ABI shim handles guest-heap `new`/`delete` and single-threaded local-static guards (up to 4,096 in-progress guards); `libstdc++.so` is accepted only as a virtual dependency backed by that explicit symbol subset. Unimplemented C++ imports need an APK-local provider or thunk; exception unwinding and `__cxa_atexit` remain unsupported. Unsupported syscalls fail with `ENOSYS`, unsupported JNI calls set explicit exceptions, and VFS paths have no host-root fallback. A synthetic 32-bit JNI/JavaVM subset is provided for `JNI_OnLoad`/`RegisterNatives`, not ART or general Java execution.
- Host APK UI and compatibility report: prototype implementation.
- NDK asset/window/input, headless EGL/GLES, and OpenSL ES subsets are installed in the interpreter session but remain synthetic: APK ZIP assets, Java `Surface`, Android input, GPU display, audible playback, and guest callbacks are not connected.
- Complete ARMv7 execution, broad VFP/NEON coverage, full Bionic/libc/libm/pthread/C++ runtime coverage and scheduling, broad JNI/system thunks, arbitrary APK entrypoints, and guest framework services: **not implemented**. The current linker handles a bounded ARM REL subset and supported dependencies only. The interpreter now covers a small scalar VFP transfer/arithmetic subset; the current thunk tables are explicit subsets, not general Android ABI compatibility.
- A non-exported Messenger endpoint in `:guest_runtime` can extract SHA-256-checked `armeabi-v7a`/`armeabi` libraries, load supported dependencies, run constructors, validate `JNI_OnLoad`, and call selected exported entrypoints through the interpreter under an instruction budget. The UI reports actual instructions, relocations, libraries, and results. This is not Java bytecode/Activity execution, arbitrary APK compatibility, a complete framework, or a security boundary for untrusted APKs.
- No root, privileged system integration, SDK/NDK download, or full-OS virtual machine is required by the source tree.

See the [compatibility matrix](docs/compatibility-matrix.md), [verification matrix](docs/verification-matrix.md), [benchmark notes](docs/benchmark.md), [architecture notes](docs/architecture.md), and [security model](docs/security.md) before treating this as anything more than a prototype.

## Repository layout

- `app/` — Kotlin/Jetpack Compose management UI and APK import flow.
- `core/manager/` — app metadata, persistent registry, and lifecycle state machine.
- `core/fs/` — isolated guest directory layout, guarded guest-path mapping, streaming data/OBB archive import, and guest-data ZIP export.
- `core/services/` — explicit, machine-readable capability reporting.
- `core/runtime/` — Android native-library module, private service IPC, app-private guest context/path policy, JNI/native session bridge, ARM32 ELF loader, and bounded interpreter lifecycle.
- `native/` — host-side CMake verification tools and tests; ARM32 binaries are generated and exercised in CI, not checked in.
- `.github/workflows/ci.yml` — Android, native host, and cross-compiled fixture verification.

## Build and verify

The supported verification path is GitHub Actions (`CI`). It uses the runner's Android SDK/NDK, builds the `arm64-v8a` and `x86_64` management app/native library, cross-compiles `armeabi-v7a` ELF fixtures, and runs Gradle tests plus host-side CTest. CTest validates metadata, guest heap/VFS/syscall behavior, a real ARM32 shared-library lifecycle session (constructor, `JNI_OnLoad`, `sqrtf`, entrypoint, guest file writes, destructor), and integer/scalar-VFP fixtures with the bounded interpreter. CI also packages and verifies a signed/zip-aligned demo APK, then imports it and exercises the actual Messenger/JNI `:guest_runtime` service on an API 35 x86_64 emulator; the test verifies execution counters and teardown output. A non-gating A32 arithmetic/branch microbenchmark reports a host-only baseline. APKs, fixture binaries, test tools, benchmark JSON, emulator results, and diagnostics are uploaded as workflow artifacts; the [verification matrix](docs/verification-matrix.md) lists exact coverage and gaps.

No Android SDK, NDK, emulator, or heavyweight toolchain is downloaded into the project workspace. A local Gradle/CMake build is optional for contributors, but is not a claim of on-device guest compatibility.
