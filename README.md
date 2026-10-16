# RetroBridge

RetroBridge is an experimental, rootless-first research project for inspecting and managing legacy ARM32 Android APKs on 64-bit-only Android devices. The repository is at the **foundation/prototype stage**: it includes an Android management shell, an isolated per-app storage model, ELF32/ARM validation, and a CI pipeline. It does **not** currently execute 32-bit Android applications.

## Honest status

- APK metadata import and private per-app storage: prototype implementation.
- ARM32 ELF header/program-header and dependency metadata inspection: implemented; checked with real ARM32 ELF fixtures in CI.
- Host APK UI and compatibility report: scaffolded.
- ARM32 instruction translation, custom relocation/linking, Bionic/syscall emulation, synthetic JNI, and guest framework services: **not implemented**.
- Launch and Stop are intentionally unavailable. A separate `:guest_runtime` Android process is reserved for future work, but is not an execution sandbox today.
- No root, privileged system integration, SDK/NDK download, or full-OS virtual machine is required by the source tree.

See [the compatibility matrix](docs/compatibility-matrix.md), [architecture notes](docs/architecture.md), and [security model](docs/security.md) before treating this as anything more than a prototype.

## Repository layout

- `app/` — Kotlin/Jetpack Compose management UI and APK import flow.
- `core/manager/` — app metadata, persistent registry, and lifecycle state machine.
- `core/fs/` — isolated guest directory layout and guarded guest-path mapping.
- `core/services/` — explicit, machine-readable capability reporting.
- `core/runtime/` — Android native-library module and C++ runtime interfaces.
- `native/` — host-side CMake validation tools and tests; ARM32 binaries are generated in CI, not checked in.
- `.github/workflows/ci.yml` — Android, native host, and cross-compiled fixture verification.

## Build and verify

The supported verification path is GitHub Actions (`CI`). It uses the runner's Android SDK/NDK, builds the `arm64-v8a` management APK and native library, cross-compiles small `armeabi-v7a` ELF fixtures, then runs Gradle unit tests and host-side CTest checks. APKs, fixture binaries, and diagnostics are uploaded as workflow artifacts.

No Android SDK, NDK, emulator, or heavyweight toolchain is downloaded into the project workspace. A local Gradle/CMake build is optional for contributors, but is not a claim of on-device guest compatibility.
