# RetroBridge

RetroBridge is an experimental, rootless-first research project for inspecting and managing legacy ARM32 Android APKs on 64-bit-only Android devices. The repository is at the **foundation/prototype stage**: it includes an Android management shell, an isolated per-app storage model, ELF32/ARM validation, and a CI pipeline. It does **not** currently execute 32-bit Android applications.

## Honest status

- APK metadata import and private per-app storage: prototype implementation.
- Android/data ZIP import, associated OBB import, and SAF guest-data/OBB-manifest export: implemented with streaming quotas, package/path validation, symlink rejection, and transactional file replacement.
- ARM32 ELF32 segment mapping, bounded ARM relocation, dynamic symbol lookup, and constructor/destructor address validation: implemented and exercised with synthetic native tests.
- A bounded A32/T32 interpreter supports an explicit instruction subset, SVC callbacks, and registered guest-address trampolines. CI executes both hand-authored interpreter tests and a cross-compiled ARM32 ELF fixture.
- Host APK UI and compatibility report: prototype implementation.
- Complete ARMv7/VFP/NEON execution, dependency loading, Bionic/syscall emulation, system/JNI thunks, and guest framework services: **not implemented**.
- Launch and Stop remain intentionally unavailable. The guest runtime service rejects start requests; native execution is not wired to imported APKs and is not a security boundary.
- No root, privileged system integration, SDK/NDK download, or full-OS virtual machine is required by the source tree.

See [the compatibility matrix](docs/compatibility-matrix.md), [architecture notes](docs/architecture.md), and [security model](docs/security.md) before treating this as anything more than a prototype.

## Repository layout

- `app/` — Kotlin/Jetpack Compose management UI and APK import flow.
- `core/manager/` — app metadata, persistent registry, and lifecycle state machine.
- `core/fs/` — isolated guest directory layout, guarded guest-path mapping, streaming data/OBB archive import, and guest-data ZIP export.
- `core/services/` — explicit, machine-readable capability reporting.
- `core/runtime/` — Android native-library module, guest-memory/ELF loader, bounded ARM32 interpreter, and lifecycle hooks.
- `native/` — host-side CMake verification tools and tests; ARM32 binaries are generated and exercised in CI, not checked in.
- `.github/workflows/ci.yml` — Android, native host, and cross-compiled fixture verification.

## Build and verify

The supported verification path is GitHub Actions (`CI`). It uses the runner's Android SDK/NDK, builds the `arm64-v8a` management APK and native library, cross-compiles small `armeabi-v7a` ELF fixtures, and runs Gradle tests plus host-side CTest. CTest validates metadata and loads/relocates/executes the minimal ARM32 executable with the bounded interpreter. APKs, fixture binaries, test tools, and diagnostics are uploaded as workflow artifacts.

No Android SDK, NDK, emulator, or heavyweight toolchain is downloaded into the project workspace. A local Gradle/CMake build is optional for contributors, but is not a claim of on-device guest compatibility.
