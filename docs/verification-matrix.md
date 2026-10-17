# Verification matrix

RetroBridge's CI verifies narrow implementation slices. A green run establishes that the listed host/Android builds and tests passed on the GitHub runner; it does not establish device compatibility or safe execution of an imported APK.

| Layer | CI command / fixture | What it verifies | Explicitly not verified |
| --- | --- | --- | --- |
| Android app and native library | `:app:assembleDebug`, `:app:lintDebug`, `:core:runtime:lintDebug` | `arm64-v8a` app/native build, Android manifest merge, and lint | Install/launch on a physical device or emulator; guest APK launch |
| App/runtime unit tests | `:app:testDebugUnitTest`, `:core:runtime:testDebugUnitTest` | Bounded ELF preflight; inspection-context identity, SHA-256/path validation, IPC session supervisor idempotence and stop behavior | A full Activity/Service/Java framework implementation or Binder calls made by guest code |
| Manager/services tests | `:core:manager:test`, `:core:services:test` | Registry validation/atomic persistence, lifecycle transition rules, and truthful capability statuses | Android PackageManager behavior or persistent guest execution lifecycle |
| Filesystem/archive tests | `:core:fs:test` | Guest path isolation; Android/data and OBB ZIP traversal/symlink/entry quotas; staged replacement and export manifest behavior | Kernel mount isolation, filesystem race freedom, fuzzing, or SAF/device provider behavior |
| Native host tests | `ctest --test-dir native/build/host --output-on-failure` | Guest memory/heap, ELF parsing/loading/relocations, interpreter, VFS/syscalls, JNI and synthetic NDK/OpenSL subsets | Complete ARMv7/Bionic/JNI/NDK APIs or the Android execution environment |
| Cross-compiled ARM32 executable | NDK-built `guest_arm32` plus `retrobridge_arm32_fixture_runner` | Loads, relocates, and executes the fixture using the bounded host interpreter | Arbitrary ARM32 application behavior |
| Cross-compiled ARM32 VFP executable | NDK-built `guest_arm32_vfp` plus fixture runner | The selected scalar VFP fixture path | General VFP, NEON, or full ARM CPU/DBT coverage |
| Cross-compiled ARM32 shared object | NDK-built `libretrobridge_fixture.so` plus `retrobridge_elf_inspect` | Shared-object ELF metadata and bounded load-segment inspection | Dependency loading, complete dynamic linking, TLS, or `JNI_OnLoad` |
| Interpreter microbenchmark | `retrobridge_arm32_benchmark 2000000` | Correctly budgeted synthetic A32 `ADD`/branch loop and a five-sample host timing summary | Android-device throughput, whole-APK performance, or a regression threshold |

## Known gaps

- CI has no emulator/device UI or lifecycle test, no Android framework proxy test, and no guest-code execution test.
- Archive, ELF, and interpreter tests are deterministic examples, not coverage-guided fuzzing.
- Performance output is informational and runner-specific. It is not used to pass/fail the build based on speed.
- The inspection-only service path starts and stops a validated context but never calls the native loader or executes APK bytecode/native code.
- Full APK execution, broad CPU/DBT coverage, full Android framework behavior, and a process/kernel security boundary remain unimplemented.

The workflow is [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml). Benchmark output is uploaded as `diagnostics/arm32-interpreter-benchmark.json` with the other CI artifacts.
