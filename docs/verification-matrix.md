# Verification matrix

RetroBridge's CI verifies narrow implementation slices. A green run establishes that the listed host/Android builds and tests passed on the GitHub runner; it does not establish device compatibility or safe execution of an imported APK.

| Layer | CI command / fixture | What it verifies | Explicitly not verified |
| --- | --- | --- | --- |
| Android app and native library | `:app:assembleDebug`, `:app:lintDebug`, `:core:runtime:lintDebug` | `arm64-v8a` app/native build, Android manifest merge, and lint | Install/launch on a physical device or emulator; guest APK launch |
| App/runtime unit tests | `:app:testDebugUnitTest`, `:core:runtime:testDebugUnitTest` | Bounded ELF preflight; app-private APK identity/hash checks; native-library ZIP extraction/quotas/SHA-256; DT_NEEDED ordering; launch/stop orchestration with a fake native controller | Actual Android JNI service execution, device-side APK loading, Activity launch, or guest Binder calls |
| Manager/services tests | `:core:manager:test`, `:core:services:test` | Registry validation/atomic persistence, lifecycle transition rules, and truthful capability statuses | Android PackageManager behavior or persistent guest execution lifecycle |
| Filesystem/archive tests | `:core:fs:test` | Guest path isolation; Android/data and OBB ZIP traversal/symlink/entry quotas; staged replacement and export manifest behavior | Kernel mount isolation, filesystem race freedom, fuzzing, or SAF/device provider behavior |
| Native host tests | `ctest --test-dir native/build/host --output-on-failure` | Guest memory/heap, ELF parsing/loading/relocations, synthetic shared-library constructor execution through the composed runtime session, interpreter, VFS/syscalls, JNI and NDK/OpenSL subsets | Complete ARMv7/Bionic/JNI/NDK APIs or the Android execution environment |
| Cross-compiled ARM32 executable | NDK-built `guest_arm32` plus `retrobridge_arm32_fixture_runner` | Loads, relocates, and executes the fixture using the bounded host interpreter | Arbitrary ARM32 application behavior |
| Cross-compiled ARM32 VFP executable | NDK-built `guest_arm32_vfp` plus fixture runner | The selected scalar VFP fixture path | General VFP, NEON, or full ARM CPU/DBT coverage |
| Cross-compiled ARM32 shared object | NDK-built `libretrobridge_fixture.so` plus `retrobridge_elf_inspect` | Shared-object ELF metadata and bounded load-segment inspection | Actual Android APK extraction, JNI service invocation, full linking/TLS, or end-to-end `JNI_OnLoad` |
| Interpreter microbenchmark | `retrobridge_arm32_benchmark 2000000` | Correctly budgeted synthetic A32 `ADD`/branch loop and a five-sample host timing summary | Android-device throughput, whole-APK performance, or a regression threshold |

## Known gaps

- CI has no emulator/device UI or service lifecycle test and no full Android framework proxy test. Host CTest executes synthetic and cross-compiled ARM32 fixtures; no APK-sourced code is run end-to-end on Android.
- Archive, ELF, and interpreter tests are deterministic examples, not coverage-guided fuzzing.
- Performance output is informational and runner-specific. It is not used to pass/fail the build based on speed.
- The Kotlin APK extraction/dependency orchestration and session lifecycle are covered with a fake native controller; a host C++ session test maps and executes synthetic shared-library constructors. CI still does not boot an Android device/emulator or exercise the actual JNI service end-to-end.
- Full APK execution, broad CPU/DBT coverage, full Android framework behavior, and a process/kernel security boundary remain unimplemented.

The workflow is [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml). Benchmark output is uploaded as `diagnostics/arm32-interpreter-benchmark.json` with the other CI artifacts.
