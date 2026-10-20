# Verification matrix

RetroBridge's CI verifies narrow implementation slices. A green run establishes that the listed host/Android builds and tests passed on the GitHub runner; it does not establish general device compatibility or safe execution of an imported APK.

| Layer | CI command / fixture | What it verifies | Explicitly not verified |
| --- | --- | --- | --- |
| Android app and native library | `:app:assembleDebug`, `:app:assembleDebugAndroidTest`, lint tasks | `arm64-v8a` and `x86_64` app/native builds, Android manifest merge, and lint | Other app ABIs; physical-device compatibility |
| App/runtime unit tests | `:app:testDebugUnitTest`, `:core:runtime:testDebugUnitTest` | Bounded ELF preflight; APK stream-copy quotas/SHA-256 and zero-length bulk-read fallback; app-private APK identity/hash checks; native-library ZIP extraction/quotas; DT_NEEDED ordering; launch/stop orchestration; fail-closed storage changes when runtime stop is unconfirmed | Full Android framework behavior or arbitrary guest APK execution |
| Compose UI regression | `:app:connectedDebugAndroidTest` on API 35 x86_64 | App-list prototype messaging, stale-launch-warning regression, and import-button click semantics | Screenshot baselines, physical devices, large-font/landscape matrix, or full accessibility audit |
| Manager/services tests | `:core:manager:test`, `:core:services:test` | Registry validation/atomic persistence, lifecycle transition rules, and truthful capability statuses | Android PackageManager behavior or persistent guest execution lifecycle |
| Filesystem/archive tests | `:core:fs:test` | Guest path isolation; Android/data and OBB ZIP traversal/symlink/entry quotas; staged replacement and export manifest behavior | Kernel mount isolation, filesystem race freedom, fuzzing, or SAF/device provider behavior |
| Native host tests | `ctest --test-dir native/build/host --output-on-failure` | Guest memory/heap, ELF parsing/loading/relocations, synthetic and NDK-built shared-library sessions, lifecycle/entrypoint execution, interpreter, VFS/syscalls, JNI and NDK/OpenSL subsets | Complete ARMv7/Bionic/JNI/NDK APIs or Android's runtime environment |
| ARM32 native demo | NDK-built `libretrobridge_demo.so` and `retrobridge_native_session_demo_runner` | Real ARM32 machine-code constructor, `JNI_OnLoad`, selected entrypoint, `sqrtf`, guest VFS file I/O, return value, and destructor-on-stop under instruction budgets | General library/API compatibility, guest threads, DEX/Java/Activity behavior, or security isolation |
| Signed/zip-aligned demo APK | `:guestDemo:assembleDebug`, `apksigner verify`, `zipalign -c -v 4` | Demo library is packaged in an `armeabi-v7a` APK with a valid debug signature and aligned ZIP entries | Play/app-store signing, installation as a guest, or general APK launchability |
| Android service instrumentation | `:app:connectedDebugAndroidTest` on API 35 x86_64 | Imports the demo APK into guest storage; invokes the real Messenger service in `:guest_runtime`; checks JNI execution report and VFS output; stops session and verifies destructor output | Broad emulator/device coverage, arbitrary imported applications, Java/Activity/framework virtualization, or an OS security boundary |
| Cross-compiled ARM32 executable | NDK-built `guest_arm32` plus `retrobridge_arm32_fixture_runner` | Loads, relocates, and executes the fixture using the bounded host interpreter | Arbitrary ARM32 application behavior |
| Cross-compiled ARM32 VFP executable | NDK-built `guest_arm32_vfp` plus fixture runner | The selected scalar VFP fixture path | General VFP, NEON, or full ARM CPU/DBT coverage |
| Cross-compiled ARM32 shared object | NDK-built `libretrobridge_fixture.so` plus `retrobridge_elf_inspect` | Shared-object ELF metadata and bounded load-segment inspection | Full linking/TLS, all relocation forms, or arbitrary `JNI_OnLoad` behavior |
| Interpreter microbenchmark | `retrobridge_arm32_benchmark 2000000` | Correctly budgeted synthetic A32 `ADD`/branch loop and a five-sample host timing summary | Android-device throughput, whole-APK performance, or a regression threshold |

## Known gaps

- The Android test exercises one demo APK on one x86_64 emulator image. It does not establish behavior across Android versions/devices, arbitrary APKs, guest Java/DEX or Activities, a complete Android framework, or a process/kernel security boundary.
- Archive, ELF, and interpreter tests are deterministic examples, not coverage-guided fuzzing.
- Performance output is informational and runner-specific. It is not used to pass/fail the build based on speed.
- The Kotlin APK extraction/dependency orchestration has fake-controller unit tests in addition to the end-to-end demo service test; fake-controller success is not evidence that unsupported guest APIs work.
- Full APK execution, broad CPU/DBT coverage, full Android framework behavior, and an OS security boundary remain unimplemented.

The workflow is [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml). Benchmark output is uploaded as `diagnostics/arm32-interpreter-benchmark.json` with the other CI artifacts.
