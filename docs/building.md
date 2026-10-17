# Build and CI

The canonical build lane is `.github/workflows/ci.yml`. It runs on `ubuntu-latest`, sets up JDK 17 and Gradle, uses the runner-provided Android SDK and `$ANDROID_NDK_LATEST_HOME`, installs the required API/build-tools/CMake packages in the disposable GitHub runner if needed, and caches Gradle/CMake build outputs.

The lane:

1. Cross-compiles small `armeabi-v7a` integer and VFP executables plus a libc-free ARM32 shared object using the NDK's `armv7a-linux-androideabi23-clang`.
2. Builds the host CMake validator, native tests, fixture runner, and interpreter benchmark, then runs CTest against synthetic ELF/runtime cases and all real cross-compiled fixtures; the VFP fixture exercises scalar register moves and `VADD.F32` through the host interpreter.
3. Runs a correctness-checked, non-gating A32 arithmetic/branch microbenchmark and stores the JSON result as an artifact; it is not an Android-device or APK performance measurement.
4. Builds the management APK and native runtime library for `arm64-v8a`, runs Android lint, and runs the app, runtime, manager, filesystem/archive, and compatibility-report unit-test tasks.
5. Uploads the debug APK, ARM32 fixtures, native test tools, benchmark JSON, test reports, and diagnostics even when a preceding verification step fails.

No SDK/NDK is downloaded into the repository or local agent workspace. CI does not launch a guest on an Android device or emulator and does not execute imported APKs; see the [verification matrix](verification-matrix.md) for the explicit scope and gaps.
