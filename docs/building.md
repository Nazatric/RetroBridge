# Build and CI

The canonical build lane is `.github/workflows/ci.yml`. It runs on `ubuntu-latest`, sets up JDK 17 and Gradle, uses the runner-provided Android SDK and `$ANDROID_NDK_LATEST_HOME`, installs the required API/build-tools/CMake packages in the disposable GitHub runner if needed, and caches Gradle/CMake build outputs.

The lane:

1. Cross-compiles small `armeabi-v7a` integer and VFP executables plus a libc-free ARM32 shared object using the NDK's `armv7a-linux-androideabi23-clang`.
2. Builds the host CMake validator and native tests, then runs CTest against synthetic ELF metadata and all real cross-compiled fixtures; the VFP fixture executes scalar register moves and `VADD.F32` through the host interpreter.
3. Builds the management APK and native runtime library for `arm64-v8a`, runs Android lint, and runs the Kotlin/JVM unit-test tasks.
4. Uploads the debug APK, ARM32 fixtures, native test tools, test reports, and diagnostic logs even when a preceding verification step fails.

No SDK/NDK is downloaded into this repository or the local agent workspace. The current workflow validates compilation and narrow metadata behavior only; it does not launch a guest on an Android device or emulator.
