# Build and CI

The canonical build lane is `.github/workflows/ci.yml`. It runs on `ubuntu-latest`, sets up JDK 17 and Gradle, uses the runner-provided Android SDK and `$ANDROID_NDK_LATEST_HOME`, installs the required API/build-tools/CMake/emulator packages in the disposable GitHub runner if needed, and caches Gradle/CMake build outputs.

The lane:

1. Cross-compiles small `armeabi-v7a` executable fixtures and two shared libraries with the NDK's `armv7a-linux-androideabi23-clang`. The runnable demo library exercises a constructor, `JNI_OnLoad`, an exported entrypoint, a destructor, `sqrtf`, and app-private `open`/`write`/`close` calls.
2. Packages the demo shared object into a minimal `org.retrobridge.guestdemo` APK, then checks its APK signature with `apksigner` and ZIP alignment with `zipalign`.
3. Builds the host CMake validator, native tests, fixture runners, and interpreter benchmark; runs CTest against synthetic ELF/runtime cases and cross-compiled ARM32 fixtures. The end-to-end session test checks constructor/JNI/entrypoint order, JNI version, entrypoint return value, guest VFS writes, and destructor execution after stop.
4. Runs a correctness-checked, non-gating A32 arithmetic/branch microbenchmark and stores its JSON result as an artifact; it is not an Android-device or whole-APK performance measurement.
5. Builds the management app/native runtime for `arm64-v8a` and `x86_64`, runs Android lint and unit tests, and builds the Android instrumentation APK.
6. Boots an API 35 x86_64 emulator and runs an instrumentation test that imports the signed demo APK through the app importer, launches it over Messenger through the non-exported `:guest_runtime` service/JNI bridge, checks execution counters and VFS output, then stops the session and verifies the destructor write.
7. Uploads the debug/test/demo APKs, ARM32 fixtures, native test tools, benchmark JSON, test reports, emulator output, and diagnostics even when a preceding verification step fails.

No SDK/NDK/emulator is downloaded into the repository or local agent workspace. CI's demo proves only the deliberately bounded ARM32 native subset and synthetic service path; it does not launch APK DEX/Java bytecode, Activities, or arbitrary guest applications. See the [verification matrix](verification-matrix.md) for explicit coverage and gaps.
