# Native interfaces and implementation boundaries

The C++ library is platform-neutral so guest-address, memory, ELF, lifecycle, and execution contracts can be host-tested before the Android runtime is allowed to run imported APK code.

- `guest_address.h` / `guest_memory.h`: overflow-checked guest address/range values and sparse, permission-checked guest memory.
- `elf32_image.h` / `elf32_loader.h`: ELF32/ARM parser, PT_LOAD mapping, dynamic metadata, supported ARM REL relocations, symbol lookup, and lifecycle-array validation.
- `translation_engine.h` / `arm32_interpreter.h`: execution contract, bounded A32/T32 interpreter subset, SVC callback, guest-address trampoline registry, and explicit unavailable DBT placeholder.
- `guest_heap.h`, `guest_bionic_thunks.*`, `guest_android_asset_thunks.*`, `native/vfs/`, and `native/bionic_bridge/arm32_syscall_dispatcher.*`: bounded 32-bit allocator; partial libc/libm/pthread function/data trampolines; caller-registered blob-backed AAsset thunks; app-private POSIX VFS; and explicitly partial ARM EABI syscalls. The thunk resolvers can be passed to ELF loading by a caller, but these remain tested primitives rather than an APK execution pipeline.
- `guest_jni_bridge.*`: synthetic 32-bit JNI/JavaVM tables, opaque local/global refs, marshaled strings/arrays, explicit exceptions, and checked native-method registration; no ART or general Java execution.
- `guest_lifecycle.h`: bounded DT_INIT/DT_INIT_ARRAY and DT_FINI_ARRAY/DT_FINI calls through a temporary guest return thunk.
- `handle_table.h`: generation-checked guest handle map to opaque 64-bit tokens; not a JNI implementation.
- `runtime_capabilities.h`: capability snapshot keeps instruction execution distinct from complete guest-app compatibility.

The host CMake project is verification-only. It cross-runs ARM32 integer and scalar-VFP fixtures with the host interpreter, but this is not evidence that arbitrary ARM32 Android applications run. The Android module builds the native sources for `arm64-v8a`; it currently exports no guest execution or JNI API, and the guest service rejects start requests.
