# Architecture and status

RetroBridge is split so a later guest runtime can be developed without conflating “the CPU can decode ARM instructions” with “an Android app is compatible.” The current code is a safety-oriented foundation, not a finished compatibility runtime.

## Process and trust boundaries

- `:app` is the normal management process. It imports a selected base APK into app-private storage, keeps registry metadata, and displays explicit capability status.
- `:core:runtime` contributes a native `arm64-v8a` library and declares a non-exported `GuestRuntimeService` in `android:process=":guest_runtime"`. The service immediately rejects start requests. The process boundary is reserved, not an active execution sandbox.
- `:core:manager` owns immutable guest metadata, an atomic JSON registry, and lifecycle transition validation.
- `:core:fs` owns the per-import filesystem layout, narrow guest-path mapper, quota-bounded streaming Android/data and OBB ZIP import, and SAF-export ZIP writer. It is not a mount namespace and does not grant access to arbitrary external storage.
- `:core:services` emits a capability report. It does not spoof PackageManager data or claim to provide Android framework services.
- `core/runtime/src/main/cpp` contains a sparse permission-checked guest memory map, an ELF32/ARM mapper and relocation subset, dynamic-symbol lookup, a bounded A32/T32 interpreter, guest SVC/trampoline hooks, lifecycle-function invocation, and an opaque handle table. These primitives are not yet connected to APK launch.
- `native/` builds host-side verification tools and tests synthetic runtime code plus real ARM32 executable/shared-library fixtures cross-compiled by CI. The executable fixture is loaded, relocated, and run by the interpreter on the host.

## Important interfaces

### Guest address space

`GuestAddress32` and `GuestRange32` store guest addresses as `uint32_t` and check arithmetic in a wider integer type. `GuestMemory` maps sparse host-backed regions, enforces per-region read/write/execute permissions, and rejects unmapped or overflowing accesses; guest addresses are never cast to host pointers. `GuestHeap32` provides a bounded, aligned free-list allocator with coalescing and calloc/realloc/POSIX alignment semantics; allocator metadata is serialized, but this is not Bionic's allocator/debug interface, an OS page arena, signal-based fault boundary, or process sandbox.

### ARM execution

`TranslationEngine` is the execution-backend interface. `Arm32Interpreter` implements a deliberately explicit subset of A32 and T32 (including common integer/data-processing, branches, loads/stores, Thumb-2 MOVW/MOVT, and SVC). `GuestCpuState32` carries R0-R15, CPSR/IT state, FPSCR, Q0-Q15, and guest TLS. Instruction budgets and guest-memory permissions are enforced. `GuestTrampolineRegistry` maps exported guest addresses/names to explicit host callbacks; it never exposes host function pointers to guest registers. `UnavailableTranslationEngine` remains a safe placeholder for a DBT backend that is not integrated. The interpreter is not a complete ARMv7/VFP/NEON implementation and is not wired to APK launch.

### Guest filesystem and syscalls

`NativeVfsPathTranslator` maps a strict set of Android private/internal, app-specific external, and OBB prefixes into an app-owned host root; it rejects traversal, package-prefix confusion, and symlink components. `NativeVfs` exposes virtual descriptors and uses directory-relative host calls without returning host paths or descriptor values to guest code. `Arm32SyscallDispatcher` converts selected ARM Linux EABI calls and fixed-width stat/time layouts, validates guest buffers, handles a subset of file/directory, clock, `mmap2`/`mprotect`/`munmap`, `brk`, and process calls, and returns `ENOSYS` for unknown calls. This is not a complete Linux kernel, thread scheduler, shared-writable mmap implementation, or APK-launch integration; the host filesystem boundary also needs race-focused hardening.

### Bionic and guest symbol bridge

`GuestBionicThunks` registers address-based function trampolines and guest data cells, and exposes `resolve_guest_symbol()` for passing its supported function/data symbols to the ELF loader's external-symbol resolver. Its tested subset includes bounded guest-heap allocation, memory/string functions and ARM EABI helpers, a selected libm/math-helper set, `open`/`close`/`read`/`write`/32-bit `lseek`/`lseek64` through `NativeVfs`, errno/stack-guard cells, and basic pthread mutex/TLS operations. `pthread_create` explicitly returns `EAGAIN`; it does not start a thread. A second lock by the single synthetic thread returns `EDEADLK` rather than blocking because there is no guest scheduler. Mutex ownership/attributes, condition variables, thread scheduling, per-thread errno/TLS, libc formatting/locale/stdio breadth, dynamic-loader semantics, and most Android/Bionic symbols remain unsupported. Guest string and memory operations are bounded and validate guest permissions. This bridge is not wired into APK launch and does not make the runtime compatible with arbitrary Android libraries.

### ELF loading and lifecycle

`Elf32Image::parse` validates little-endian ELFCLASS32 `EM_ARM` ET_EXEC/ET_DYN metadata. `Elf32Loader` maps PT_LOAD segments and permissions, parses dynamic symbols/hash tables, resolves symbols through a supplied callback, and applies a constrained ARM REL set. Unsupported RELA/RELR/Android packed relocations and full dependency loading are rejected rather than guessed. PT_TLS and full dynamic linking remain unsupported; the partial `GuestBionicThunks` symbol resolver can be supplied by a caller, but no complete Bionic or dependency-loading pipeline is integrated. `GuestLifecycleExecutor` retrieves validated DT_INIT/DT_INIT_ARRAY and DT_FINI_ARRAY/DT_FINI functions and calls them using a temporary return trampoline. Native tests cover A32/T32 constructors/destructors, and CI cross-compiles, loads, relocates, and executes a small ARM32 ET_DYN program on the host.

### Guest references

`HandleTable` maps guest-width handles to opaque host tokens. `GuestJniBridge` allocates 32-bit `JNIEnv`/`JavaVM` tables in guest memory, registers address-based trampolines, implements a tested string/array/reference/local-frame/exception subset, and validates guest `RegisterNatives` descriptors and executable entry points. It has no ART, class loader, Java-method engine, callback scheduler, GC, modified UTF-8, or concurrency; unsupported table slots set an explicit pending exception. This is not a virtual Android Java runtime or `JNI_OnLoad` launcher.

### Persistence and per-app storage

Each import gets `RetroBridge/apps/<package>/<uuid>/` so separate imports cannot reuse a mutable root. The manager stores only normalized paths relative to RetroBridge's private data root. Registry writes use a same-directory temporary file and atomic replacement when supported. The storage layer only maps the documented app-private paths and rejects traversal, unknown roots, and symlink components.

## Roadmap (gates, not promises)

1. Keep import, registry, path isolation, capability reporting, and ABI diagnostics tested.
2. Expand the interpreter subset or integrate a reviewed, licensed ARM32 DBT; add instruction/ABI tests and harden unsupported-instruction behavior.
3. Implement dependency loading, TLS, and linker semantics on top of the current guest memory/ELF primitives; fuzz all untrusted ELF paths and relocate/test failures.
4. Expand syscall/VFS coverage, harden host path race handling, and add guest ABI layout tests; never pass host pointers or host `long`/`size_t` layouts through guest registers.
5. Expand the synthetic JNI subset into a Java-facing thunk/callback layer, implement attach/detach and thread safety, and add dedicated cross-ABI tests.
6. Add lifecycle IPC and framework proxying incrementally, with capability checks and per-API unsupported reports. Only after a separate security review consider enabling a constrained launch path.

A completed earlier gate does not imply that a later gate or general Android framework compatibility is available.
