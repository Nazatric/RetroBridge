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

`GuestAddress32` and `GuestRange32` store guest addresses as `uint32_t` and check arithmetic in a wider integer type. `GuestMemory` maps sparse host-backed regions, enforces per-region read/write/execute permissions, and rejects unmapped or overflowing accesses; guest addresses are never cast to host pointers. This is not an OS page arena, signal-based fault boundary, process sandbox, or guest/host ABI marshaling layer.

### ARM execution

`TranslationEngine` is the execution-backend interface. `Arm32Interpreter` implements a deliberately explicit subset of A32 and T32 (including common integer/data-processing, branches, loads/stores, Thumb-2 MOVW/MOVT, and SVC). `GuestCpuState32` carries R0-R15, CPSR/IT state, FPSCR, Q0-Q15, and guest TLS. Instruction budgets and guest-memory permissions are enforced. `GuestTrampolineRegistry` maps exported guest addresses/names to explicit host callbacks; it never exposes host function pointers to guest registers. `UnavailableTranslationEngine` remains a safe placeholder for a DBT backend that is not integrated. The interpreter is not a complete ARMv7/VFP/NEON implementation and is not wired to APK launch.

### ELF loading and lifecycle

`Elf32Image::parse` validates little-endian ELFCLASS32 `EM_ARM` ET_EXEC/ET_DYN metadata. `Elf32Loader` maps PT_LOAD segments and permissions, parses dynamic symbols/hash tables, resolves symbols through a supplied callback, and applies a constrained ARM REL set. Unsupported RELA/RELR/Android packed relocations and full dependency loading are rejected rather than guessed. PT_TLS, full dynamic linking, and Bionic are not implemented. `GuestLifecycleExecutor` retrieves validated DT_INIT/DT_INIT_ARRAY and DT_FINI_ARRAY/DT_FINI functions and calls them using a temporary return trampoline. Native tests cover A32/T32 constructors/destructors, and CI cross-compiles, loads, relocates, and executes a small ARM32 ET_DYN program on the host.

### Guest references

`HandleTable` demonstrates a generation-checked 32-bit handle to opaque 64-bit token mapping. It is not a synthetic `JNIEnv`, does not call ART, and does not yet model JNI local frames, weak-reference collection, exceptions, or callbacks.

### Persistence and per-app storage

Each import gets `RetroBridge/apps/<package>/<uuid>/` so separate imports cannot reuse a mutable root. The manager stores only normalized paths relative to RetroBridge's private data root. Registry writes use a same-directory temporary file and atomic replacement when supported. The storage layer only maps the documented app-private paths and rejects traversal, unknown roots, and symlink components.

## Roadmap (gates, not promises)

1. Keep import, registry, path isolation, capability reporting, and ABI diagnostics tested.
2. Expand the interpreter subset or integrate a reviewed, licensed ARM32 DBT; add instruction/ABI tests and harden unsupported-instruction behavior.
3. Implement dependency loading, TLS, and linker semantics on top of the current guest memory/ELF primitives; fuzz all untrusted ELF paths and relocate/test failures.
4. Add an explicit syscall/VFS boundary and guest ABI layout tests; never pass host pointers or host `long`/`size_t` layouts through guest registers.
5. Implement system/JNI thunks, handles/strings/arrays/exceptions, and thread attach/detach with dedicated tests.
6. Add lifecycle IPC and framework proxying incrementally, with capability checks and per-API unsupported reports. Only after a separate security review consider enabling a constrained launch path.

A completed earlier gate does not imply that a later gate or general Android framework compatibility is available.
