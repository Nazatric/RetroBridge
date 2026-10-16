# Architecture and status

RetroBridge is split so a later guest runtime can be developed without conflating “the CPU can decode ARM instructions” with “an Android app is compatible.” The current code is a safety-oriented foundation, not a finished compatibility runtime.

## Process and trust boundaries

- `:app` is the normal management process. It imports a selected base APK into app-private storage, keeps registry metadata, and displays explicit capability status.
- `:core:runtime` contributes a native `arm64-v8a` library and declares a non-exported `GuestRuntimeService` in `android:process=":guest_runtime"`. The service immediately rejects start requests. The process boundary is reserved, not an active execution sandbox.
- `:core:manager` owns immutable guest metadata, an atomic JSON registry, and lifecycle transition validation.
- `:core:fs` owns the per-import filesystem layout, narrow guest-path mapper, quota-bounded streaming Android/data and OBB ZIP import, and SAF-export ZIP writer. It is not a mount namespace and does not grant access to arbitrary external storage.
- `:core:services` emits a capability report. It does not spoof PackageManager data or claim to provide Android framework services.
- `core/runtime/src/main/cpp` contains native ABI boundary types, a strict ELF32/ARM metadata reader, an opaque handle table, and a translation-engine interface. The only supplied engine refuses execution.
- `native/` builds host-side verification tools and parses real ARM32 test ELF files cross-compiled by CI.

## Important interfaces

### Guest address space

`GuestAddress32` and `GuestRange32` store guest addresses as `uint32_t` and check arithmetic in a wider integer type. They never reinterpret a 32-bit guest address as a host pointer. A real guest arena, page mapping strategy, memory protection implementation, signal handler, and guest/host marshaling layer are not implemented.

### Translation engine

`TranslationEngine` is the future A32/T32-to-A64 execution boundary. `GuestCpuState32` carries R0-R15, CPSR, FPSCR, Q0-Q15, and guest TLS. `UnavailableTranslationEngine` reports `BackendUnavailable` for every run request. Dynarmic is not vendored, configured, or claimed to have been validated.

### ELF inspection

`Elf32Image::parse` accepts little-endian ELFCLASS32 `EM_ARM` ET_EXEC/ET_DYN files, validates program-header and file-backed segment bounds, and extracts `DT_NEEDED` names from a mapped `DT_STRTAB`. Diagnostics include the source filename and optional guest package. It does **not** mmap segments, implement `PT_TLS`, resolve symbols, apply ARM relocations, load dependencies, or invoke constructors. Host CTest checks generated ARM32 executable and shared-library fixtures.

### Guest references

`HandleTable` demonstrates a generation-checked 32-bit handle to opaque 64-bit token mapping. It is not a synthetic `JNIEnv`, does not call ART, and does not yet model JNI local frames, weak-reference collection, exceptions, or callbacks.

### Persistence and per-app storage

Each import gets `RetroBridge/apps/<package>/<uuid>/` so separate imports cannot reuse a mutable root. The manager stores only normalized paths relative to RetroBridge's private data root. Registry writes use a same-directory temporary file and atomic replacement when supported. The storage layer only maps the documented app-private paths and rejects traversal, unknown roots, and symlink components.

## Roadmap (gates, not promises)

1. Keep import, registry, path isolation, and ABI diagnostics tested.
2. Select a licensed ARM32 translation backend, document its provenance and limitations, then add instruction-level tests before enabling any guest instruction execution.
3. Implement an owned guest memory arena, ELF mapping/relocation/dependency loading, and safe guest fault reporting; fuzz the parser/loader before loading untrusted APK content.
4. Add an explicit syscall/VFS boundary and ABI layout tests; never pass host pointers or host `long`/`size_t` layouts through guest registers.
5. Implement JNI handles/strings/arrays/exception behavior and thread attach/detach with dedicated tests.
6. Add framework proxying incrementally, with capability checks and per-API unsupported reports. Only then consider enabling a constrained launch path.

A completed earlier gate does not imply that a later gate or general Android framework compatibility is available.
