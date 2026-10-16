# Compatibility matrix

This matrix describes what the current tree implements. “Available” means the listed narrow operation is present; it is not a claim that arbitrary Android software runs.

| Area | Current status | Boundaries |
| --- | --- | --- |
| Import a single APK | Partial | Copies a document-provider selection to private storage, hashes it, reads package/version/SDK metadata, and catalogs `.so` files inside the APK. Split APKs and package installation are not implemented. |
| Management UI | Partial | Lists imported records, shows details and capability diagnostics, supports guest data/OBB attachments, export, clearing guest-owned directories, and removing one imported record. Launch and Stop stay disabled until an end-to-end runtime and security boundary are available. |
| Android/data ZIP import | Available | Streams into private temporary storage, enforces compressed/uncompressed byte and entry quotas, validates optional package-qualified roots, rejects traversal/duplicate paths/Unix symlinks, and commits with rollback. This is data import, not Android app installation. |
| OBB import and export | Available | Imports one package/version-qualified `.obb` or ZIP bundles of associated OBBs with quotas and path/symlink checks. SAF ZIP export streams guest internal/external/OBB files and a JSON manifest. |
| Registry | Available | App-private JSON registry, record/path validation, and atomic replacement. It is not encrypted and relies on Android's normal application sandbox. |
| ARM32 ELF identification | Available | Host validator accepts supported ELF32 little-endian `EM_ARM` ET_EXEC/ET_DYN metadata; CI uses actual NDK-produced ARM32 executable and shared-object fixtures. |
| ELF segment loading and relocations | Partial | Maps bounded PT_LOAD regions with guest permissions, parses dynamic/hash tables, resolves exports and applies a reviewed ARM REL subset. RELA/RELR/Android packed relocations, dependency loading, a full dynamic linker, and TLS are unsupported. |
| ELF lifecycle functions | Partial | Validates DT_INIT/DT_INIT_ARRAY and DT_FINI/DT_FINI_ARRAY addresses, then can call them through a temporary guest return thunk. This is covered by synthetic A32/T32 native tests; not wired to app launch/unload. |
| A32/T32 instruction execution | Partial | A bounded interpreter executes an explicit ARMv7 subset (including common integer, branch, memory, Thumb-2 MOVW/MOVT, SVC, and guest trampoline paths). It is not a complete ARM CPU or DBT and does not implement VFP/NEON. The optional unavailable DBT placeholder remains separate. |
| Guest heap | Partial | A bounded 32-bit allocator supports aligned allocation, calloc/realloc/free, coalescing, and POSIX alignment validation. It is not a replacement for Bionic's allocator or multithread-safe process heap. |
| Guest VFS and Linux EABI syscalls | Partial | A POSIX-backed descriptor layer maps only app-private internal/external/OBB roots, rejects traversal/symlink components, and implements tested file I/O, stat/directory basics, clocks, `mmap2`/`munmap`/`mprotect`, `brk`, and selected process calls. Writable shared mappings, full `*at`/futex semantics, many syscalls, and all libc wrappers are unsupported; unknown calls return `ENOSYS`. This is not wired to APK launch or a kernel sandbox. |
| Bionic/libc/libm/pthread | Not implemented | The heap/VFS/syscall layer is not a Bionic implementation. No general C/C++ runtime, math, thread, dynamic-loader, TLS, or Android-specific symbol coverage is present. |
| JNI | Not implemented | The native opaque-handle table is a primitive only; no guest `JNIEnv`/`JavaVM`, ART refs, `JNI_OnLoad`, `RegisterNatives`, callbacks, or exception marshaling. |
| Android framework | Not implemented | No Activity/Service proxy, PackageManager spoofing, Resources/AssetManager virtualization, permission model, or guest lifecycle integration. |
| Rootless data isolation | Partial | App-private per-import directories and guarded path mapping exist. This is not kernel isolation, a process-level guest sandbox, or a safe execution boundary for native guest code. |
| Privileged/system integration | Out of scope for this prototype | Device-wide ABI reporting, system linker changes, and global package visibility cannot be promised to a standard unprivileged app. |

## Why ARM32 ABI detection is not compatibility

An APK may contain valid ARM32 machine code and still require unsupported linker symbols, Android framework APIs, Bionic behavior, kernel syscalls, graphics/audio services, or native libraries. RetroBridge currently does not execute code from imported APKs. The UI reports that separately from ELF metadata validation.
