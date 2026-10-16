# Security model and limitations

## Current trust model

- APKs, registry files, package metadata, ZIP entries, ELF headers, and library names are untrusted input.
- Imported data stays below the app's private files directory. A generated UUID is part of each guest root so two imports do not share mutable files.
- Registry fields are validated on both write and read. Corrupt registry data causes a visible startup failure; the original file is not silently replaced with an empty registry.
- The filesystem mapper allows only explicit package-private `/data` and app-specific external data/OBB prefixes. It rejects traversal, NULs, unknown roots, and symlink components.
- Clear Data operates only on that import's internal and app-specific external directories. Remove operates only on its validated UUID root and does not follow symlinks.
- APK import copies bytes, reads package metadata, and catalogs native-library names. It performs a bounded read-only ELF preflight (header plus program-header table, with per-library and archive work caps), records structural failures, and never extracts a `.so`; a passing result does not prove dependencies, relocations, symbols, loadability, or launch support. Import does not call the package installer or load guest code.
- Android/data and OBB ZIP imports spool to app-private temporary files, enforce compressed/uncompressed byte and entry-count quotas, reject traversal and Unix symlink entries, validate package-qualified roots and OBB filenames, then stage before replacing guest files with rollback backups. Current limits are 1 GiB compressed / 2 GiB expanded / 50,000 entries / 512 MiB per data file; OBB bundle 2 GiB compressed / 16 GiB expanded / 256 entries / 8 GiB per OBB; raw OBB import 8 GiB.
- ZIP export walks only guest-owned internal, external, and OBB directories without following symlinks, is capped at 16 GiB of guest file bytes, streams files to the selected SAF destination, and includes a JSON inventory/OBB manifest.
- The reserved guest service is non-exported and in `:guest_runtime`; it rejects start requests. No untrusted native code currently runs in it.

## Not a security boundary for guest execution

A process split alone is not a complete sandbox. The repository now contains a bounded ARM instruction interpreter and host-side fixture execution, but imported APK code is not launched and the reserved Android guest service still rejects start requests. Before enabling execution of imported code, the design must account for host process credentials, file descriptors, signals, memory mapping, executable memory, thread creation, Binder access, Android permission checks, host pointers, callbacks, and denial-of-service risks. Guest code must not be enabled based solely on ELF validation or the current interpreter.

A POSIX-backed VFS and ARM32 EABI syscall dispatcher mediate a tested subset of guest file, memory, clock, and process calls when explicitly attached to the runtime. `GuestBionicThunks` separately provides a narrow libc/libm/pthread subset backed by guest memory and the VFS; it does not start guest threads, implement per-thread errno/TLS, or replace Bionic. Path translation permits only app-private internal/external/OBB roots and rejects traversal and symlink components; it is not a kernel mount namespace and does not protect against every filesystem race. Many syscalls and Bionic APIs, writable shared mappings, guest thread scheduling, Binder, and arbitrary host APIs remain unsupported, and neither layer is wired to imported APK launch. Do not use the prototype to run APKs from untrusted sources as executable guests.

## Planned hardening before imported APK execution

- Fuzz ELF parsing and any ZIP/data archive extraction.
- Fuzz the guest allocator and continue bounds-checking every guest read/write and ABI structure conversion.
- Keep host pointers, JNI references, `size_t`, `long`, `off_t`, and host structure layouts behind typed marshaling APIs.
- Deny unimplemented syscalls and symbols with package/library/symbol diagnostics; never resolve an ARM32 symbol by loading an incompatible ARM64 library.
- Add resource limits, cancellation, crash isolation, and per-app storage quota handling.
- Perform a security review before enabling Launch.
