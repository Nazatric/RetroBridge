# Native interfaces and implementation boundaries

The C++ library is deliberately small and platform-neutral so the ELF/address/handle contracts can be host-tested before native Android code is permitted to run guest instructions.

- `guest_address.h`: overflow-checked guest address and range values.
- `elf32_image.h`: parser output and package-aware diagnostics.
- `translation_engine.h`: future translator contract and explicit unavailable backend.
- `handle_table.h`: generation-checked guest handle map to opaque 64-bit tokens.
- `runtime_capabilities.h`: compile-time capability snapshot that keeps parser support distinct from execution.

The host CMake project is verification-only. It must not be treated as an ARM32 emulator. The Android module builds the same native library for `arm64-v8a`; it currently exports no guest execution or JNI API.
