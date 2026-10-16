#pragma once

namespace retrobridge::runtime {

struct RuntimeCapabilities final {
    bool arm32_elf_metadata_validation = true;
    bool arm32_instruction_translation = false;
    bool arm32_instruction_execution = true;
    bool guest_elf_mapping_and_supported_relocations = true;
    bool guest_heap_allocator = true;
    bool native_guest_vfs = true;
    bool arm32_eabi_syscall_subset = true;
    bool guest_bionic_libc_libm_pthread_thunks = true;
    bool bionic_and_guest_syscalls = false;
    bool synthetic_jni_tables_and_handle_subset = true;
    bool synthetic_jni = false;
    bool android_framework_virtualization = false;
    bool arbitrary_guest_execution = false;
};

[[nodiscard]] constexpr RuntimeCapabilities current_capabilities() noexcept {
    return {};
}

}  // namespace retrobridge::runtime
