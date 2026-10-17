#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/elf32_image.h"
#include "retrobridge/elf32_loader.h"
#include "retrobridge/guest_android_asset_thunks.h"
#include "retrobridge/guest_android_input_thunks.h"
#include "retrobridge/guest_android_window_thunks.h"
#include "retrobridge/guest_bionic_thunks.h"
#include "retrobridge/guest_headless_gles_egl_thunks.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/guest_jni_bridge.h"
#include "retrobridge/guest_lifecycle.h"
#include "retrobridge/guest_memory.h"
#include "retrobridge/guest_opensl_thunks.h"
#include "arm32_syscall_dispatcher.h"
#include "native_vfs.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace retrobridge::runtime {

struct NativeLibraryMetadata final {
    bool valid = false;
    std::string library_name;
    std::string soname;
    std::vector<std::string> needed_libraries;
    std::string diagnostic;
};

struct NativeLoadResult final {
    bool loaded = false;
    std::string library_name;
    std::uint32_t load_address = 0;
    std::vector<std::string> needed_libraries;
    std::string diagnostic;
};

struct NativeExecutionReport final {
    bool success = false;
    std::uint64_t guest_instructions = 0;
    std::uint32_t relocation_count = 0;
    std::int32_t jni_on_load_version = -1;
    std::uint32_t registered_native_count = 0;
    std::vector<std::string> loaded_libraries;
    std::vector<std::string> entrypoint_results;
    std::vector<std::string> diagnostics;
};

/**
 * Bounded ARM32 shared-object session. Guest addresses are interpreted by Arm32Interpreter and
 * all host interaction is marshalled through the explicitly installed guest thunks/VFS.
 */
class NativeExecutionSession final {
public:
    NativeExecutionSession(std::filesystem::path app_root, std::string package_name);
    ~NativeExecutionSession();

    NativeExecutionSession(const NativeExecutionSession&) = delete;
    NativeExecutionSession& operator=(const NativeExecutionSession&) = delete;

    [[nodiscard]] bool initialize(std::string* diagnostic = nullptr);
    [[nodiscard]] NativeLibraryMetadata inspect_library(
        std::span<const std::byte> file,
        std::string library_name) const;
    [[nodiscard]] NativeLoadResult load_library(
        std::span<const std::byte> file,
        std::string library_name);
    [[nodiscard]] NativeExecutionReport execute(std::uint64_t instruction_budget = 8'000'000);
    void stop() noexcept;

    [[nodiscard]] const std::filesystem::path& app_root() const noexcept { return app_root_; }
    [[nodiscard]] const std::filesystem::path& native_library_root() const noexcept { return native_library_root_; }
    [[nodiscard]] bool initialized() const noexcept { return initialized_; }
    [[nodiscard]] std::size_t loaded_library_count() const noexcept { return images_.size(); }

private:
    struct Library final {
        Elf32LoadedImage image;
        std::size_t file_size = 0;
    };

    [[nodiscard]] std::vector<std::size_t> dependency_order(std::vector<std::string>& diagnostics) const;
    [[nodiscard]] bool supported_platform_library(std::string_view name) const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(
        std::string_view name,
        std::size_t importing_image,
        const std::vector<std::size_t>& order) const noexcept;
    [[nodiscard]] ExecutionResult invoke_guest_function(
        GuestAddress32 function,
        std::uint64_t instruction_budget,
        std::uint32_t first_argument,
        std::uint32_t second_argument,
        std::uint32_t& return_value,
        std::string_view label);
    [[nodiscard]] std::uint64_t remaining_budget(std::uint64_t budget) const noexcept;
    void append_diagnostic(NativeExecutionReport& report, std::string diagnostic) const;

    std::filesystem::path app_root_;
    std::filesystem::path native_library_root_;
    std::string package_name_;
    GuestMemory memory_;
    GuestHeap32 heap_;
    GuestTrampolineRegistry trampolines_;
    NativeVfs vfs_;
    Arm32SyscallDispatcher syscalls_;
    Arm32Interpreter engine_;
    GuestLifecycleExecutor lifecycle_;
    GuestBionicThunks bionic_;
    GuestJniBridge jni_;
    GuestAndroidAssetThunks assets_;
    GuestAndroidWindowThunks windows_;
    GuestAndroidInputThunks input_;
    GuestHeadlessGlesEglThunks gles_;
    GuestOpenSlThunks opensl_;
    std::vector<Library> images_;
    std::vector<std::size_t> initialized_image_order_;
    GuestCpuState32 cpu_state_{};
    std::uint64_t next_load_bias_ = 0x40000000ULL;
    std::size_t loaded_file_bytes_ = 0;
    std::uint64_t instructions_executed_ = 0;
    bool initialized_ = false;
    bool executed_ = false;
    bool guest_code_started_ = false;
    bool stopped_ = false;
    mutable std::mutex mutex_;

    static constexpr std::size_t kGuestMemoryLimit = 256U * 1024U * 1024U;
    static constexpr std::size_t kMaximumLibraries = 32;
    static constexpr std::size_t kMaximumLibraryBytes = 64U * 1024U * 1024U;
    static constexpr std::size_t kMaximumTotalLibraryBytes = 192U * 1024U * 1024U;
    static constexpr std::uint32_t kGuestStackBase = 0x70000000U;
    static constexpr std::uint32_t kGuestStackSize = 2U * 1024U * 1024U;
};

}  // namespace retrobridge::runtime
