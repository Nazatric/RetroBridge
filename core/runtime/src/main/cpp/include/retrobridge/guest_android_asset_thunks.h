#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/handle_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/**
 * Narrow NDK AAssetManager/AAsset bridge backed by caller-registered immutable asset blobs.
 * Guest handles are generation-checked opaque values, never host pointers or file descriptors.
 */
class GuestAndroidAssetThunks final {
public:
    GuestAndroidAssetThunks(GuestMemory& memory, GuestHeap32& heap, GuestTrampolineRegistry& trampolines);
    ~GuestAndroidAssetThunks();

    GuestAndroidAssetThunks(const GuestAndroidAssetThunks&) = delete;
    GuestAndroidAssetThunks& operator=(const GuestAndroidAssetThunks&) = delete;

    [[nodiscard]] bool register_asset(
        std::string name,
        std::span<const std::byte> contents,
        std::string* diagnostic = nullptr);
    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;

    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::uint32_t asset_manager_handle() const noexcept { return asset_manager_handle_; }
    [[nodiscard]] std::size_t registered_asset_count() const noexcept { return catalog_.size(); }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;

private:
    struct OpenAsset final {
        std::uint64_t token = 0;
        const std::vector<std::byte>* contents = nullptr;
        std::size_t position = 0;
        GuestAddress32 materialized_buffer{0};
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<GuestAddress32> allocate_handle_cell(std::uint32_t table_handle);
    [[nodiscard]] std::optional<std::string> read_c_string(std::uint32_t address, std::size_t maximum) const;
    [[nodiscard]] std::optional<std::uint32_t> stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept;
    [[nodiscard]] OpenAsset* find_asset(std::uint32_t handle) noexcept;
    [[nodiscard]] const OpenAsset* find_asset(std::uint32_t handle) const noexcept;
    [[nodiscard]] GuestHookResult open_asset(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult read_asset(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult asset_buffer(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult seek_asset(GuestCpuState32& state, bool wide);
    [[nodiscard]] GuestHookResult asset_length(GuestCpuState32& state, bool remaining, bool wide);
    [[nodiscard]] GuestHookResult close_asset(GuestCpuState32& state);
    [[nodiscard]] static bool valid_asset_name(std::string_view name) noexcept;

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    HandleTable handles_{4096};
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf4000000U;
    std::uint32_t asset_manager_handle_ = 0;
    std::uint64_t next_asset_token_ = 2;
    std::size_t catalog_bytes_ = 0;
    std::map<std::string, std::vector<std::byte>, std::less<>> catalog_;
    std::map<std::uint64_t, OpenAsset> open_assets_;
    std::map<std::uint32_t, std::uint32_t> external_handles_;
    std::vector<GuestAddress32> handle_cells_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::vector<std::uint32_t> trampoline_addresses_;
    mutable std::mutex state_mutex_;

    static constexpr std::uint64_t kAssetManagerToken = 1;
    static constexpr std::uint32_t kHandleMagic = 0x41535354U; // "ASST"
    static constexpr std::size_t kMaxAssetHandleCells = 8192;
    static constexpr std::size_t kMaxAssetCount = 4096;
    static constexpr std::size_t kMaxAssetBytes = 64U * 1024U * 1024U;
    static constexpr std::size_t kMaxCatalogBytes = 256U * 1024U * 1024U;
    static constexpr std::size_t kMaxReadBytes = 16U * 1024U * 1024U;
};

}  // namespace retrobridge::runtime
