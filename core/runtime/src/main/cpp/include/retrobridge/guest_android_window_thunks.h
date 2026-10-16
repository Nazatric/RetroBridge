#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/handle_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** Bounded headless ANativeWindow buffer bridge; it does not create Android Surface objects. */
class GuestAndroidWindowThunks final {
public:
    static constexpr std::uint32_t kRgba8888 = 1;

    GuestAndroidWindowThunks(GuestMemory& memory, GuestHeap32& heap, GuestTrampolineRegistry& trampolines);
    ~GuestAndroidWindowThunks();

    GuestAndroidWindowThunks(const GuestAndroidWindowThunks&) = delete;
    GuestAndroidWindowThunks& operator=(const GuestAndroidWindowThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] std::optional<std::uint32_t> create_headless_window(
        std::uint32_t width,
        std::uint32_t height,
        std::uint32_t format = kRgba8888,
        std::string* diagnostic = nullptr);

    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;
    [[nodiscard]] std::optional<GuestAddress32> pixel_buffer(std::uint32_t window) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> posted_frame_count(std::uint32_t window) const noexcept;

private:
    struct Window final {
        std::uint64_t token = 0;
        std::uint32_t width = 0;
        std::uint32_t height = 0;
        std::uint32_t format = kRgba8888;
        std::uint32_t references = 1;
        GuestAddress32 pixels{0};
        bool locked = false;
        std::uint64_t posted_frames = 0;
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::uint32_t> allocate_window_handle(std::uint64_t token);
    [[nodiscard]] Window* find_window(std::uint32_t handle) noexcept;
    [[nodiscard]] const Window* find_window(std::uint32_t handle) const noexcept;
    [[nodiscard]] std::optional<std::size_t> buffer_size(std::uint32_t width, std::uint32_t height) const noexcept;
    [[nodiscard]] std::optional<GuestAddress32> allocate_surface_buffer(std::size_t bytes);
    void free_surface_buffer(GuestAddress32 address, std::size_t bytes) noexcept;
    [[nodiscard]] bool configure_window(Window& window, std::uint32_t width, std::uint32_t height, std::uint32_t format);
    [[nodiscard]] GuestHookResult acquire(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult release(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult get_width(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult get_height(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult get_format(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult set_geometry(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult lock_window(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult unlock_and_post(GuestCpuState32& state);
    [[nodiscard]] bool write_buffer_descriptor(std::uint32_t address, const Window& window);
    [[nodiscard]] bool write_dirty_rect(std::uint32_t address, const Window& window);

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    HandleTable handles_{256};
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf5000000U;
    std::uint64_t next_window_token_ = 2;
    std::map<std::uint64_t, Window> windows_;
    std::map<std::uint32_t, std::uint32_t> external_handles_;
    std::map<std::uint32_t, std::size_t> surface_ranges_;
    std::size_t surface_bytes_ = 0;
    std::vector<GuestAddress32> handle_cells_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::vector<std::uint32_t> trampoline_addresses_;
    mutable std::mutex state_mutex_;

    static constexpr std::uint32_t kHandleMagic = 0x4e57494eU; // "NWIN"
    static constexpr std::size_t kMaxWindows = 32;
    static constexpr std::size_t kMaxHandleCells = 256;
    static constexpr std::uint64_t kMaxSurfacePixels = 4U * 1024U * 1024U;
    static constexpr std::size_t kMaxSurfaceBytesTotal = 16U * 1024U * 1024U;
    static constexpr std::uint32_t kSurfaceVirtualStart = 0x68000000U;
    static constexpr std::uint32_t kSurfaceVirtualEnd = 0x6c000000U;
    static constexpr std::size_t kSurfacePageBytes = 4096;
    static constexpr std::size_t kMaxSurfacePlacementProbes = 16U * 1024U;
};

}  // namespace retrobridge::runtime
