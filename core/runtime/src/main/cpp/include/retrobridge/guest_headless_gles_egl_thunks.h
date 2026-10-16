#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_android_window_thunks.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/handle_table.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** Software EGL/window-surface and GLES clear/scissor subset; no shader or draw pipeline. */
class GuestHeadlessGlesEglThunks final {
public:
    static constexpr std::uint32_t kEglTrue = 1;
    static constexpr std::uint32_t kEglFalse = 0;
    static constexpr std::uint32_t kEglNone = 0x3038;
    static constexpr std::uint32_t kEglOpenGlesApi = 0x30a0;
    static constexpr std::uint32_t kGlColorBufferBit = 0x00004000;
    static constexpr std::uint32_t kGlScissorTest = 0x0c11;

    GuestHeadlessGlesEglThunks(
        GuestMemory& memory,
        GuestHeap32& heap,
        GuestTrampolineRegistry& trampolines,
        GuestAndroidWindowThunks& windows);
    ~GuestHeadlessGlesEglThunks();

    GuestHeadlessGlesEglThunks(const GuestHeadlessGlesEglThunks&) = delete;
    GuestHeadlessGlesEglThunks& operator=(const GuestHeadlessGlesEglThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;

private:
    struct Surface final {
        std::uint64_t token = 0;
        std::uint32_t guest_handle = 0;
        std::uint32_t native_window = 0;
        std::uint64_t config_token = 2;
    };
    struct Context final {
        std::uint64_t token = 0;
        std::uint32_t guest_handle = 0;
        std::uint64_t config_token = 2;
        std::array<float, 4> clear_color{0.0F, 0.0F, 0.0F, 0.0F};
        std::array<std::int32_t, 4> viewport{0, 0, 0, 0};
        std::array<std::int32_t, 4> scissor{0, 0, 0, 0};
        bool scissor_enabled = false;
        std::uint32_t error = 0;
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::uint32_t> allocate_handle_cell(std::uint64_t token);
    [[nodiscard]] std::optional<std::uint64_t> resolve_token(std::uint32_t handle) const noexcept;
    [[nodiscard]] bool is_display(std::uint32_t handle) const noexcept;
    [[nodiscard]] bool is_config(std::uint32_t handle) const noexcept;
    [[nodiscard]] Surface* find_surface(std::uint32_t handle) noexcept;
    [[nodiscard]] const Surface* find_surface(std::uint32_t handle) const noexcept;
    [[nodiscard]] Context* find_context(std::uint32_t handle) noexcept;
    [[nodiscard]] const Context* find_context(std::uint32_t handle) const noexcept;
    void invalidate_handle(std::uint32_t handle) noexcept;
    [[nodiscard]] std::optional<std::uint32_t> stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept;
    void set_egl_error(std::uint32_t error) noexcept;
    void set_gl_error(Context& context, std::uint32_t error) noexcept;
    [[nodiscard]] bool supported_config_attributes(std::uint32_t address, bool& matches) const noexcept;
    [[nodiscard]] bool supported_surface_attributes(std::uint32_t address) const noexcept;
    [[nodiscard]] bool supported_context_attributes(std::uint32_t address) const noexcept;
    [[nodiscard]] GuestHookResult egl_get_display(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_initialize(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_terminate(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_choose_config(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_get_config_attrib(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_create_window_surface(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_create_context(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_make_current(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_swap_buffers(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_destroy_surface(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_destroy_context(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_bind_api(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_get_error(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_get_current_display(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_get_current_context(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult egl_get_current_surface(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_clear_color(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_clear(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_viewport(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_scissor(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_enable(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_disable(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_get_error(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_get_string(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_flush(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult gl_finish(GuestCpuState32& state);
    [[nodiscard]] bool write_c_string(std::string_view value, GuestAddress32& output);

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    GuestAndroidWindowThunks& windows_;
    HandleTable handles_{128};
    bool installed_ = false;
    bool initialized_ = false;
    std::uint32_t bound_api_ = kEglOpenGlesApi;
    std::uint32_t egl_error_ = 0x3000;
    std::uint32_t next_trampoline_address_ = 0xf7000000U;
    std::uint64_t next_object_token_ = 3;
    std::uint32_t display_handle_ = 0;
    std::uint32_t config_handle_ = 0;
    std::uint64_t current_context_token_ = 0;
    std::uint64_t current_surface_token_ = 0;
    std::map<std::uint64_t, Surface> surfaces_;
    std::map<std::uint64_t, Context> contexts_;
    std::map<std::uint32_t, std::uint32_t> external_handles_;
    std::vector<GuestAddress32> handle_cells_;
    std::map<std::uint32_t, GuestAddress32> gl_strings_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::vector<std::uint32_t> trampoline_addresses_;
    mutable std::mutex state_mutex_;

    static constexpr std::uint64_t kDisplayToken = 1;
    static constexpr std::uint64_t kConfigToken = 2;
    static constexpr std::uint32_t kHandleMagic = 0x45474c48U; // "EGLH"
    static constexpr std::size_t kMaxHandleCells = 128;
    static constexpr std::size_t kMaxSurfaces = 16;
    static constexpr std::size_t kMaxContexts = 16;
    static constexpr std::uint32_t kEglSuccess = 0x3000;
    static constexpr std::uint32_t kEglNotInitialized = 0x3001;
    static constexpr std::uint32_t kEglBadAlloc = 0x3003;
    static constexpr std::uint32_t kEglBadAttribute = 0x3004;
    static constexpr std::uint32_t kEglBadConfig = 0x3005;
    static constexpr std::uint32_t kEglBadContext = 0x3006;
    static constexpr std::uint32_t kEglBadDisplay = 0x3008;
    static constexpr std::uint32_t kEglBadMatch = 0x3009;
    static constexpr std::uint32_t kEglBadNativeWindow = 0x300b;
    static constexpr std::uint32_t kEglBadParameter = 0x300c;
    static constexpr std::uint32_t kEglBadSurface = 0x300d;
    static constexpr std::uint32_t kGlNoError = 0;
    static constexpr std::uint32_t kGlInvalidEnum = 0x0500;
    static constexpr std::uint32_t kGlInvalidValue = 0x0501;
    static constexpr std::uint32_t kGlOutOfMemory = 0x0505;
    static constexpr std::uint32_t kGlInvalidFramebufferOperation = 0x0506;
    static constexpr std::uint32_t kGlVersion = 0x1f02;
    static constexpr std::uint32_t kGlVendor = 0x1f00;
    static constexpr std::uint32_t kGlRenderer = 0x1f01;
    static constexpr std::uint32_t kGlExtensions = 0x1f03;
};

}  // namespace retrobridge::runtime
