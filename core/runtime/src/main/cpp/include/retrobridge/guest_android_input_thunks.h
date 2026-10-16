#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/handle_table.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

enum class GuestInputEventType32 : std::int32_t {
    Key = 1,
    Motion = 2,
};

struct GuestMotionPointer32 final {
    std::int32_t id = 0;
    float x = 0.0F;
    float y = 0.0F;
    float pressure = 1.0F;
};

/** Host-injected event data; floats and timestamps are marshaled into the ARM32 NDK ABI. */
struct GuestInputEvent32 final {
    GuestInputEventType32 type = GuestInputEventType32::Key;
    std::int32_t device_id = 0;
    std::int32_t source = 0;
    std::int32_t action = 0;
    std::int32_t key_code = 0;
    std::int32_t meta_state = 0;
    std::int32_t repeat_count = 0;
    std::int64_t down_time_ns = 0;
    std::int64_t event_time_ns = 0;
    std::vector<GuestMotionPointer32> pointers;
};

/** Synthetic AInputQueue and nonblocking ALooper subset; no Android system input source is attached. */
class GuestAndroidInputThunks final {
public:
    GuestAndroidInputThunks(GuestMemory& memory, GuestHeap32& heap, GuestTrampolineRegistry& trampolines);
    ~GuestAndroidInputThunks();

    GuestAndroidInputThunks(const GuestAndroidInputThunks&) = delete;
    GuestAndroidInputThunks& operator=(const GuestAndroidInputThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] std::optional<std::uint32_t> create_input_queue(std::string* diagnostic = nullptr);
    [[nodiscard]] bool enqueue_input_event(
        std::uint32_t queue,
        GuestInputEvent32 event,
        std::string* diagnostic = nullptr);

    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;

private:
    struct Queue final {
        std::uint64_t token = 0;
        std::deque<GuestInputEvent32> pending;
    };
    struct EventRecord final {
        std::uint64_t queue_token = 0;
        GuestInputEvent32 event;
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::uint32_t> allocate_handle_cell(std::uint64_t token);
    [[nodiscard]] std::optional<std::uint64_t> resolve_object_token(std::uint32_t handle) const noexcept;
    [[nodiscard]] Queue* find_queue(std::uint32_t handle) noexcept;
    [[nodiscard]] const Queue* find_queue(std::uint32_t handle) const noexcept;
    [[nodiscard]] EventRecord* find_event(std::uint32_t handle) noexcept;
    [[nodiscard]] const EventRecord* find_event(std::uint32_t handle) const noexcept;
    [[nodiscard]] bool is_looper(std::uint32_t handle) const noexcept;
    void invalidate_handle(std::uint32_t handle) noexcept;
    [[nodiscard]] GuestHookResult queue_has_events(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_get_event(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_pre_dispatch(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_finish_event(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult input_event_type(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult input_event_device_id(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult input_event_source(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_action(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_key_code(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_meta_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_repeat_count(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_down_time(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult key_event_event_time(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_action(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_meta_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_pointer_count(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_history_size(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_pointer_id(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_x(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_y(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_pressure(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult motion_event_event_time(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_prepare(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_for_thread(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_acquire(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_release(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_wake(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_poll(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_add_fd(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult looper_remove_fd(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult event_int_field(GuestCpuState32& state, std::int32_t GuestInputEvent32::*field, bool key_only);
    [[nodiscard]] GuestHookResult event_time_field(GuestCpuState32& state, std::int64_t GuestInputEvent32::*field, bool key_only);
    [[nodiscard]] GuestHookResult motion_float_field(GuestCpuState32& state, float GuestMotionPointer32::*field);
    [[nodiscard]] bool valid_event(const GuestInputEvent32& event) const noexcept;

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    HandleTable handles_{512};
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf6000000U;
    std::uint64_t next_object_token_ = 2;
    std::uint64_t queue_token_ = 0;
    std::uint32_t queue_handle_ = 0;
    std::uint32_t looper_handle_ = 0;
    std::uint32_t looper_references_ = 1;
    bool looper_wake_pending_ = false;
    Queue queue_;
    std::map<std::uint64_t, EventRecord> events_;
    std::map<std::uint32_t, std::uint32_t> external_handles_;
    std::vector<GuestAddress32> handle_cells_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::vector<std::uint32_t> trampoline_addresses_;
    mutable std::mutex state_mutex_;

    static constexpr std::uint64_t kLooperToken = 1;
    static constexpr std::uint32_t kHandleMagic = 0x41494e50U; // "AINP"
    static constexpr std::size_t kMaxHandleCells = 512;
    static constexpr std::size_t kMaxPendingEvents = 64;
    static constexpr std::size_t kMaxMotionPointers = 16;
};

}  // namespace retrobridge::runtime
