#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** Host-drained PCM from the narrow OpenSL ES buffer-queue model; this is not audible playback. */
struct GuestOpenSlPcmBuffer32 final {
    std::uint32_t sample_rate_millihz = 0;
    std::uint32_t channels = 0;
    std::uint32_t bits_per_sample = 0;
    std::vector<std::byte> samples;
};

/**
 * Synthetic OpenSL ES engine/output-mix/player ABI for bounded Android PCM buffer queues.
 * It has guest-memory object/interface vtables and no Android audio sink or callback scheduler.
 */
class GuestOpenSlThunks final {
public:
    GuestOpenSlThunks(GuestMemory& memory, GuestHeap32& heap, GuestTrampolineRegistry& trampolines);
    ~GuestOpenSlThunks();

    GuestOpenSlThunks(const GuestOpenSlThunks&) = delete;
    GuestOpenSlThunks& operator=(const GuestOpenSlThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;
    [[nodiscard]] std::optional<GuestOpenSlPcmBuffer32> consume_next_playback_buffer(std::uint32_t player_object);

private:
    enum class InterfaceIdKind : std::uint8_t {
        Null,
        Object,
        Engine,
        OutputMix,
        Play,
        BufferQueue,
        AndroidSimpleBufferQueue,
        Volume,
        EffectSend,
        AndroidConfiguration,
        Record,
    };
    enum class ObjectKind : std::uint8_t { Engine, OutputMix, AudioPlayer };
    enum class InterfaceKind : std::uint8_t { Engine, Play, BufferQueue };

    struct InterfaceId final {
        std::uint32_t time_low = 0;
        std::uint16_t time_mid = 0;
        std::uint16_t time_hi_and_version = 0;
        std::uint16_t clock_sequence = 0;
        std::array<std::uint8_t, 6> node{};
        friend bool operator==(const InterfaceId&, const InterfaceId&) = default;
    };
    struct InterfaceRef final {
        std::uint64_t object_token = 0;
        InterfaceKind kind = InterfaceKind::Engine;
    };
    struct RequestedInterface final {
        InterfaceId id{};
        std::uint8_t required = 0;
    };
    struct RequestedInterfaces final {
        std::array<RequestedInterface, 16> values{};
        std::size_t count = 0;
    };
    struct Object final {
        std::uint64_t token = 0;
        std::uint32_t guest_handle = 0;
        ObjectKind kind = ObjectKind::Engine;
        std::uint64_t engine_token = 0;
        std::uint64_t output_mix_token = 0;
        std::uint32_t reference_count = 1;
        std::uint32_t engine_interface = 0;
        std::uint32_t play_interface = 0;
        std::uint32_t buffer_queue_interface = 0;
        std::uint32_t max_queue_buffers = 0;
        std::uint32_t play_state = 1;
        std::uint32_t queue_index = 0;
        std::uint32_t sample_rate_millihz = 0;
        std::uint32_t channels = 0;
        std::uint32_t bits_per_sample = 0;
        std::int32_t priority = 0;
        bool preemptable = true;
        bool realized = false;
        std::size_t queued_bytes = 0;
        std::deque<std::vector<std::byte>> buffers;
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<GuestAddress32> allocate_guest(std::size_t size);
    void free_guest(GuestAddress32 address) noexcept;
    [[nodiscard]] std::optional<GuestAddress32> make_vtable(std::span<const std::uint32_t> entries);
    [[nodiscard]] std::optional<std::uint32_t> create_object(
        ObjectKind kind,
        std::uint64_t engine_token,
        std::uint64_t output_mix_token,
        std::uint32_t max_queue_buffers,
        std::uint32_t sample_rate_millihz,
        std::uint32_t channels,
        std::uint32_t bits_per_sample);
    [[nodiscard]] Object* object_for_handle(std::uint32_t handle) noexcept;
    [[nodiscard]] const Object* object_for_handle(std::uint32_t handle) const noexcept;
    [[nodiscard]] Object* object_for_token(std::uint64_t token) noexcept;
    [[nodiscard]] InterfaceRef* interface_for_handle(std::uint32_t handle) noexcept;
    [[nodiscard]] bool read_interface_id(std::uint32_t address, InterfaceId& output) const noexcept;
    [[nodiscard]] std::optional<InterfaceIdKind> classify_interface_id(const InterfaceId& id) const noexcept;
    [[nodiscard]] bool write_interface_id(InterfaceIdKind kind, GuestAddress32& variable_address);
    [[nodiscard]] bool read_requested_interfaces(
        const GuestCpuState32& state,
        std::uint32_t count,
        std::uint32_t ids_address,
        std::uint32_t required_address,
        RequestedInterfaces& output) const noexcept;
    [[nodiscard]] bool requested_interface_is_supported(
        const RequestedInterfaces& interfaces,
        std::span<const InterfaceIdKind> supported) const noexcept;
    [[nodiscard]] bool stack_argument(const GuestCpuState32& state, std::size_t index, std::uint32_t& output) const noexcept;
    [[nodiscard]] GuestHookResult unsupported(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult create_engine(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult query_num_engine_interfaces(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult query_engine_interface(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_realize(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_resume(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_get_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_get_interface(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_register_callback(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_abort_async_operation(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_destroy(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_set_priority(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult object_get_priority(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult engine_create_output_mix(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult engine_create_audio_player(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult play_set_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult play_get_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_enqueue(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_clear(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_get_state(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult queue_register_callback(GuestCpuState32& state);
    [[nodiscard]] std::uint32_t validate_audio_player_source(
        std::uint32_t source_address,
        std::uint32_t sink_address,
        std::uint64_t engine_token,
        std::uint64_t& output_mix_token,
        std::uint32_t& max_queue_buffers,
        std::uint32_t& sample_rate_millihz,
        std::uint32_t& channels,
        std::uint32_t& bits_per_sample) const noexcept;
    void destroy_object(std::uint64_t token) noexcept;

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf8000000U;
    std::uint64_t next_object_token_ = 1;
    std::size_t queued_bytes_total_ = 0;
    GuestAddress32 object_vtable_{0};
    GuestAddress32 engine_vtable_{0};
    GuestAddress32 play_vtable_{0};
    GuestAddress32 queue_vtable_{0};
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::map<InterfaceIdKind, InterfaceId> interface_ids_;
    std::map<std::uint64_t, Object> objects_;
    std::map<std::uint32_t, std::uint64_t> object_handles_;
    std::map<std::uint32_t, InterfaceRef> interface_handles_;
    std::vector<GuestAddress32> guest_allocations_;
    std::vector<std::uint32_t> trampoline_addresses_;
    mutable std::mutex state_mutex_;

    static constexpr std::uint32_t kResultSuccess = 0;
    static constexpr std::uint32_t kResultPreconditionsViolated = 1;
    static constexpr std::uint32_t kResultParameterInvalid = 2;
    static constexpr std::uint32_t kResultMemoryFailure = 3;
    static constexpr std::uint32_t kResultResourceError = 4;
    static constexpr std::uint32_t kResultBufferInsufficient = 7;
    static constexpr std::uint32_t kResultContentUnsupported = 9;
    static constexpr std::uint32_t kResultFeatureUnsupported = 12;
    static constexpr std::uint32_t kObjectStateUnrealized = 1;
    static constexpr std::uint32_t kObjectStateRealized = 2;
    static constexpr std::uint32_t kPlayStateStopped = 1;
    static constexpr std::uint32_t kPlayStatePaused = 2;
    static constexpr std::uint32_t kPlayStatePlaying = 3;
    static constexpr std::uint32_t kMaxObjects = 32;
    static constexpr std::uint32_t kMaxEngineOptions = 16;
    static constexpr std::uint32_t kMaxQueueBuffers = 32;
    static constexpr std::size_t kMaxPcmBufferBytes = 1024U * 1024U;
    static constexpr std::size_t kMaxQueuedPcmBytes = 8U * 1024U * 1024U;
    static constexpr std::size_t kMaxGuestAllocations = 1024;
    static constexpr std::size_t kMaxInterfaceRequests = 16;

    // Standard IDs match the OpenSL ES 1.0.1 ABI shipped by the Android NDK; Android extension IDs use AOSP API-level-9 definitions.
    static constexpr InterfaceId kIidNull{0xec7178ecU, 0xe5e1U, 0x4432U, 0xa3f4U, {0x46, 0x57, 0xe6, 0x79, 0x52, 0x10}};
    static constexpr InterfaceId kIidObject{0x79216360U, 0xddd7U, 0x11dbU, 0xac16U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidEngine{0x8d97c260U, 0xddd4U, 0x11dbU, 0x958fU, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidOutputMix{0x97750f60U, 0xddd7U, 0x11dbU, 0x92b1U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidPlay{0xef0bd9c0U, 0xddd7U, 0x11dbU, 0xbf49U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidBufferQueue{0x2bc99cc0U, 0xddd4U, 0x11dbU, 0x8d99U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidBufferQueue11{0x524b68a0U, 0xd3d6U, 0x11dfU, 0xbd3bU, {0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66}};
    static constexpr InterfaceId kIidAndroidSimpleBufferQueue{0x89f6a7e0U, 0xbeacU, 0x11dfU, 0x8b5cU, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidVolume{0x09e8ede0U, 0xdddeU, 0x11dbU, 0xb4f6U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidEffectSend{0x56e7d200U, 0xddd4U, 0x11dbU, 0xaefbU, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidAndroidConfiguration{0x7be462c0U, 0xbc43U, 0x11dfU, 0x8670U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    static constexpr InterfaceId kIidRecord{0xc5657aa0U, 0xdddbU, 0x11dbU, 0x82f7U, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
};

}  // namespace retrobridge::runtime
