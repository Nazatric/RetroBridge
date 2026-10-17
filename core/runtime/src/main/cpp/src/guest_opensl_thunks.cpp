#include "retrobridge/guest_opensl_thunks.h"

#include <algorithm>
#include <bit>
#include <limits>
#include <new>
#include <utility>

namespace retrobridge::runtime {
namespace {
constexpr std::uint32_t kDataLocatorOutputMix = 0x00000004U;
constexpr std::uint32_t kDataLocatorAndroidSimpleBufferQueue = 0x800007bdU;
constexpr std::uint32_t kDataFormatPcm = 0x00000001U;
constexpr std::uint32_t kByteOrderLittleEndian = 2U;
constexpr std::uint32_t kEngineOptionThreadSafe = 1U;
constexpr std::uint32_t kEngineOptionLossOfControl = 2U;
constexpr std::uint32_t kSpeakerFrontLeft = 0x00000001U;
constexpr std::uint32_t kSpeakerFrontRight = 0x00000002U;
constexpr std::uint32_t kSpeakerFrontCenter = 0x00000004U;
constexpr std::uint32_t kSampleFormatFixed8 = 8U;
constexpr std::uint32_t kSampleFormatFixed16 = 16U;
}

GuestOpenSlThunks::GuestOpenSlThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines)
    : memory_(memory), heap_(heap), trampolines_(trampolines) {}

GuestOpenSlThunks::~GuestOpenSlThunks() {
    shutdown();
}

bool GuestOpenSlThunks::install(std::string* diagnostic) {
    if (diagnostic != nullptr) diagnostic->clear();
    if (installed_) return true;
    if (!heap_.initialized()) {
        if (diagnostic != nullptr) *diagnostic = "OpenSL ES thunks require an initialized guest heap";
        return false;
    }
    try {
        interface_ids_.emplace(InterfaceIdKind::Null, kIidNull);
        interface_ids_.emplace(InterfaceIdKind::Object, kIidObject);
        interface_ids_.emplace(InterfaceIdKind::Engine, kIidEngine);
        interface_ids_.emplace(InterfaceIdKind::OutputMix, kIidOutputMix);
        interface_ids_.emplace(InterfaceIdKind::Play, kIidPlay);
        interface_ids_.emplace(InterfaceIdKind::BufferQueue, kIidBufferQueue);
        interface_ids_.emplace(InterfaceIdKind::AndroidSimpleBufferQueue, kIidAndroidSimpleBufferQueue);
        interface_ids_.emplace(InterfaceIdKind::Volume, kIidVolume);
        interface_ids_.emplace(InterfaceIdKind::EffectSend, kIidEffectSend);
        interface_ids_.emplace(InterfaceIdKind::AndroidConfiguration, kIidAndroidConfiguration);
        interface_ids_.emplace(InterfaceIdKind::Record, kIidRecord);

        const auto add_iid = [this](std::string name, InterfaceIdKind kind) {
            GuestAddress32 address{0};
            if (!write_interface_id(kind, address)) return false;
            const auto [entry, inserted] = symbols_.emplace(std::move(name), address.value());
            (void)entry;
            return inserted;
        };
        if (!add_iid("SL_IID_NULL", InterfaceIdKind::Null)
            || !add_iid("SL_IID_OBJECT", InterfaceIdKind::Object)
            || !add_iid("SL_IID_ENGINE", InterfaceIdKind::Engine)
            || !add_iid("SL_IID_OUTPUTMIX", InterfaceIdKind::OutputMix)
            || !add_iid("SL_IID_PLAY", InterfaceIdKind::Play)
            || !add_iid("SL_IID_BUFFERQUEUE", InterfaceIdKind::BufferQueue)
            || !add_iid("SL_IID_ANDROIDSIMPLEBUFFERQUEUE", InterfaceIdKind::AndroidSimpleBufferQueue)
            || !add_iid("SL_IID_VOLUME", InterfaceIdKind::Volume)
            || !add_iid("SL_IID_EFFECTSEND", InterfaceIdKind::EffectSend)
            || !add_iid("SL_IID_ANDROIDCONFIGURATION", InterfaceIdKind::AndroidConfiguration)
            || !add_iid("SL_IID_RECORD", InterfaceIdKind::Record)) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "guest memory could not stage OpenSL ES interface identifiers";
            return false;
        }

        const auto add = [this](std::string name, Callback callback) {
            return add_thunk(std::move(name), std::move(callback));
        };
        const auto unsupported_address = add("opensl.unsupported", [this](GuestCpuState32& state, GuestMemory&) {
            return unsupported(state);
        });
        const auto create_engine_address = add("slCreateEngine", [this](GuestCpuState32& state, GuestMemory&) {
            return create_engine(state);
        });
        const auto query_num_engine_interfaces_address = add(
            "slQueryNumSupportedEngineInterfaces", [this](GuestCpuState32& state, GuestMemory&) {
                return query_num_engine_interfaces(state);
            });
        const auto query_engine_interface_address = add(
            "slQuerySupportedEngineInterfaces", [this](GuestCpuState32& state, GuestMemory&) {
                return query_engine_interface(state);
            });
        if (!unsupported_address.has_value() || !create_engine_address.has_value()
            || !query_num_engine_interfaces_address.has_value() || !query_engine_interface_address.has_value()) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "unable to register OpenSL ES entrypoint thunks";
            return false;
        }

        const auto object_realize_address = add("opensl.object.realize", [this](GuestCpuState32& state, GuestMemory&) {
            return object_realize(state);
        });
        const auto object_resume_address = add("opensl.object.resume", [this](GuestCpuState32& state, GuestMemory&) {
            return object_resume(state);
        });
        const auto object_get_state_address = add("opensl.object.get_state", [this](GuestCpuState32& state, GuestMemory&) {
            return object_get_state(state);
        });
        const auto object_get_interface_address = add("opensl.object.get_interface", [this](GuestCpuState32& state, GuestMemory&) {
            return object_get_interface(state);
        });
        const auto object_register_callback_address = add("opensl.object.register_callback", [this](GuestCpuState32& state, GuestMemory&) {
            return object_register_callback(state);
        });
        const auto object_abort_address = add("opensl.object.abort_async", [this](GuestCpuState32& state, GuestMemory&) {
            return object_abort_async_operation(state);
        });
        const auto object_destroy_address = add("opensl.object.destroy", [this](GuestCpuState32& state, GuestMemory&) {
            return object_destroy(state);
        });
        const auto object_set_priority_address = add("opensl.object.set_priority", [this](GuestCpuState32& state, GuestMemory&) {
            return object_set_priority(state);
        });
        const auto object_get_priority_address = add("opensl.object.get_priority", [this](GuestCpuState32& state, GuestMemory&) {
            return object_get_priority(state);
        });
        const auto engine_create_output_mix_address = add("opensl.engine.create_output_mix", [this](GuestCpuState32& state, GuestMemory&) {
            return engine_create_output_mix(state);
        });
        const auto engine_create_audio_player_address = add("opensl.engine.create_audio_player", [this](GuestCpuState32& state, GuestMemory&) {
            return engine_create_audio_player(state);
        });
        const auto play_set_state_address = add("opensl.play.set_state", [this](GuestCpuState32& state, GuestMemory&) {
            return play_set_state(state);
        });
        const auto play_get_state_address = add("opensl.play.get_state", [this](GuestCpuState32& state, GuestMemory&) {
            return play_get_state(state);
        });
        const auto queue_enqueue_address = add("opensl.queue.enqueue", [this](GuestCpuState32& state, GuestMemory&) {
            return queue_enqueue(state);
        });
        const auto queue_clear_address = add("opensl.queue.clear", [this](GuestCpuState32& state, GuestMemory&) {
            return queue_clear(state);
        });
        const auto queue_get_state_address = add("opensl.queue.get_state", [this](GuestCpuState32& state, GuestMemory&) {
            return queue_get_state(state);
        });
        const auto queue_register_callback_address = add("opensl.queue.register_callback", [this](GuestCpuState32& state, GuestMemory&) {
            return queue_register_callback(state);
        });
        if (!object_realize_address.has_value() || !object_resume_address.has_value()
            || !object_get_state_address.has_value() || !object_get_interface_address.has_value()
            || !object_register_callback_address.has_value() || !object_abort_address.has_value()
            || !object_destroy_address.has_value() || !object_set_priority_address.has_value()
            || !object_get_priority_address.has_value() || !engine_create_output_mix_address.has_value()
            || !engine_create_audio_player_address.has_value() || !play_set_state_address.has_value()
            || !play_get_state_address.has_value() || !queue_enqueue_address.has_value()
            || !queue_clear_address.has_value() || !queue_get_state_address.has_value()
            || !queue_register_callback_address.has_value()) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "unable to register an OpenSL ES object/interface thunk";
            return false;
        }

        std::array<std::uint32_t, 10> object_entries{};
        object_entries.fill(*unsupported_address);
        object_entries[0] = *object_realize_address;          // Realize
        object_entries[1] = *object_resume_address;           // Resume
        object_entries[2] = *object_get_state_address;        // GetState
        object_entries[3] = *object_get_interface_address;    // GetInterface
        object_entries[4] = *object_register_callback_address; // RegisterCallback
        object_entries[5] = *object_abort_address;            // AbortAsyncOperation
        object_entries[6] = *object_destroy_address;          // Destroy
        object_entries[7] = *object_set_priority_address;     // SetPriority
        object_entries[8] = *object_get_priority_address;     // GetPriority

        std::array<std::uint32_t, 15> engine_entries{};
        engine_entries.fill(*unsupported_address);
        engine_entries[2] = *engine_create_audio_player_address; // CreateAudioPlayer
        engine_entries[7] = *engine_create_output_mix_address;   // CreateOutputMix

        std::array<std::uint32_t, 11> play_entries{};
        play_entries.fill(*unsupported_address);
        play_entries[0] = *play_set_state_address; // SetPlayState
        play_entries[1] = *play_get_state_address; // GetPlayState

        const std::array<std::uint32_t, 4> queue_entries{
            *queue_enqueue_address,
            *queue_clear_address,
            *queue_get_state_address,
            *queue_register_callback_address,
        };
        const auto object_vtable = make_vtable(object_entries);
        const auto engine_vtable = make_vtable(engine_entries);
        const auto play_vtable = make_vtable(play_entries);
        const auto queue_vtable = make_vtable(queue_entries);
        if (!object_vtable.has_value() || !engine_vtable.has_value()
            || !play_vtable.has_value() || !queue_vtable.has_value()) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "guest heap could not allocate OpenSL ES interface vtables";
            return false;
        }
        object_vtable_ = *object_vtable;
        engine_vtable_ = *engine_vtable;
        play_vtable_ = *play_vtable;
        queue_vtable_ = *queue_vtable;
        installed_ = true;
        if (diagnostic != nullptr) diagnostic->clear();
        return true;
    } catch (...) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "host allocation failed while installing OpenSL ES thunks";
        return false;
    }
}

void GuestOpenSlThunks::shutdown() noexcept {
    for (const auto address : trampoline_addresses_) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
    }
    trampoline_addresses_.clear();
    {
        std::lock_guard lock(state_mutex_);
        symbols_.clear();
        interface_ids_.clear();
        objects_.clear();
        object_handles_.clear();
        interface_handles_.clear();
        queued_bytes_total_ = 0;
        object_vtable_ = GuestAddress32{0};
        engine_vtable_ = GuestAddress32{0};
        play_vtable_ = GuestAddress32{0};
        queue_vtable_ = GuestAddress32{0};
        while (!guest_allocations_.empty()) {
            const auto address = guest_allocations_.back();
            guest_allocations_.pop_back();
            (void)heap_.free(address);
        }
    }
    next_object_token_ = 1;
    installed_ = false;
}

std::optional<std::uint32_t> GuestOpenSlThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) return std::nullopt;
    return found->second;
}

std::optional<GuestOpenSlPcmBuffer32> GuestOpenSlThunks::consume_next_playback_buffer(std::uint32_t player_object) {
    std::lock_guard lock(state_mutex_);
    auto* object = object_for_handle(player_object);
    if (object == nullptr || object->kind != ObjectKind::AudioPlayer || !object->realized
        || object->play_state != kPlayStatePlaying || object->buffers.empty()) {
        return std::nullopt;
    }
    GuestOpenSlPcmBuffer32 output;
    output.sample_rate_millihz = object->sample_rate_millihz;
    output.channels = object->channels;
    output.bits_per_sample = object->bits_per_sample;
    output.samples = std::move(object->buffers.front());
    object->buffers.pop_front();
    const auto bytes = output.samples.size();
    object->queued_bytes = bytes > object->queued_bytes ? 0 : object->queued_bytes - bytes;
    queued_bytes_total_ = bytes > queued_bytes_total_ ? 0 : queued_bytes_total_ - bytes;
    if (object->queue_index < std::numeric_limits<std::uint32_t>::max()) ++object->queue_index;
    return output;
}

std::optional<std::uint32_t> GuestOpenSlThunks::add_thunk(std::string name, Callback callback) {
    if (symbols_.contains(name) || next_trampoline_address_ > std::numeric_limits<std::uint32_t>::max() - 4U) {
        return std::nullopt;
    }
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) {
            return GuestHookResult{GuestHookAction::Fault, "OpenSL ES thunk received unrelated guest memory"};
        }
        try {
            return callback(state, memory);
        } catch (...) {
            return GuestHookResult{GuestHookAction::Fault, "OpenSL ES thunk failed while handling guest input"};
        }
    };
    if (!trampolines_.register_trampoline(name, GuestAddress32{address}, std::move(wrapped))) return std::nullopt;
    try {
        const auto [symbol, inserted] = symbols_.emplace(name, address);
        if (!inserted) {
            (void)trampolines_.unregister_trampoline(GuestAddress32{address});
            return std::nullopt;
        }
        try {
            trampoline_addresses_.push_back(address);
        } catch (...) {
            symbols_.erase(symbol);
            throw;
        }
    } catch (...) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<GuestAddress32> GuestOpenSlThunks::allocate_guest(std::size_t size) {
    if (size == 0 || guest_allocations_.size() >= kMaxGuestAllocations) return std::nullopt;
    const auto address = heap_.malloc(size);
    if (!address.has_value()) return std::nullopt;
    try {
        guest_allocations_.push_back(*address);
    } catch (...) {
        (void)heap_.free(*address);
        return std::nullopt;
    }
    return address;
}

void GuestOpenSlThunks::free_guest(GuestAddress32 address) noexcept {
    const auto found = std::find(guest_allocations_.begin(), guest_allocations_.end(), address);
    if (found == guest_allocations_.end()) return;
    (void)heap_.free(address);
    guest_allocations_.erase(found);
}

std::optional<GuestAddress32> GuestOpenSlThunks::make_vtable(std::span<const std::uint32_t> entries) {
    if (entries.empty() || entries.size() > 64U) return std::nullopt;
    const auto size = entries.size() * sizeof(std::uint32_t);
    const auto address = allocate_guest(size);
    if (!address.has_value()) return std::nullopt;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto field = address->checked_add(index * sizeof(std::uint32_t));
        if (!field.has_value() || !memory_.write_u32(*field, entries[index])) {
            free_guest(*address);
            return std::nullopt;
        }
    }
    return address;
}

bool GuestOpenSlThunks::write_interface_id(InterfaceIdKind kind, GuestAddress32& variable_address) {
    const auto found = interface_ids_.find(kind);
    if (found == interface_ids_.end()) return false;
    const auto guid = allocate_guest(16U);
    if (!guid.has_value()) return false;
    const auto variable = allocate_guest(sizeof(std::uint32_t));
    if (!variable.has_value()) {
        free_guest(*guid);
        return false;
    }
    const auto sequence_address = guid->checked_add(6U);
    const auto clock_address = guid->checked_add(8U);
    if (!sequence_address.has_value() || !clock_address.has_value()
        || !memory_.write_u32(*guid, found->second.time_low)
        || !memory_.write_u16(GuestAddress32{guid->value() + 4U}, found->second.time_mid)
        || !memory_.write_u16(GuestAddress32{guid->value() + 6U}, found->second.time_hi_and_version)
        || !memory_.write_u16(*clock_address, found->second.clock_sequence)) {
        free_guest(*variable);
        free_guest(*guid);
        return false;
    }
    std::array<std::byte, 6> node{};
    for (std::size_t index = 0; index < node.size(); ++index) {
        node[index] = static_cast<std::byte>(found->second.node[index]);
    }
    const auto node_address = clock_address->checked_add(sizeof(std::uint16_t));
    if (!node_address.has_value() || !memory_.write(*node_address, node)
        || !memory_.write_u32(*variable, guid->value())) {
        free_guest(*variable);
        free_guest(*guid);
        return false;
    }
    variable_address = *variable;
    return true;
}

bool GuestOpenSlThunks::read_interface_id(std::uint32_t address, InterfaceId& output) const noexcept {
    const auto clock_address = static_cast<std::uint64_t>(address) + 8U;
    if (clock_address + 8U - 1U > std::numeric_limits<std::uint32_t>::max()) return false;
    const auto time_low = memory_.read_u32(GuestAddress32{address});
    const auto time_mid = memory_.read_u16(GuestAddress32{address + 4U});
    const auto time_hi = memory_.read_u16(GuestAddress32{address + 6U});
    const auto sequence = memory_.read_u16(GuestAddress32{static_cast<std::uint32_t>(clock_address)});
    if (!time_low.has_value() || !time_mid.has_value() || !time_hi.has_value() || !sequence.has_value()) return false;
    InterfaceId id;
    id.time_low = *time_low;
    id.time_mid = *time_mid;
    id.time_hi_and_version = *time_hi;
    id.clock_sequence = *sequence;
    for (std::size_t index = 0; index < id.node.size(); ++index) {
        const auto byte = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(clock_address + 2U + index)});
        if (!byte.has_value()) return false;
        id.node[index] = *byte;
    }
    output = id;
    return true;
}

std::optional<GuestOpenSlThunks::InterfaceIdKind> GuestOpenSlThunks::classify_interface_id(const InterfaceId& id) const noexcept {
    if (id == kIidNull) return InterfaceIdKind::Null;
    if (id == kIidObject) return InterfaceIdKind::Object;
    if (id == kIidEngine) return InterfaceIdKind::Engine;
    if (id == kIidOutputMix) return InterfaceIdKind::OutputMix;
    if (id == kIidPlay) return InterfaceIdKind::Play;
    if (id == kIidBufferQueue || id == kIidBufferQueue11) return InterfaceIdKind::BufferQueue;
    if (id == kIidAndroidSimpleBufferQueue) return InterfaceIdKind::AndroidSimpleBufferQueue;
    if (id == kIidVolume) return InterfaceIdKind::Volume;
    if (id == kIidEffectSend) return InterfaceIdKind::EffectSend;
    if (id == kIidAndroidConfiguration) return InterfaceIdKind::AndroidConfiguration;
    if (id == kIidRecord) return InterfaceIdKind::Record;
    return std::nullopt;
}

bool GuestOpenSlThunks::read_requested_interfaces(
    const GuestCpuState32& state,
    std::uint32_t count,
    std::uint32_t ids_address,
    std::uint32_t required_address,
    RequestedInterfaces& output) const noexcept {
    (void)state;
    output.count = 0;
    if (count > kMaxInterfaceRequests) return false;
    if (count == 0) return true;
    const auto ids_bytes = static_cast<std::uint64_t>(count) * sizeof(std::uint32_t);
    if (ids_address == 0 || required_address == 0
        || !memory_.is_accessible(GuestAddress32{ids_address}, ids_bytes, GuestPermission::Read)
        || !memory_.is_accessible(GuestAddress32{required_address}, count, GuestPermission::Read)) {
        return false;
    }
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto id_address = static_cast<std::uint64_t>(ids_address) + index * sizeof(std::uint32_t);
        const auto required_field = static_cast<std::uint64_t>(required_address) + index;
        if (id_address > std::numeric_limits<std::uint32_t>::max()
            || required_field > std::numeric_limits<std::uint32_t>::max()) return false;
        const auto id_pointer = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(id_address)});
        const auto required = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(required_field)});
        if (!id_pointer.has_value() || !required.has_value() || *required > 1U) return false;
        InterfaceId id;
        if (!read_interface_id(*id_pointer, id)) return false;
        for (std::size_t prior = 0; prior < output.count; ++prior) {
            if (output.values[prior].id == id) return false;
        }
        output.values[output.count++] = RequestedInterface{id, *required};
    }
    return true;
}

bool GuestOpenSlThunks::requested_interface_is_supported(
    const RequestedInterfaces& interfaces,
    std::span<const InterfaceIdKind> supported) const noexcept {
    for (std::size_t index = 0; index < interfaces.count; ++index) {
        const auto& requested = interfaces.values[index];
        if (requested.required == 0) continue;
        const auto kind = classify_interface_id(requested.id);
        if (!kind.has_value() || std::find(supported.begin(), supported.end(), *kind) == supported.end()) return false;
    }
    return true;
}

bool GuestOpenSlThunks::stack_argument(
    const GuestCpuState32& state,
    std::size_t index,
    std::uint32_t& output) const noexcept {
    const auto address = static_cast<std::uint64_t>(state.r[13]) + index * sizeof(std::uint32_t);
    if (address > std::numeric_limits<std::uint32_t>::max()) return false;
    const auto value = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(address)});
    if (!value.has_value()) return false;
    output = *value;
    return true;
}

std::optional<std::uint32_t> GuestOpenSlThunks::create_object(
    ObjectKind kind,
    std::uint64_t engine_token,
    std::uint64_t output_mix_token,
    std::uint32_t max_queue_buffers,
    std::uint32_t sample_rate_millihz,
    std::uint32_t channels,
    std::uint32_t bits_per_sample) {
    if (!installed_ || objects_.size() >= kMaxObjects
        || next_object_token_ == 0 || next_object_token_ == std::numeric_limits<std::uint64_t>::max()) {
        return std::nullopt;
    }
    const auto original_allocation_count = guest_allocations_.size();
    const auto rollback_allocations = [this, original_allocation_count] {
        while (guest_allocations_.size() > original_allocation_count) {
            const auto address = guest_allocations_.back();
            guest_allocations_.pop_back();
            (void)heap_.free(address);
        }
    };
    const auto token = next_object_token_++;
    Object object;
    object.token = token;
    object.kind = kind;
    object.engine_token = kind == ObjectKind::Engine ? token : engine_token;
    object.output_mix_token = output_mix_token;
    object.max_queue_buffers = max_queue_buffers;
    object.sample_rate_millihz = sample_rate_millihz;
    object.channels = channels;
    object.bits_per_sample = bits_per_sample;

    const auto object_cell = allocate_guest(sizeof(std::uint32_t));
    if (!object_cell.has_value() || !memory_.write_u32(*object_cell, object_vtable_.value())) {
        rollback_allocations();
        return std::nullopt;
    }
    object.guest_handle = object_cell->value();
    if (kind == ObjectKind::Engine) {
        const auto cell = allocate_guest(sizeof(std::uint32_t));
        if (!cell.has_value() || !memory_.write_u32(*cell, engine_vtable_.value())) {
            rollback_allocations();
            return std::nullopt;
        }
        object.engine_interface = cell->value();
    } else if (kind == ObjectKind::AudioPlayer) {
        const auto play_cell = allocate_guest(sizeof(std::uint32_t));
        if (!play_cell.has_value() || !memory_.write_u32(*play_cell, play_vtable_.value())) {
            rollback_allocations();
            return std::nullopt;
        }
        object.play_interface = play_cell->value();
        if (max_queue_buffers != 0) {
            const auto queue_cell = allocate_guest(sizeof(std::uint32_t));
            if (!queue_cell.has_value() || !memory_.write_u32(*queue_cell, queue_vtable_.value())) {
                rollback_allocations();
                return std::nullopt;
            }
            object.buffer_queue_interface = queue_cell->value();
        }
    }

    try {
        const auto [object_entry, inserted] = objects_.emplace(token, std::move(object));
        (void)object_entry;
        if (!inserted) {
            rollback_allocations();
            return std::nullopt;
        }
        const auto& committed = objects_.at(token);
        const auto [object_alias, object_alias_inserted] = object_handles_.emplace(committed.guest_handle, token);
        (void)object_alias;
        if (!object_alias_inserted) {
            objects_.erase(token);
            rollback_allocations();
            return std::nullopt;
        }
        if (committed.engine_interface != 0) {
            const auto [alias, alias_inserted] = interface_handles_.emplace(
                committed.engine_interface, InterfaceRef{token, InterfaceKind::Engine});
            (void)alias;
            if (!alias_inserted) throw std::bad_alloc{};
        }
        if (committed.play_interface != 0) {
            const auto [alias, alias_inserted] = interface_handles_.emplace(
                committed.play_interface, InterfaceRef{token, InterfaceKind::Play});
            (void)alias;
            if (!alias_inserted) throw std::bad_alloc{};
        }
        if (committed.buffer_queue_interface != 0) {
            const auto [alias, alias_inserted] = interface_handles_.emplace(
                committed.buffer_queue_interface, InterfaceRef{token, InterfaceKind::BufferQueue});
            (void)alias;
            if (!alias_inserted) throw std::bad_alloc{};
        }
    } catch (...) {
        const auto found = objects_.find(token);
        if (found != objects_.end()) {
            object_handles_.erase(found->second.guest_handle);
            interface_handles_.erase(found->second.engine_interface);
            interface_handles_.erase(found->second.play_interface);
            interface_handles_.erase(found->second.buffer_queue_interface);
            objects_.erase(found);
        }
        rollback_allocations();
        return std::nullopt;
    }
    return objects_.at(token).guest_handle;
}

GuestOpenSlThunks::Object* GuestOpenSlThunks::object_for_handle(std::uint32_t handle) noexcept {
    const auto alias = object_handles_.find(handle);
    if (alias == object_handles_.end()) return nullptr;
    return object_for_token(alias->second);
}

const GuestOpenSlThunks::Object* GuestOpenSlThunks::object_for_handle(std::uint32_t handle) const noexcept {
    const auto alias = object_handles_.find(handle);
    if (alias == object_handles_.end()) return nullptr;
    const auto found = objects_.find(alias->second);
    return found == objects_.end() ? nullptr : &found->second;
}

GuestOpenSlThunks::Object* GuestOpenSlThunks::object_for_token(std::uint64_t token) noexcept {
    const auto found = objects_.find(token);
    return found == objects_.end() ? nullptr : &found->second;
}

GuestOpenSlThunks::InterfaceRef* GuestOpenSlThunks::interface_for_handle(std::uint32_t handle) noexcept {
    const auto found = interface_handles_.find(handle);
    return found == interface_handles_.end() ? nullptr : &found->second;
}

GuestHookResult GuestOpenSlThunks::unsupported(GuestCpuState32& state) {
    state.r[0] = kResultFeatureUnsupported;
    return {};
}

GuestHookResult GuestOpenSlThunks::create_engine(GuestCpuState32& state) {
    const auto output = state.r[0];
    const auto option_count = state.r[1];
    const auto option_array = state.r[2];
    const auto interface_count = state.r[3];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)
        || !memory_.write_u32(GuestAddress32{output}, 0U)) return {};
    if (option_count > kMaxEngineOptions) return {};
    if (option_count != 0) {
        const auto options_size = static_cast<std::uint64_t>(option_count) * 2U * sizeof(std::uint32_t);
        if (option_array == 0 || !memory_.is_accessible(GuestAddress32{option_array}, options_size, GuestPermission::Read)) return {};
        for (std::uint32_t index = 0; index < option_count; ++index) {
            const auto feature_address = static_cast<std::uint64_t>(option_array)
                + static_cast<std::uint64_t>(index) * 2U * sizeof(std::uint32_t);
            const auto data_address = feature_address + sizeof(std::uint32_t);
            const auto feature = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(feature_address)});
            const auto data = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(data_address)});
            if (!feature.has_value() || !data.has_value()) return {};
            if (*feature != kEngineOptionThreadSafe && *feature != kEngineOptionLossOfControl) return {};
            (void)data; // Android recognizes these options but ignores their values.
        }
    }
    std::uint32_t ids_address = 0;
    std::uint32_t required_address = 0;
    if (interface_count != 0
        && (!stack_argument(state, 0, ids_address) || !stack_argument(state, 1, required_address))) return {};
    RequestedInterfaces requested;
    if (!read_requested_interfaces(state, interface_count, ids_address, required_address, requested)) return {};
    constexpr std::array supported{
        InterfaceIdKind::Object, InterfaceIdKind::Engine,
    };
    if (!requested_interface_is_supported(requested, supported)) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    std::lock_guard lock(state_mutex_);
    const auto existing_engine = std::find_if(objects_.begin(), objects_.end(), [](const auto& entry) {
        return entry.second.kind == ObjectKind::Engine;
    });
    if (existing_engine != objects_.end()) {
        if (existing_engine->second.reference_count == std::numeric_limits<std::uint32_t>::max()) {
            state.r[0] = kResultResourceError;
            return {};
        }
        if (!memory_.write_u32(GuestAddress32{output}, existing_engine->second.guest_handle)) return {};
        ++existing_engine->second.reference_count;
        state.r[0] = kResultSuccess;
        return {};
    }
    const auto engine = create_object(ObjectKind::Engine, 0, 0, 0, 0, 0, 0);
    if (!engine.has_value()) {
        state.r[0] = kResultMemoryFailure;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, *engine)) {
        destroy_object(object_handles_.at(*engine));
        state.r[0] = kResultParameterInvalid;
        return {};
    }
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::query_num_engine_interfaces(GuestCpuState32& state) {
    const auto output = state.r[0];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)) return {};
    if (!memory_.write_u32(GuestAddress32{output}, 1U)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::query_engine_interface(GuestCpuState32& state) {
    const auto index = state.r[0];
    const auto output = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)) return {};
    if (!memory_.write_u32(GuestAddress32{output}, 0U)) return {};
    if (index != 0) return {};
    const auto symbol = symbols_.find("SL_IID_ENGINE");
    if (symbol == symbols_.end()) return {};
    const auto interface_id = memory_.read_u32(GuestAddress32{symbol->second});
    if (!interface_id.has_value() || !memory_.write_u32(GuestAddress32{output}, *interface_id)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_realize(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto async = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (async > 1U) return {};
    if (async != 0) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    std::lock_guard lock(state_mutex_);
    auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    if (object->kind != ObjectKind::Engine) {
        const auto* engine = object_for_token(object->engine_token);
        if (engine == nullptr || engine->kind != ObjectKind::Engine || !engine->realized) {
            state.r[0] = kResultPreconditionsViolated;
            return {};
        }
        if (object->kind == ObjectKind::AudioPlayer) {
            const auto* mix = object_for_token(object->output_mix_token);
            if (mix == nullptr || mix->kind != ObjectKind::OutputMix || !mix->realized) {
                state.r[0] = kResultPreconditionsViolated;
                return {};
            }
        }
    }
    object->realized = true;
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_resume(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto async = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (async > 1U) return {};
    if (async != 0) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    std::lock_guard lock(state_mutex_);
    const auto* object = object_for_handle(handle);
    state.r[0] = object != nullptr && object->realized ? kResultSuccess : kResultPreconditionsViolated;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_get_state(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto output = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)) return {};
    std::lock_guard lock(state_mutex_);
    const auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    const auto object_state = object->realized ? kObjectStateRealized : kObjectStateUnrealized;
    if (!memory_.write_u32(GuestAddress32{output}, object_state)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_get_interface(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto id_address = state.r[1];
    const auto output = state.r[2];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)
        || !memory_.write_u32(GuestAddress32{output}, 0U)) return {};
    InterfaceId id;
    if (!read_interface_id(id_address, id)) return {};
    std::lock_guard lock(state_mutex_);
    auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    if (!object->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    const auto kind = classify_interface_id(id);
    if (!kind.has_value()) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    std::uint32_t interface_handle = 0;
    switch (*kind) {
        case InterfaceIdKind::Object:
            interface_handle = object->guest_handle;
            break;
        case InterfaceIdKind::Engine:
            if (object->kind == ObjectKind::Engine) interface_handle = object->engine_interface;
            break;
        case InterfaceIdKind::Play:
            if (object->kind == ObjectKind::AudioPlayer) interface_handle = object->play_interface;
            break;
        case InterfaceIdKind::BufferQueue:
        case InterfaceIdKind::AndroidSimpleBufferQueue:
            if (object->kind == ObjectKind::AudioPlayer) interface_handle = object->buffer_queue_interface;
            break;
        default:
            break;
    }
    if (interface_handle == 0) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, interface_handle)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_register_callback(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto callback = state.r[1];
    state.r[0] = kResultParameterInvalid;
    std::lock_guard lock(state_mutex_);
    if (object_for_handle(handle) == nullptr) return {};
    state.r[0] = callback == 0 ? kResultSuccess : kResultFeatureUnsupported;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_abort_async_operation(GuestCpuState32& state) {
    (void)state;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_destroy(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto alias = object_handles_.find(handle);
    if (alias == object_handles_.end()) return {};
    auto* object = object_for_token(alias->second);
    if (object == nullptr) return {};
    if (object->kind == ObjectKind::Engine && object->reference_count > 1U) {
        --object->reference_count;
        return {};
    }
    destroy_object(alias->second);
    return {};
}

GuestHookResult GuestOpenSlThunks::object_set_priority(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto priority = std::bit_cast<std::int32_t>(state.r[1]);
    const auto preemptable = state.r[2];
    state.r[0] = kResultParameterInvalid;
    if (preemptable > 1U) return {};
    std::lock_guard lock(state_mutex_);
    auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    object->priority = priority;
    object->preemptable = preemptable != 0;
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::object_get_priority(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto priority_output = state.r[1];
    const auto preemptable_output = state.r[2];
    state.r[0] = kResultParameterInvalid;
    if (priority_output == 0 || preemptable_output == 0
        || !memory_.is_accessible(GuestAddress32{priority_output}, sizeof(std::uint32_t), GuestPermission::Write)
        || !memory_.is_accessible(GuestAddress32{preemptable_output}, sizeof(std::uint8_t), GuestPermission::Write)) return {};
    std::lock_guard lock(state_mutex_);
    const auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    const auto preemptable = std::array<std::byte, 1>{object->preemptable ? std::byte{1} : std::byte{0}};
    if (!memory_.write_u32(GuestAddress32{priority_output}, std::bit_cast<std::uint32_t>(object->priority))
        || !memory_.write(GuestAddress32{preemptable_output}, preemptable)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::engine_create_output_mix(GuestCpuState32& state) {
    const auto engine_interface = state.r[0];
    const auto output = state.r[1];
    const auto interface_count = state.r[2];
    const auto ids_address = state.r[3];
    std::uint32_t required_address = 0;
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)
        || !memory_.write_u32(GuestAddress32{output}, 0U)) return {};
    if (interface_count != 0 && !stack_argument(state, 0, required_address)) return {};
    RequestedInterfaces requested;
    if (!read_requested_interfaces(state, interface_count, ids_address, required_address, requested)) return {};
    constexpr std::array supported{InterfaceIdKind::Object};
    if (!requested_interface_is_supported(requested, supported)) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(engine_interface);
    if (interface == nullptr || interface->kind != InterfaceKind::Engine) return {};
    const auto* engine = object_for_token(interface->object_token);
    if (engine == nullptr || engine->kind != ObjectKind::Engine || !engine->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    const auto output_mix = create_object(ObjectKind::OutputMix, engine->token, 0, 0, 0, 0, 0);
    if (!output_mix.has_value()) {
        state.r[0] = kResultMemoryFailure;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, *output_mix)) {
        const auto alias = object_handles_.find(*output_mix);
        if (alias != object_handles_.end()) destroy_object(alias->second);
        state.r[0] = kResultParameterInvalid;
        return {};
    }
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::engine_create_audio_player(GuestCpuState32& state) {
    const auto engine_interface = state.r[0];
    const auto output = state.r[1];
    const auto source = state.r[2];
    const auto sink = state.r[3];
    std::uint32_t interface_count = 0;
    std::uint32_t ids_address = 0;
    std::uint32_t required_address = 0;
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)
        || !memory_.write_u32(GuestAddress32{output}, 0U)
        || !stack_argument(state, 0, interface_count)
        || !stack_argument(state, 1, ids_address)
        || !stack_argument(state, 2, required_address)) return {};
    RequestedInterfaces requested;
    if (!read_requested_interfaces(state, interface_count, ids_address, required_address, requested)) return {};
    constexpr std::array supported{
        InterfaceIdKind::Object, InterfaceIdKind::Play,
        InterfaceIdKind::BufferQueue, InterfaceIdKind::AndroidSimpleBufferQueue,
    };
    if (!requested_interface_is_supported(requested, supported)) {
        state.r[0] = kResultFeatureUnsupported;
        return {};
    }
    const bool queue_requested = std::any_of(
        requested.values.begin(), requested.values.begin() + static_cast<std::ptrdiff_t>(requested.count),
        [this](const RequestedInterface& entry) {
            const auto kind = classify_interface_id(entry.id);
            return kind.has_value() && (*kind == InterfaceIdKind::BufferQueue
                || *kind == InterfaceIdKind::AndroidSimpleBufferQueue);
        });
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(engine_interface);
    if (interface == nullptr || interface->kind != InterfaceKind::Engine) return {};
    const auto* engine = object_for_token(interface->object_token);
    if (engine == nullptr || engine->kind != ObjectKind::Engine || !engine->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    std::uint64_t output_mix_token = 0;
    std::uint32_t max_queue_buffers = 0;
    std::uint32_t sample_rate_millihz = 0;
    std::uint32_t channels = 0;
    std::uint32_t bits_per_sample = 0;
    const auto validation = validate_audio_player_source(
        source, sink, engine->token, output_mix_token, max_queue_buffers,
        sample_rate_millihz, channels, bits_per_sample);
    if (validation != kResultSuccess) {
        state.r[0] = validation;
        return {};
    }
    const auto player_queue_capacity = queue_requested ? max_queue_buffers : 0U;
    const auto player = create_object(
        ObjectKind::AudioPlayer, engine->token, output_mix_token, player_queue_capacity,
        sample_rate_millihz, channels, bits_per_sample);
    if (!player.has_value()) {
        state.r[0] = kResultMemoryFailure;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, *player)) {
        const auto alias = object_handles_.find(*player);
        if (alias != object_handles_.end()) destroy_object(alias->second);
        state.r[0] = kResultParameterInvalid;
        return {};
    }
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::play_set_state(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto play_state = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (play_state != kPlayStateStopped && play_state != kPlayStatePaused && play_state != kPlayStatePlaying) return {};
    std::lock_guard lock(state_mutex_);
    auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::Play) return {};
    auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    player->play_state = play_state;
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::play_get_state(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto output = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)) return {};
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::Play) return {};
    const auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, player->play_state)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::queue_enqueue(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto buffer_address = state.r[1];
    const auto size = state.r[2];
    state.r[0] = kResultParameterInvalid;
    if (buffer_address == 0 || size == 0 || size > kMaxPcmBufferBytes
        || !memory_.is_accessible(GuestAddress32{buffer_address}, size, GuestPermission::Read)) return {};
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::BufferQueue) return {};
    auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    if (player->buffers.size() >= player->max_queue_buffers
        || size > kMaxQueuedPcmBytes - queued_bytes_total_) {
        state.r[0] = kResultBufferInsufficient;
        return {};
    }
    const auto bytes_per_sample = player->bits_per_sample / 8U;
    const auto bytes_per_frame = static_cast<std::uint64_t>(bytes_per_sample) * player->channels;
    if (bytes_per_frame == 0 || size % bytes_per_frame != 0) return {};
    std::vector<std::byte> buffer;
    try {
        buffer.resize(size);
        if (!memory_.read(GuestAddress32{buffer_address}, buffer)) return {};
        player->buffers.push_back(std::move(buffer));
    } catch (const std::bad_alloc&) {
        state.r[0] = kResultMemoryFailure;
        return {};
    }
    player->queued_bytes += size;
    queued_bytes_total_ += size;
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::queue_clear(GuestCpuState32& state) {
    const auto handle = state.r[0];
    state.r[0] = kResultParameterInvalid;
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::BufferQueue) return {};
    auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    const auto cleared_bytes = player->queued_bytes;
    queued_bytes_total_ = cleared_bytes > queued_bytes_total_ ? 0 : queued_bytes_total_ - cleared_bytes;
    player->buffers.clear();
    player->queued_bytes = 0;
    player->queue_index = 0;
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::queue_get_state(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto output = state.r[1];
    state.r[0] = kResultParameterInvalid;
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, 2U * sizeof(std::uint32_t), GuestPermission::Write)) return {};
    const auto index_address = static_cast<std::uint64_t>(output) + sizeof(std::uint32_t);
    if (index_address > std::numeric_limits<std::uint32_t>::max()) return {};
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::BufferQueue) return {};
    const auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, static_cast<std::uint32_t>(player->buffers.size()))
        || !memory_.write_u32(GuestAddress32{static_cast<std::uint32_t>(index_address)}, player->queue_index)) return {};
    state.r[0] = kResultSuccess;
    return {};
}

GuestHookResult GuestOpenSlThunks::queue_register_callback(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto callback = state.r[1];
    state.r[0] = kResultParameterInvalid;
    std::lock_guard lock(state_mutex_);
    const auto* interface = interface_for_handle(handle);
    if (interface == nullptr || interface->kind != InterfaceKind::BufferQueue) return {};
    const auto* player = object_for_token(interface->object_token);
    if (player == nullptr || player->kind != ObjectKind::AudioPlayer) return {};
    if (!player->realized) {
        state.r[0] = kResultPreconditionsViolated;
        return {};
    }
    state.r[0] = callback == 0 ? kResultSuccess : kResultFeatureUnsupported;
    return {};
}

std::uint32_t GuestOpenSlThunks::validate_audio_player_source(
    std::uint32_t source_address,
    std::uint32_t sink_address,
    std::uint64_t engine_token,
    std::uint64_t& output_mix_token,
    std::uint32_t& max_queue_buffers,
    std::uint32_t& sample_rate_millihz,
    std::uint32_t& channels,
    std::uint32_t& bits_per_sample) const noexcept {
    if (source_address == 0 || sink_address == 0
        || !memory_.is_accessible(GuestAddress32{source_address}, 2U * sizeof(std::uint32_t), GuestPermission::Read)
        || !memory_.is_accessible(GuestAddress32{sink_address}, 2U * sizeof(std::uint32_t), GuestPermission::Read)) {
        return kResultParameterInvalid;
    }
    const auto locator_address = memory_.read_u32(GuestAddress32{source_address});
    const auto format_address = memory_.read_u32(GuestAddress32{source_address + 4U});
    const auto sink_locator_address = memory_.read_u32(GuestAddress32{sink_address});
    const auto sink_format = memory_.read_u32(GuestAddress32{sink_address + 4U});
    if (!locator_address.has_value() || !format_address.has_value()
        || !sink_locator_address.has_value() || !sink_format.has_value()
        || *locator_address == 0 || *format_address == 0 || *sink_locator_address == 0) {
        return kResultParameterInvalid;
    }
    if (!memory_.is_accessible(GuestAddress32{*locator_address}, 2U * sizeof(std::uint32_t), GuestPermission::Read)
        || !memory_.is_accessible(GuestAddress32{*format_address}, 7U * sizeof(std::uint32_t), GuestPermission::Read)
        || !memory_.is_accessible(GuestAddress32{*sink_locator_address}, 2U * sizeof(std::uint32_t), GuestPermission::Read)) {
        return kResultParameterInvalid;
    }
    const auto source_locator_type = memory_.read_u32(GuestAddress32{*locator_address});
    const auto queue_capacity = memory_.read_u32(GuestAddress32{*locator_address + 4U});
    const auto format_type = memory_.read_u32(GuestAddress32{*format_address});
    const auto requested_channels = memory_.read_u32(GuestAddress32{*format_address + 4U});
    const auto requested_rate = memory_.read_u32(GuestAddress32{*format_address + 8U});
    const auto requested_bits = memory_.read_u32(GuestAddress32{*format_address + 12U});
    const auto container_size = memory_.read_u32(GuestAddress32{*format_address + 16U});
    const auto channel_mask = memory_.read_u32(GuestAddress32{*format_address + 20U});
    const auto byte_order = memory_.read_u32(GuestAddress32{*format_address + 24U});
    const auto sink_locator_type = memory_.read_u32(GuestAddress32{*sink_locator_address});
    const auto output_mix_handle = memory_.read_u32(GuestAddress32{*sink_locator_address + 4U});
    if (!source_locator_type.has_value() || !queue_capacity.has_value() || !format_type.has_value()
        || !requested_channels.has_value() || !requested_rate.has_value() || !requested_bits.has_value()
        || !container_size.has_value() || !channel_mask.has_value() || !byte_order.has_value()
        || !sink_locator_type.has_value() || !output_mix_handle.has_value()) {
        return kResultParameterInvalid;
    }
    if (*sink_format != 0 || *source_locator_type != kDataLocatorAndroidSimpleBufferQueue
        || *sink_locator_type != kDataLocatorOutputMix || *format_type != kDataFormatPcm) {
        return kResultContentUnsupported;
    }
    if (*queue_capacity == 0 || *queue_capacity > kMaxQueueBuffers
        || (*requested_channels != 1U && *requested_channels != 2U)
        || *requested_rate < 8'000'000U || *requested_rate > 192'000'000U
        || (*requested_bits != kSampleFormatFixed8 && *requested_bits != kSampleFormatFixed16)
        || *container_size != *requested_bits || *byte_order != kByteOrderLittleEndian) {
        return kResultContentUnsupported;
    }
    const bool channel_mask_valid = *channel_mask == 0
        || (*requested_channels == 1U && *channel_mask == kSpeakerFrontCenter)
        || (*requested_channels == 2U && *channel_mask == (kSpeakerFrontLeft | kSpeakerFrontRight));
    if (!channel_mask_valid) return kResultContentUnsupported;
    const auto* mix = object_for_handle(*output_mix_handle);
    if (mix == nullptr || mix->kind != ObjectKind::OutputMix || mix->engine_token != engine_token) {
        return kResultParameterInvalid;
    }
    if (!mix->realized) return kResultPreconditionsViolated;
    output_mix_token = mix->token;
    max_queue_buffers = *queue_capacity;
    sample_rate_millihz = *requested_rate;
    channels = *requested_channels;
    bits_per_sample = *requested_bits;
    return kResultSuccess;
}

void GuestOpenSlThunks::destroy_object(std::uint64_t token) noexcept {
    auto found = objects_.find(token);
    if (found == objects_.end()) return;
    const auto kind = found->second.kind;
    if (kind == ObjectKind::Engine || kind == ObjectKind::OutputMix) {
        for (;;) {
            const auto child = std::find_if(objects_.begin(), objects_.end(), [token, kind](const auto& entry) {
                if (entry.first == token) return false;
                if (kind == ObjectKind::Engine) return entry.second.engine_token == token;
                return entry.second.output_mix_token == token;
            });
            if (child == objects_.end()) break;
            destroy_object(child->first);
        }
        found = objects_.find(token);
        if (found == objects_.end()) return;
    }
    const auto subtract = found->second.queued_bytes;
    queued_bytes_total_ = subtract > queued_bytes_total_ ? 0 : queued_bytes_total_ - subtract;
    const std::array<std::uint32_t, 4> guest_cells{
        found->second.guest_handle,
        found->second.engine_interface,
        found->second.play_interface,
        found->second.buffer_queue_interface,
    };
    object_handles_.erase(found->second.guest_handle);
    interface_handles_.erase(found->second.engine_interface);
    interface_handles_.erase(found->second.play_interface);
    interface_handles_.erase(found->second.buffer_queue_interface);
    for (const auto cell : guest_cells) {
        if (cell == 0) continue;
        (void)memory_.write_u32(GuestAddress32{cell}, 0U);
        free_guest(GuestAddress32{cell});
    }
    objects_.erase(found);
}

}  // namespace retrobridge::runtime
