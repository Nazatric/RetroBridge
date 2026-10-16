#include "retrobridge/guest_android_input_thunks.h"

#include <bit>
#include <cerrno>
#include <cmath>
#include <limits>
#include <new>
#include <utility>

namespace retrobridge::runtime {
namespace {
constexpr std::uint32_t kPollTimeout = static_cast<std::uint32_t>(-3);
constexpr std::uint32_t kPollWake = static_cast<std::uint32_t>(-1);
constexpr std::uint32_t kPollError = static_cast<std::uint32_t>(-4);
constexpr std::uint32_t kInputEventBytes = sizeof(std::uint32_t);
}

GuestAndroidInputThunks::GuestAndroidInputThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines)
    : memory_(memory), heap_(heap), trampolines_(trampolines) {}

GuestAndroidInputThunks::~GuestAndroidInputThunks() {
    shutdown();
}

bool GuestAndroidInputThunks::install(std::string* diagnostic) {
    if (diagnostic != nullptr) diagnostic->clear();
    if (installed_) return true;
    const auto add = [&](std::string name, Callback callback) {
        return add_thunk(std::move(name), std::move(callback)).has_value();
    };
    if (!add("AInputQueue_hasEvents", [this](GuestCpuState32& state, GuestMemory&) { return queue_has_events(state); })
        || !add("AInputQueue_getEvent", [this](GuestCpuState32& state, GuestMemory&) { return queue_get_event(state); })
        || !add("AInputQueue_preDispatchEvent", [this](GuestCpuState32& state, GuestMemory&) { return queue_pre_dispatch(state); })
        || !add("AInputQueue_finishEvent", [this](GuestCpuState32& state, GuestMemory&) { return queue_finish_event(state); })
        || !add("AInputEvent_getType", [this](GuestCpuState32& state, GuestMemory&) { return input_event_type(state); })
        || !add("AInputEvent_getDeviceId", [this](GuestCpuState32& state, GuestMemory&) { return input_event_device_id(state); })
        || !add("AInputEvent_getSource", [this](GuestCpuState32& state, GuestMemory&) { return input_event_source(state); })
        || !add("AKeyEvent_getAction", [this](GuestCpuState32& state, GuestMemory&) { return key_event_action(state); })
        || !add("AKeyEvent_getKeyCode", [this](GuestCpuState32& state, GuestMemory&) { return key_event_key_code(state); })
        || !add("AKeyEvent_getMetaState", [this](GuestCpuState32& state, GuestMemory&) { return key_event_meta_state(state); })
        || !add("AKeyEvent_getRepeatCount", [this](GuestCpuState32& state, GuestMemory&) { return key_event_repeat_count(state); })
        || !add("AKeyEvent_getDownTime", [this](GuestCpuState32& state, GuestMemory&) { return key_event_down_time(state); })
        || !add("AKeyEvent_getEventTime", [this](GuestCpuState32& state, GuestMemory&) { return key_event_event_time(state); })
        || !add("AMotionEvent_getAction", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_action(state); })
        || !add("AMotionEvent_getMetaState", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_meta_state(state); })
        || !add("AMotionEvent_getPointerCount", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_pointer_count(state); })
        || !add("AMotionEvent_getHistorySize", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_history_size(state); })
        || !add("AMotionEvent_getPointerId", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_pointer_id(state); })
        || !add("AMotionEvent_getX", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_x(state); })
        || !add("AMotionEvent_getY", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_y(state); })
        || !add("AMotionEvent_getPressure", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_pressure(state); })
        || !add("AMotionEvent_getEventTime", [this](GuestCpuState32& state, GuestMemory&) { return motion_event_event_time(state); })
        || !add("ALooper_prepare", [this](GuestCpuState32& state, GuestMemory&) { return looper_prepare(state); })
        || !add("ALooper_forThread", [this](GuestCpuState32& state, GuestMemory&) { return looper_for_thread(state); })
        || !add("ALooper_acquire", [this](GuestCpuState32& state, GuestMemory&) { return looper_acquire(state); })
        || !add("ALooper_release", [this](GuestCpuState32& state, GuestMemory&) { return looper_release(state); })
        || !add("ALooper_wake", [this](GuestCpuState32& state, GuestMemory&) { return looper_wake(state); })
        || !add("ALooper_pollOnce", [this](GuestCpuState32& state, GuestMemory&) { return looper_poll(state); })
        || !add("ALooper_pollAll", [this](GuestCpuState32& state, GuestMemory&) { return looper_poll(state); })
        || !add("ALooper_addFd", [this](GuestCpuState32& state, GuestMemory&) { return looper_add_fd(state); })
        || !add("ALooper_removeFd", [this](GuestCpuState32& state, GuestMemory&) { return looper_remove_fd(state); })) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "unable to register a synthetic Android input/looper thunk";
        return false;
    }
    installed_ = true;
    return true;
}

void GuestAndroidInputThunks::shutdown() noexcept {
    for (const auto address : trampoline_addresses_) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
    }
    trampoline_addresses_.clear();
    symbols_.clear();
    {
        std::lock_guard lock(state_mutex_);
        events_.clear();
        queue_.pending.clear();
        queue_.token = 0;
        queue_token_ = 0;
        queue_handle_ = 0;
        looper_handle_ = 0;
        looper_references_ = 1;
        looper_wake_pending_ = false;
        external_handles_.clear();
        for (const auto cell : handle_cells_) (void)heap_.free(cell);
        handle_cells_.clear();
    }
    handles_.clear(ReferenceKind::Global);
    installed_ = false;
}

std::optional<std::uint32_t> GuestAndroidInputThunks::create_input_queue(std::string* diagnostic) {
    const auto fail = [&](std::string message) -> std::optional<std::uint32_t> {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return std::nullopt;
    };
    if (!installed_) return fail("synthetic input thunks are not installed");
    std::lock_guard lock(state_mutex_);
    if (queue_handle_ != 0) {
        if (diagnostic != nullptr) diagnostic->clear();
        return queue_handle_;
    }
    if (next_object_token_ == 0 || next_object_token_ == std::numeric_limits<std::uint64_t>::max()) {
        return fail("input object token space is exhausted");
    }
    const auto token = next_object_token_++;
    const auto handle = allocate_handle_cell(token);
    if (!handle.has_value()) return fail("guest heap or handle table could not allocate the input queue");
    queue_token_ = token;
    queue_.token = token;
    queue_handle_ = *handle;
    if (diagnostic != nullptr) diagnostic->clear();
    return handle;
}

bool GuestAndroidInputThunks::enqueue_input_event(
    std::uint32_t queue,
    GuestInputEvent32 event,
    std::string* diagnostic) {
    const auto fail = [&](std::string message) {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return false;
    };
    if (!installed_) return fail("synthetic input thunks are not installed");
    if (!valid_event(event)) return fail("input event is malformed or exceeds the pointer limit");
    std::lock_guard lock(state_mutex_);
    auto* target = find_queue(queue);
    if (target == nullptr) return fail("input queue handle is invalid or stale");
    if (target->pending.size() >= kMaxPendingEvents) return fail("pending input event limit reached");
    try {
        target->pending.push_back(std::move(event));
    } catch (const std::bad_alloc&) {
        return fail("host allocation failed while queuing an input event");
    }
    if (diagnostic != nullptr) diagnostic->clear();
    return true;
}

std::optional<std::uint32_t> GuestAndroidInputThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) return std::nullopt;
    return found->second;
}

std::optional<std::uint32_t> GuestAndroidInputThunks::add_thunk(std::string name, Callback callback) {
    if (symbols_.contains(name) || next_trampoline_address_ > std::numeric_limits<std::uint32_t>::max() - 4U) {
        return std::nullopt;
    }
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) {
            return GuestHookResult{GuestHookAction::Fault, "Android input thunk received unrelated guest memory"};
        }
        try {
            return callback(state, memory);
        } catch (...) {
            return GuestHookResult{GuestHookAction::Fault, "Android input thunk failed while handling guest input"};
        }
    };
    if (!trampolines_.register_trampoline(name, GuestAddress32{address}, std::move(wrapped))) return std::nullopt;
    try {
        symbols_.emplace(std::move(name), address);
        trampoline_addresses_.push_back(address);
    } catch (...) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<std::uint32_t> GuestAndroidInputThunks::allocate_handle_cell(std::uint64_t token) {
    if (handle_cells_.size() >= kMaxHandleCells) return std::nullopt;
    const auto table_handle = handles_.insert(token, ReferenceKind::Global);
    if (!table_handle.has_value() || *table_handle == 0) return std::nullopt;
    const auto cell = heap_.malloc(2U * sizeof(std::uint32_t));
    if (!cell.has_value()) {
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    const auto table_field = cell->checked_add(sizeof(std::uint32_t));
    if (!table_field.has_value() || !memory_.write_u32(*cell, kHandleMagic)
        || !memory_.write_u32(*table_field, *table_handle)
    ) {
        (void)heap_.free(*cell);
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    try {
        const auto [alias, inserted] = external_handles_.emplace(cell->value(), *table_handle);
        (void)alias;
        if (!inserted) {
            (void)heap_.free(*cell);
            (void)handles_.release(*table_handle);
            return std::nullopt;
        }
        handle_cells_.push_back(*cell);
    } catch (...) {
        external_handles_.erase(cell->value());
        (void)heap_.free(*cell);
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    return cell->value();
}

std::optional<std::uint64_t> GuestAndroidInputThunks::resolve_object_token(std::uint32_t handle) const noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return std::nullopt;
    const auto kind = handles_.kind_of(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global) return std::nullopt;
    return handles_.resolve(alias->second);
}

GuestAndroidInputThunks::Queue* GuestAndroidInputThunks::find_queue(std::uint32_t handle) noexcept {
    const auto token = resolve_object_token(handle);
    return token.has_value() && *token == queue_token_ && queue_token_ != 0 ? &queue_ : nullptr;
}

const GuestAndroidInputThunks::Queue* GuestAndroidInputThunks::find_queue(std::uint32_t handle) const noexcept {
    const auto token = resolve_object_token(handle);
    return token.has_value() && *token == queue_token_ && queue_token_ != 0 ? &queue_ : nullptr;
}

GuestAndroidInputThunks::EventRecord* GuestAndroidInputThunks::find_event(std::uint32_t handle) noexcept {
    const auto token = resolve_object_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = events_.find(*token);
    return found == events_.end() ? nullptr : &found->second;
}

const GuestAndroidInputThunks::EventRecord* GuestAndroidInputThunks::find_event(std::uint32_t handle) const noexcept {
    const auto token = resolve_object_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = events_.find(*token);
    return found == events_.end() ? nullptr : &found->second;
}

bool GuestAndroidInputThunks::is_looper(std::uint32_t handle) const noexcept {
    const auto token = resolve_object_token(handle);
    return token.has_value() && *token == kLooperToken && looper_handle_ == handle;
}

void GuestAndroidInputThunks::invalidate_handle(std::uint32_t handle) noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return;
    (void)handles_.release(alias->second);
    external_handles_.erase(alias);
    (void)memory_.write_u32(GuestAddress32{handle}, 0U);
}

bool GuestAndroidInputThunks::valid_event(const GuestInputEvent32& event) const noexcept {
    if (event.down_time_ns < 0 || event.event_time_ns < 0 || event.event_time_ns < event.down_time_ns) return false;
    if (event.type == GuestInputEventType32::Key) {
        return event.repeat_count >= 0 && event.pointers.empty();
    }
    if (event.type != GuestInputEventType32::Motion || event.pointers.empty()
        || event.pointers.size() > kMaxMotionPointers) return false;
    for (const auto& pointer : event.pointers) {
        if (!std::isfinite(pointer.x) || !std::isfinite(pointer.y) || !std::isfinite(pointer.pressure)
            || pointer.pressure < 0.0F) return false;
    }
    return true;
}

GuestHookResult GuestAndroidInputThunks::queue_has_events(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto* queue = find_queue(handle);
    state.r[0] = queue != nullptr && !queue->pending.empty() ? 1U : 0U;
    return {};
}

GuestHookResult GuestAndroidInputThunks::queue_get_event(GuestCpuState32& state) {
    const auto queue_handle = state.r[0];
    const auto output = state.r[1];
    state.r[0] = static_cast<std::uint32_t>(-EINVAL);
    std::lock_guard lock(state_mutex_);
    auto* queue = find_queue(queue_handle);
    if (queue == nullptr) return {};
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, kInputEventBytes, GuestPermission::Write)) {
        state.r[0] = static_cast<std::uint32_t>(-EFAULT);
        return {};
    }
    if (queue->pending.empty()) {
        state.r[0] = static_cast<std::uint32_t>(-EAGAIN);
        return {};
    }
    if (next_object_token_ == 0 || next_object_token_ == std::numeric_limits<std::uint64_t>::max()) {
        state.r[0] = static_cast<std::uint32_t>(-ENOMEM);
        return {};
    }
    const auto token = next_object_token_++;
    const auto event_handle = allocate_handle_cell(token);
    if (!event_handle.has_value()) {
        state.r[0] = static_cast<std::uint32_t>(-ENOMEM);
        return {};
    }
    try {
        const auto [record, inserted] = events_.emplace(
            token, EventRecord{queue->token, queue->pending.front()});
        (void)record;
        if (!inserted) {
            invalidate_handle(*event_handle);
            state.r[0] = static_cast<std::uint32_t>(-ENOMEM);
            return {};
        }
    } catch (const std::bad_alloc&) {
        invalidate_handle(*event_handle);
        state.r[0] = static_cast<std::uint32_t>(-ENOMEM);
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, *event_handle)) {
        events_.erase(token);
        invalidate_handle(*event_handle);
        state.r[0] = static_cast<std::uint32_t>(-EFAULT);
        return {};
    }
    queue->pending.pop_front();
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestAndroidInputThunks::queue_pre_dispatch(GuestCpuState32& state) {
    state.r[0] = 0U; // No IME or framework pre-dispatch exists in this bridge.
    return {};
}

GuestHookResult GuestAndroidInputThunks::queue_finish_event(GuestCpuState32& state) {
    const auto queue_handle = state.r[0];
    const auto event_handle = state.r[1];
    std::lock_guard lock(state_mutex_);
    const auto* queue = find_queue(queue_handle);
    const auto* event = find_event(event_handle);
    if (queue == nullptr || event == nullptr || event->queue_token != queue->token) return {};
    const auto token = resolve_object_token(event_handle);
    if (token.has_value()) events_.erase(*token);
    invalidate_handle(event_handle);
    return {};
}

GuestHookResult GuestAndroidInputThunks::input_event_type(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    state.r[0] = event == nullptr ? 0U : static_cast<std::uint32_t>(event->event.type);
    return {};
}

GuestHookResult GuestAndroidInputThunks::input_event_device_id(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    state.r[0] = event == nullptr ? 0U : std::bit_cast<std::uint32_t>(event->event.device_id);
    return {};
}

GuestHookResult GuestAndroidInputThunks::input_event_source(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    state.r[0] = event == nullptr ? 0U : std::bit_cast<std::uint32_t>(event->event.source);
    return {};
}

GuestHookResult GuestAndroidInputThunks::event_int_field(
    GuestCpuState32& state,
    std::int32_t GuestInputEvent32::*field,
    bool key_only) {
    std::lock_guard lock(state_mutex_);
    const auto* record = find_event(state.r[0]);
    if (record == nullptr
        || (key_only && record->event.type != GuestInputEventType32::Key)
        || (!key_only && record->event.type != GuestInputEventType32::Motion)) {
        state.r[0] = 0;
    } else {
        state.r[0] = std::bit_cast<std::uint32_t>(record->event.*field);
    }
    return {};
}

GuestHookResult GuestAndroidInputThunks::event_time_field(
    GuestCpuState32& state,
    std::int64_t GuestInputEvent32::*field,
    bool key_only) {
    std::lock_guard lock(state_mutex_);
    const auto* record = find_event(state.r[0]);
    if (record == nullptr
        || (key_only && record->event.type != GuestInputEventType32::Key)
        || (!key_only && record->event.type != GuestInputEventType32::Motion)) {
        state.r[0] = 0;
        state.r[1] = 0;
        return {};
    }
    const auto value = std::bit_cast<std::uint64_t>(record->event.*field);
    state.r[0] = static_cast<std::uint32_t>(value);
    state.r[1] = static_cast<std::uint32_t>(value >> 32U);
    return {};
}

GuestHookResult GuestAndroidInputThunks::key_event_action(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::action, true);
}

GuestHookResult GuestAndroidInputThunks::key_event_key_code(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::key_code, true);
}

GuestHookResult GuestAndroidInputThunks::key_event_meta_state(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::meta_state, true);
}

GuestHookResult GuestAndroidInputThunks::key_event_repeat_count(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::repeat_count, true);
}

GuestHookResult GuestAndroidInputThunks::key_event_down_time(GuestCpuState32& state) {
    return event_time_field(state, &GuestInputEvent32::down_time_ns, true);
}

GuestHookResult GuestAndroidInputThunks::key_event_event_time(GuestCpuState32& state) {
    return event_time_field(state, &GuestInputEvent32::event_time_ns, true);
}

GuestHookResult GuestAndroidInputThunks::motion_event_action(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::action, false);
}

GuestHookResult GuestAndroidInputThunks::motion_event_meta_state(GuestCpuState32& state) {
    return event_int_field(state, &GuestInputEvent32::meta_state, false);
}

GuestHookResult GuestAndroidInputThunks::motion_event_pointer_count(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    state.r[0] = event != nullptr && event->event.type == GuestInputEventType32::Motion
        ? static_cast<std::uint32_t>(event->event.pointers.size()) : 0U;
    return {};
}

GuestHookResult GuestAndroidInputThunks::motion_event_history_size(GuestCpuState32& state) {
    state.r[0] = 0U; // Historical samples are not part of the bounded event record.
    return {};
}

GuestHookResult GuestAndroidInputThunks::motion_event_pointer_id(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    const auto pointer_index = static_cast<std::size_t>(state.r[1]);
    state.r[0] = event != nullptr && event->event.type == GuestInputEventType32::Motion
        && pointer_index < event->event.pointers.size()
        ? std::bit_cast<std::uint32_t>(event->event.pointers[pointer_index].id) : 0U;
    return {};
}

GuestHookResult GuestAndroidInputThunks::motion_float_field(
    GuestCpuState32& state,
    float GuestMotionPointer32::*field) {
    std::lock_guard lock(state_mutex_);
    const auto* event = find_event(state.r[0]);
    const auto pointer_index = static_cast<std::size_t>(state.r[1]);
    state.r[0] = event != nullptr && event->event.type == GuestInputEventType32::Motion
        && pointer_index < event->event.pointers.size()
        ? std::bit_cast<std::uint32_t>(event->event.pointers[pointer_index].*field) : 0U;
    return {};
}

GuestHookResult GuestAndroidInputThunks::motion_event_x(GuestCpuState32& state) {
    return motion_float_field(state, &GuestMotionPointer32::x);
}

GuestHookResult GuestAndroidInputThunks::motion_event_y(GuestCpuState32& state) {
    return motion_float_field(state, &GuestMotionPointer32::y);
}

GuestHookResult GuestAndroidInputThunks::motion_event_pressure(GuestCpuState32& state) {
    return motion_float_field(state, &GuestMotionPointer32::pressure);
}

GuestHookResult GuestAndroidInputThunks::motion_event_event_time(GuestCpuState32& state) {
    return event_time_field(state, &GuestInputEvent32::event_time_ns, false);
}

GuestHookResult GuestAndroidInputThunks::looper_prepare(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    if (!installed_) {
        state.r[0] = 0;
        return {};
    }
    if (looper_handle_ == 0) {
        const auto handle = allocate_handle_cell(kLooperToken);
        if (!handle.has_value()) {
            state.r[0] = 0;
            return {};
        }
        looper_handle_ = *handle;
        looper_references_ = 1;
        looper_wake_pending_ = false;
    }
    state.r[0] = looper_handle_;
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_for_thread(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    state.r[0] = looper_handle_;
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_acquire(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    if (is_looper(state.r[0]) && looper_references_ < std::numeric_limits<std::uint32_t>::max()) ++looper_references_;
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_release(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    if (is_looper(state.r[0]) && looper_references_ > 1) --looper_references_;
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_wake(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    if (is_looper(state.r[0])) looper_wake_pending_ = true;
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_poll(GuestCpuState32& state) {
    const auto timeout = std::bit_cast<std::int32_t>(state.r[0]);
    const auto out_fd = state.r[1];
    const auto out_events = state.r[2];
    const auto out_data = state.r[3];
    std::lock_guard lock(state_mutex_);
    if (looper_handle_ == 0 || timeout < -1
        || (out_fd != 0 && !memory_.is_accessible(GuestAddress32{out_fd}, sizeof(std::uint32_t), GuestPermission::Write))
        || (out_events != 0 && !memory_.is_accessible(GuestAddress32{out_events}, sizeof(std::uint32_t), GuestPermission::Write))
        || (out_data != 0 && !memory_.is_accessible(GuestAddress32{out_data}, sizeof(std::uint32_t), GuestPermission::Write))) {
        state.r[0] = kPollError;
        return {};
    }
    if ((out_fd != 0 && !memory_.write_u32(GuestAddress32{out_fd}, std::numeric_limits<std::uint32_t>::max()))
        || (out_events != 0 && !memory_.write_u32(GuestAddress32{out_events}, 0U))
        || (out_data != 0 && !memory_.write_u32(GuestAddress32{out_data}, 0U))) {
        state.r[0] = kPollError;
        return {};
    }
    if (looper_wake_pending_) {
        looper_wake_pending_ = false;
        state.r[0] = kPollWake;
    } else {
        state.r[0] = kPollTimeout;
    }
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_add_fd(GuestCpuState32& state) {
    state.r[0] = std::numeric_limits<std::uint32_t>::max();
    return {};
}

GuestHookResult GuestAndroidInputThunks::looper_remove_fd(GuestCpuState32& state) {
    (void)state;
    state.r[0] = 0U;
    return {};
}

}  // namespace retrobridge::runtime
