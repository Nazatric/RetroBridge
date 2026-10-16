#include "retrobridge/guest_android_window_thunks.h"

#include <bit>
#include <cerrno>
#include <iterator>
#include <limits>
#include <new>
#include <utility>

namespace retrobridge::runtime {
namespace {
constexpr std::uint32_t kNativeWindowBufferBytes = 24;
constexpr std::uint32_t kNativeRectBytes = 16;
constexpr std::uint32_t kNativeWindowStrideOffset = 8;
}

GuestAndroidWindowThunks::GuestAndroidWindowThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines)
    : memory_(memory), heap_(heap), trampolines_(trampolines) {}

GuestAndroidWindowThunks::~GuestAndroidWindowThunks() {
    shutdown();
}

bool GuestAndroidWindowThunks::install(std::string* diagnostic) {
    if (diagnostic != nullptr) diagnostic->clear();
    if (installed_) return true;
    const auto add = [&](std::string name, Callback callback) {
        return add_thunk(std::move(name), std::move(callback)).has_value();
    };
    if (!add("ANativeWindow_acquire", [this](GuestCpuState32& state, GuestMemory&) { return acquire(state); })
        || !add("ANativeWindow_release", [this](GuestCpuState32& state, GuestMemory&) { return release(state); })
        || !add("ANativeWindow_getWidth", [this](GuestCpuState32& state, GuestMemory&) { return get_width(state); })
        || !add("ANativeWindow_getHeight", [this](GuestCpuState32& state, GuestMemory&) { return get_height(state); })
        || !add("ANativeWindow_getFormat", [this](GuestCpuState32& state, GuestMemory&) { return get_format(state); })
        || !add("ANativeWindow_setBuffersGeometry", [this](GuestCpuState32& state, GuestMemory&) { return set_geometry(state); })
        || !add("ANativeWindow_lock", [this](GuestCpuState32& state, GuestMemory&) { return lock_window(state); })
        || !add("ANativeWindow_unlockAndPost", [this](GuestCpuState32& state, GuestMemory&) { return unlock_and_post(state); })) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "unable to register a headless ANativeWindow thunk";
        return false;
    }
    installed_ = true;
    return true;
}

void GuestAndroidWindowThunks::shutdown() noexcept {
    for (const auto address : trampoline_addresses_) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
    }
    trampoline_addresses_.clear();
    symbols_.clear();
    {
        std::lock_guard lock(state_mutex_);
        for (const auto& [token, window] : windows_) {
            (void)token;
            const auto bytes = buffer_size(window.width, window.height);
            if (window.pixels.value() != 0 && bytes.has_value()) free_surface_buffer(window.pixels, *bytes);
        }
        windows_.clear();
        external_handles_.clear();
        surface_ranges_.clear();
        surface_bytes_ = 0;
        for (const auto cell : handle_cells_) (void)heap_.free(cell);
        handle_cells_.clear();
    }
    handles_.clear(ReferenceKind::Global);
    installed_ = false;
}

std::optional<std::uint32_t> GuestAndroidWindowThunks::create_headless_window(
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t format,
    std::string* diagnostic) {
    const auto fail = [&](std::string message) -> std::optional<std::uint32_t> {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return std::nullopt;
    };
    if (!installed_) return fail("headless native-window thunks are not installed");
    const auto bytes = buffer_size(width, height);
    if (!bytes.has_value() || format != kRgba8888) {
        return fail("headless surface dimensions or pixel format are unsupported");
    }
    std::lock_guard lock(state_mutex_);
    if (windows_.size() >= kMaxWindows) return fail("headless window count limit reached");
    if (*bytes > kMaxSurfaceBytesTotal - surface_bytes_) return fail("headless surface byte quota is exhausted");
    if (next_window_token_ == 0 || next_window_token_ == std::numeric_limits<std::uint64_t>::max()) {
        return fail("headless window token space is exhausted");
    }
    const auto token = next_window_token_++;
    const auto guest_handle = allocate_window_handle(token);
    if (!guest_handle.has_value()) return fail("guest heap or handle table could not allocate a native-window handle");
    const auto pixels = allocate_surface_buffer(*bytes);
    if (!pixels.has_value()) {
        const auto alias = external_handles_.find(*guest_handle);
        if (alias != external_handles_.end()) {
            (void)handles_.release(alias->second);
            external_handles_.erase(alias);
        }
        (void)memory_.write_u32(GuestAddress32{*guest_handle}, 0U);
        return fail("guest address space could not map the headless pixel buffer");
    }
    try {
        const auto [window, inserted] = windows_.emplace(
            token, Window{token, width, height, format, 1, *pixels, false, 0});
        (void)window;
        if (!inserted) {
            free_surface_buffer(*pixels, *bytes);
            const auto alias = external_handles_.find(*guest_handle);
            if (alias != external_handles_.end()) {
                (void)handles_.release(alias->second);
                external_handles_.erase(alias);
            }
            (void)memory_.write_u32(GuestAddress32{*guest_handle}, 0U);
            return fail("duplicate headless window token");
        }
    } catch (...) {
        free_surface_buffer(*pixels, *bytes);
        const auto alias = external_handles_.find(*guest_handle);
        if (alias != external_handles_.end()) {
            (void)handles_.release(alias->second);
            external_handles_.erase(alias);
        }
        (void)memory_.write_u32(GuestAddress32{*guest_handle}, 0U);
        return fail("host allocation failed while creating a headless window");
    }
    if (diagnostic != nullptr) diagnostic->clear();
    return guest_handle;
}

std::optional<std::uint32_t> GuestAndroidWindowThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) return std::nullopt;
    return found->second;
}

std::optional<GuestAddress32> GuestAndroidWindowThunks::pixel_buffer(std::uint32_t window) const noexcept {
    std::lock_guard lock(state_mutex_);
    const auto* found = find_window(window);
    return found == nullptr ? std::nullopt : std::optional<GuestAddress32>{found->pixels};
}

std::optional<std::uint64_t> GuestAndroidWindowThunks::posted_frame_count(std::uint32_t window) const noexcept {
    std::lock_guard lock(state_mutex_);
    const auto* found = find_window(window);
    return found == nullptr ? std::nullopt : std::optional<std::uint64_t>{found->posted_frames};
}

std::optional<HeadlessNativeWindowSnapshot32> GuestAndroidWindowThunks::snapshot_window(std::uint32_t window) const noexcept {
    std::lock_guard lock(state_mutex_);
    const auto* found = find_window(window);
    if (found == nullptr) return std::nullopt;
    return HeadlessNativeWindowSnapshot32{found->width, found->height, found->format, found->pixels, found->locked};
}

bool GuestAndroidWindowThunks::retain_headless_window(std::uint32_t window) noexcept {
    std::lock_guard lock(state_mutex_);
    auto* found = find_window(window);
    if (found == nullptr || found->references == std::numeric_limits<std::uint32_t>::max()) return false;
    ++found->references;
    return true;
}

void GuestAndroidWindowThunks::release_headless_window(std::uint32_t window) noexcept {
    GuestCpuState32 state{};
    state.r[0] = window;
    (void)release(state);
}

bool GuestAndroidWindowThunks::post_headless_frame(std::uint32_t window) noexcept {
    std::lock_guard lock(state_mutex_);
    auto* found = find_window(window);
    if (found == nullptr || found->locked) return false;
    if (found->posted_frames < std::numeric_limits<std::uint64_t>::max()) ++found->posted_frames;
    return true;
}

std::optional<std::uint32_t> GuestAndroidWindowThunks::add_thunk(std::string name, Callback callback) {
    if (symbols_.contains(name) || next_trampoline_address_ > std::numeric_limits<std::uint32_t>::max() - 4U) {
        return std::nullopt;
    }
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) {
            return GuestHookResult{GuestHookAction::Fault, "native-window thunk received unrelated guest memory"};
        }
        try {
            return callback(state, memory);
        } catch (...) {
            return GuestHookResult{GuestHookAction::Fault, "native-window thunk failed while handling guest input"};
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

std::optional<std::uint32_t> GuestAndroidWindowThunks::allocate_window_handle(std::uint64_t token) {
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

GuestAndroidWindowThunks::Window* GuestAndroidWindowThunks::find_window(std::uint32_t handle) noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return nullptr;
    const auto kind = handles_.kind_of(alias->second);
    const auto token = handles_.resolve(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global || !token.has_value()) return nullptr;
    const auto found = windows_.find(*token);
    return found == windows_.end() ? nullptr : &found->second;
}

const GuestAndroidWindowThunks::Window* GuestAndroidWindowThunks::find_window(std::uint32_t handle) const noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return nullptr;
    const auto kind = handles_.kind_of(alias->second);
    const auto token = handles_.resolve(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global || !token.has_value()) return nullptr;
    const auto found = windows_.find(*token);
    return found == windows_.end() ? nullptr : &found->second;
}

std::optional<std::size_t> GuestAndroidWindowThunks::buffer_size(
    std::uint32_t width,
    std::uint32_t height) const noexcept {
    if (width == 0 || height == 0 || width > kMaxSurfaceDimension || height > kMaxSurfaceDimension) return std::nullopt;
    const auto pixels = static_cast<std::uint64_t>(width) * height;
    if (pixels > kMaxSurfacePixels || pixels > std::numeric_limits<std::size_t>::max() / 4U) return std::nullopt;
    return static_cast<std::size_t>(pixels * 4U);
}

std::optional<GuestAddress32> GuestAndroidWindowThunks::allocate_surface_buffer(std::size_t bytes) {
    constexpr std::uint64_t page_bytes = kSurfacePageBytes;
    if (bytes == 0 || bytes > kMaxSurfaceBytesTotal
        || memory_.mapped_bytes() > memory_.byte_limit()
        || bytes > memory_.byte_limit() - memory_.mapped_bytes()) {
        return std::nullopt;
    }
    const auto extent = (static_cast<std::uint64_t>(bytes) + page_bytes - 1U) & ~(page_bytes - 1U);
    std::uint64_t candidate = kSurfaceVirtualStart;
    const auto end = static_cast<std::uint64_t>(kSurfaceVirtualEnd);
    for (std::size_t probe = 0; probe < kMaxSurfacePlacementProbes && candidate + extent <= end; ++probe) {
        auto next = surface_ranges_.lower_bound(static_cast<std::uint32_t>(candidate));
        if (next != surface_ranges_.begin()) {
            const auto previous = std::prev(next);
            const auto previous_end = static_cast<std::uint64_t>(previous->first) + previous->second;
            if (candidate < previous_end) {
                candidate = previous_end;
                continue;
            }
        }
        next = surface_ranges_.lower_bound(static_cast<std::uint32_t>(candidate));
        if (next != surface_ranges_.end() && candidate + extent > next->first) {
            candidate = static_cast<std::uint64_t>(next->first) + next->second;
            continue;
        }
        const GuestAddress32 address{static_cast<std::uint32_t>(candidate)};
        if (memory_.map_zeroed(address, bytes, GuestPermission::Read | GuestPermission::Write)) {
            try {
                const auto [range, inserted] = surface_ranges_.emplace(address.value(), static_cast<std::size_t>(extent));
                (void)range;
                if (!inserted) {
                    (void)memory_.unmap(address);
                    return std::nullopt;
                }
            } catch (...) {
                (void)memory_.unmap(address);
                return std::nullopt;
            }
            surface_bytes_ += bytes;
            return address;
        }
        candidate += page_bytes;
    }
    return std::nullopt;
}

void GuestAndroidWindowThunks::free_surface_buffer(GuestAddress32 address, std::size_t bytes) noexcept {
    const auto range = surface_ranges_.find(address.value());
    if (range == surface_ranges_.end() || !memory_.unmap(address)) return;
    surface_ranges_.erase(range);
    surface_bytes_ = bytes > surface_bytes_ ? 0 : surface_bytes_ - bytes;
}

bool GuestAndroidWindowThunks::configure_window(
    Window& window,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t format) {
    if (window.locked || format != kRgba8888) return false;
    const auto bytes = buffer_size(width, height);
    const auto old_bytes = buffer_size(window.width, window.height);
    if (!bytes.has_value() || !old_bytes.has_value() || *old_bytes > surface_bytes_) return false;
    if (width == window.width && height == window.height && format == window.format) return true;
    const auto retained_bytes = surface_bytes_ - *old_bytes;
    if (*bytes > kMaxSurfaceBytesTotal - retained_bytes) return false;
    if (*bytes != *old_bytes) {
        const auto pixels = allocate_surface_buffer(*bytes);
        if (!pixels.has_value()) return false;
        free_surface_buffer(window.pixels, *old_bytes);
        window.pixels = *pixels;
    }
    window.width = width;
    window.height = height;
    window.format = format;
    return true;
}

GuestHookResult GuestAndroidWindowThunks::acquire(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    auto* window = find_window(handle);
    if (window != nullptr && window->references < std::numeric_limits<std::uint32_t>::max()) ++window->references;
    return {};
}

GuestHookResult GuestAndroidWindowThunks::release(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return {};
    const auto table_handle = alias->second;
    const auto token = handles_.resolve(table_handle);
    if (!token.has_value()) return {};
    const auto found = windows_.find(*token);
    if (found == windows_.end()) return {};
    if (found->second.references > 1) {
        --found->second.references;
        return {};
    }
    if (found->second.locked) return {};
    const auto bytes = buffer_size(found->second.width, found->second.height);
    if (found->second.pixels.value() != 0 && bytes.has_value()) free_surface_buffer(found->second.pixels, *bytes);
    windows_.erase(found);
    (void)handles_.release(table_handle);
    (void)memory_.write_u32(GuestAddress32{handle}, 0U);
    external_handles_.erase(alias);
    return {};
}

GuestHookResult GuestAndroidWindowThunks::get_width(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto* window = find_window(handle);
    state.r[0] = window == nullptr ? 0U : window->width;
    return {};
}

GuestHookResult GuestAndroidWindowThunks::get_height(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto* window = find_window(handle);
    state.r[0] = window == nullptr ? 0U : window->height;
    return {};
}

GuestHookResult GuestAndroidWindowThunks::get_format(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto* window = find_window(handle);
    state.r[0] = window == nullptr ? 0U : window->format;
    return {};
}

GuestHookResult GuestAndroidWindowThunks::set_geometry(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto requested_width = std::bit_cast<std::int32_t>(state.r[1]);
    const auto requested_height = std::bit_cast<std::int32_t>(state.r[2]);
    const auto requested_format = state.r[3];
    std::lock_guard lock(state_mutex_);
    auto* window = find_window(handle);
    if (window == nullptr) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    if (requested_width < 0 || requested_height < 0) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    const auto width = requested_width == 0 ? window->width : static_cast<std::uint32_t>(requested_width);
    const auto height = requested_height == 0 ? window->height : static_cast<std::uint32_t>(requested_height);
    const auto format = requested_format == 0 ? window->format : requested_format;
    if (!buffer_size(width, height).has_value() || format != kRgba8888) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    if (window->locked) {
        state.r[0] = static_cast<std::uint32_t>(-EBUSY);
        return {};
    }
    if (!configure_window(*window, width, height, format)) {
        state.r[0] = static_cast<std::uint32_t>(-ENOMEM);
        return {};
    }
    state.r[0] = 0;
    return {};
}

bool GuestAndroidWindowThunks::write_buffer_descriptor(std::uint32_t address, const Window& window) {
    if (!memory_.is_accessible(GuestAddress32{address}, kNativeWindowBufferBytes, GuestPermission::Write)) return false;
    return memory_.write_u32(GuestAddress32{address}, window.width)
        && memory_.write_u32(GuestAddress32{address + 4U}, window.height)
        && memory_.write_u32(GuestAddress32{address + kNativeWindowStrideOffset}, window.width)
        && memory_.write_u32(GuestAddress32{address + 12U}, window.format)
        && memory_.write_u32(GuestAddress32{address + 16U}, window.pixels.value())
        && memory_.write_u32(GuestAddress32{address + 20U}, 0U);
}

bool GuestAndroidWindowThunks::write_dirty_rect(std::uint32_t address, const Window& window) {
    if (address == 0) return true;
    if (!memory_.is_accessible(GuestAddress32{address}, kNativeRectBytes, GuestPermission::Write)) return false;
    return memory_.write_u32(GuestAddress32{address}, 0U)
        && memory_.write_u32(GuestAddress32{address + 4U}, 0U)
        && memory_.write_u32(GuestAddress32{address + 8U}, window.width)
        && memory_.write_u32(GuestAddress32{address + 12U}, window.height);
}

GuestHookResult GuestAndroidWindowThunks::lock_window(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto buffer_out = state.r[1];
    const auto dirty_bounds = state.r[2];
    std::lock_guard lock(state_mutex_);
    auto* window = find_window(handle);
    if (window == nullptr) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    if (window->locked) {
        state.r[0] = static_cast<std::uint32_t>(-EBUSY);
        return {};
    }
    if (buffer_out == 0
        || !memory_.is_accessible(GuestAddress32{buffer_out}, kNativeWindowBufferBytes, GuestPermission::Write)
        || (dirty_bounds != 0 && !memory_.is_accessible(GuestAddress32{dirty_bounds}, kNativeRectBytes, GuestPermission::Write))
    ) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    if (!write_buffer_descriptor(buffer_out, *window) || !write_dirty_rect(dirty_bounds, *window)) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    window->locked = true;
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestAndroidWindowThunks::unlock_and_post(GuestCpuState32& state) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    auto* window = find_window(handle);
    if (window == nullptr) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    if (!window->locked) {
        state.r[0] = static_cast<std::uint32_t>(-EINVAL);
        return {};
    }
    window->locked = false;
    if (window->posted_frames < std::numeric_limits<std::uint64_t>::max()) ++window->posted_frames;
    state.r[0] = 0;
    return {};
}

}  // namespace retrobridge::runtime
