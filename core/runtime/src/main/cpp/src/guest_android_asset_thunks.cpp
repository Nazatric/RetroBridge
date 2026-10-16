#include "retrobridge/guest_android_asset_thunks.h"

#include <algorithm>
#include <bit>
#include <limits>
#include <new>
#include <utility>

namespace retrobridge::runtime {

GuestAndroidAssetThunks::GuestAndroidAssetThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines)
    : memory_(memory), heap_(heap), trampolines_(trampolines) {}

GuestAndroidAssetThunks::~GuestAndroidAssetThunks() {
    shutdown();
}

bool GuestAndroidAssetThunks::register_asset(
    std::string name,
    std::span<const std::byte> contents,
    std::string* diagnostic) {
    const auto fail = [&](std::string message) {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return false;
    };
    if (installed_) return fail("asset catalog is immutable after thunk installation");
    if (!valid_asset_name(name)) return fail("asset name must be a normalized relative path without traversal");
    if (contents.size() > kMaxAssetBytes) return fail("asset exceeds the per-asset byte limit");
    std::lock_guard lock(state_mutex_);
    if (catalog_.size() >= kMaxAssetCount) return fail("asset catalog exceeds the entry limit");
    if (catalog_.contains(name)) return fail("asset name is already registered");
    if (contents.size() > kMaxCatalogBytes - catalog_bytes_) return fail("asset catalog exceeds the total byte limit");
    try {
        std::vector<std::byte> copy(contents.size());
        if (!contents.empty()) std::copy(contents.begin(), contents.end(), copy.begin());
        catalog_.emplace(std::move(name), std::move(copy));
    } catch (const std::bad_alloc&) {
        return fail("host memory allocation failed while registering the asset");
    }
    catalog_bytes_ += contents.size();
    if (diagnostic != nullptr) diagnostic->clear();
    return true;
}

bool GuestAndroidAssetThunks::install(std::string* diagnostic) {
    if (diagnostic != nullptr) diagnostic->clear();
    const auto fail = [&](std::string message) {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return false;
    };
    if (installed_) return true;

    const auto manager = handles_.insert(kAssetManagerToken, ReferenceKind::Global);
    if (!manager.has_value() || *manager == 0) return fail("unable to allocate the synthetic AAssetManager handle");
    const auto manager_cell = allocate_handle_cell(*manager);
    if (!manager_cell.has_value()) {
        (void)handles_.release(*manager);
        return fail("unable to allocate the guest AAssetManager object");
    }
    asset_manager_handle_ = manager_cell->value();
    const auto add = [&](std::string name, Callback callback) {
        if (add_thunk(std::move(name), std::move(callback)).has_value()) return true;
        if (diagnostic != nullptr && diagnostic->empty()) *diagnostic = "unable to register an NDK asset thunk";
        return false;
    };
    if (!add("AAssetManager_open", [this](GuestCpuState32& state, GuestMemory&) { return open_asset(state); })
        || !add("AAsset_read", [this](GuestCpuState32& state, GuestMemory&) { return read_asset(state); })
        || !add("AAsset_getBuffer", [this](GuestCpuState32& state, GuestMemory&) { return asset_buffer(state); })
        || !add("AAsset_seek", [this](GuestCpuState32& state, GuestMemory&) { return seek_asset(state, false); })
        || !add("AAsset_seek64", [this](GuestCpuState32& state, GuestMemory&) { return seek_asset(state, true); })
        || !add("AAsset_getLength", [this](GuestCpuState32& state, GuestMemory&) { return asset_length(state, false, false); })
        || !add("AAsset_getLength64", [this](GuestCpuState32& state, GuestMemory&) { return asset_length(state, false, true); })
        || !add("AAsset_getRemainingLength", [this](GuestCpuState32& state, GuestMemory&) { return asset_length(state, true, false); })
        || !add("AAsset_getRemainingLength64", [this](GuestCpuState32& state, GuestMemory&) { return asset_length(state, true, true); })
        || !add("AAsset_close", [this](GuestCpuState32& state, GuestMemory&) { return close_asset(state); })) {
        shutdown();
        if (diagnostic != nullptr && diagnostic->empty()) *diagnostic = "NDK asset thunk installation failed";
        return false;
    }
    installed_ = true;
    if (diagnostic != nullptr) diagnostic->clear();
    return true;
}

void GuestAndroidAssetThunks::shutdown() noexcept {
    for (const auto address : trampoline_addresses_) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
    }
    trampoline_addresses_.clear();
    symbols_.clear();
    {
        std::lock_guard lock(state_mutex_);
        for (const auto& [token, asset] : open_assets_) {
            (void)token;
            if (asset.materialized_buffer.value() != 0) (void)heap_.free(asset.materialized_buffer);
        }
        open_assets_.clear();
        external_handles_.clear();
        for (const auto cell : handle_cells_) (void)heap_.free(cell);
        handle_cells_.clear();
    }
    handles_.clear(ReferenceKind::Global);
    asset_manager_handle_ = 0;
    installed_ = false;
}

std::optional<std::uint32_t> GuestAndroidAssetThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) return std::nullopt;
    return found->second;
}

std::optional<std::uint32_t> GuestAndroidAssetThunks::add_thunk(std::string name, Callback callback) {
    if (symbols_.contains(name) || next_trampoline_address_ > std::numeric_limits<std::uint32_t>::max() - 4U) {
        return std::nullopt;
    }
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) {
            return GuestHookResult{GuestHookAction::Fault, "NDK asset thunk received unrelated guest memory"};
        }
        try {
            return callback(state, memory);
        } catch (...) {
            return GuestHookResult{GuestHookAction::Fault, "NDK asset thunk failed while handling guest input"};
        }
    };
    std::string diagnostic;
    if (!trampolines_.register_trampoline(name, GuestAddress32{address}, std::move(wrapped), &diagnostic)) {
        return std::nullopt;
    }
    symbols_.emplace(std::move(name), address);
    trampoline_addresses_.push_back(address);
    return address;
}

std::optional<GuestAddress32> GuestAndroidAssetThunks::allocate_handle_cell(std::uint32_t table_handle) {
    if (table_handle == 0 || handle_cells_.size() >= kMaxAssetHandleCells) return std::nullopt;
    const auto cell = heap_.malloc(2U * sizeof(std::uint32_t));
    if (!cell.has_value()) return std::nullopt;
    const auto table_field = cell->checked_add(sizeof(std::uint32_t));
    if (!table_field.has_value() || !memory_.write_u32(*cell, kHandleMagic)
        || !memory_.write_u32(*table_field, table_handle)
    ) {
        (void)heap_.free(*cell);
        return std::nullopt;
    }
    try {
        const auto [alias, inserted] = external_handles_.emplace(cell->value(), table_handle);
        (void)alias;
        if (!inserted) {
            (void)heap_.free(*cell);
            return std::nullopt;
        }
        handle_cells_.push_back(*cell);
    } catch (...) {
        external_handles_.erase(cell->value());
        (void)heap_.free(*cell);
        return std::nullopt;
    }
    return cell;
}

std::optional<std::string> GuestAndroidAssetThunks::read_c_string(
    std::uint32_t address,
    std::size_t maximum) const {
    std::string result;
    result.reserve(std::min<std::size_t>(maximum, 256));
    for (std::size_t index = 0; index < maximum; ++index) {
        const auto current = static_cast<std::uint64_t>(address) + index;
        if (current > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        const auto value = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(current)});
        if (!value.has_value()) return std::nullopt;
        if (*value == 0) return result;
        result.push_back(static_cast<char>(*value));
    }
    return std::nullopt;
}

std::optional<std::uint32_t> GuestAndroidAssetThunks::stack_argument(
    const GuestCpuState32& state,
    std::size_t index) const noexcept {
    const auto address = static_cast<std::uint64_t>(state.r[13]) + index * sizeof(std::uint32_t);
    if (address > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(address)});
}

GuestAndroidAssetThunks::OpenAsset* GuestAndroidAssetThunks::find_asset(std::uint32_t handle) noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return nullptr;
    const auto kind = handles_.kind_of(alias->second);
    const auto token = handles_.resolve(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global || !token.has_value() || *token == kAssetManagerToken) {
        return nullptr;
    }
    const auto found = open_assets_.find(*token);
    return found == open_assets_.end() ? nullptr : &found->second;
}

const GuestAndroidAssetThunks::OpenAsset* GuestAndroidAssetThunks::find_asset(std::uint32_t handle) const noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return nullptr;
    const auto kind = handles_.kind_of(alias->second);
    const auto token = handles_.resolve(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global || !token.has_value() || *token == kAssetManagerToken) {
        return nullptr;
    }
    const auto found = open_assets_.find(*token);
    return found == open_assets_.end() ? nullptr : &found->second;
}

GuestHookResult GuestAndroidAssetThunks::open_asset(GuestCpuState32& state) {
    const auto manager = state.r[0];
    const auto name_address = state.r[1];
    const auto mode = state.r[2];
    state.r[0] = 0;
    if (!installed_ || manager != asset_manager_handle_ || mode > 3U) return {};
    const auto name = read_c_string(name_address, 4096);
    if (!name.has_value() || !valid_asset_name(*name)) return {};
    const auto found = catalog_.find(*name);
    if (found == catalog_.end() || next_asset_token_ == 0
        || next_asset_token_ == std::numeric_limits<std::uint64_t>::max()
    ) {
        return {};
    }

    std::lock_guard lock(state_mutex_);
    const auto token = next_asset_token_++;
    const auto table_handle = handles_.insert(token, ReferenceKind::Global);
    if (!table_handle.has_value() || *table_handle == 0) return {};
    const auto guest_cell = allocate_handle_cell(*table_handle);
    if (!guest_cell.has_value()) {
        (void)handles_.release(*table_handle);
        return {};
    }
    try {
        const auto [asset, inserted] = open_assets_.emplace(token, OpenAsset{token, &found->second, 0});
        if (!inserted) {
            external_handles_.erase(guest_cell->value());
            (void)handles_.release(*table_handle);
            return {};
        }
        (void)asset;
    } catch (...) {
        external_handles_.erase(guest_cell->value());
        (void)handles_.release(*table_handle);
        return {};
    }
    state.r[0] = guest_cell->value();
    return {};
}

GuestHookResult GuestAndroidAssetThunks::read_asset(GuestCpuState32& state) {
    const auto handle = state.r[0];
    const auto destination = state.r[1];
    const auto requested = std::min<std::size_t>(state.r[2], kMaxReadBytes);
    std::lock_guard lock(state_mutex_);
    auto* asset = find_asset(handle);
    if (asset == nullptr || asset->contents == nullptr) {
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        return {};
    }
    const auto remaining = asset->contents->size() - asset->position;
    const auto amount = std::min(requested, remaining);
    if (amount > 0) {
        const auto bytes = std::span<const std::byte>(*asset->contents).subspan(asset->position, amount);
        if (!memory_.write(GuestAddress32{destination}, bytes)) {
            state.r[0] = std::numeric_limits<std::uint32_t>::max();
            return {};
        }
        asset->position += amount;
    }
    state.r[0] = static_cast<std::uint32_t>(amount);
    return {};
}

GuestHookResult GuestAndroidAssetThunks::asset_buffer(GuestCpuState32& state) {
    const auto handle = state.r[0];
    state.r[0] = 0;
    std::lock_guard lock(state_mutex_);
    auto* asset = find_asset(handle);
    if (asset == nullptr || asset->contents == nullptr || asset->contents->empty()) return {};
    if (asset->materialized_buffer.value() == 0) {
        const auto buffer = heap_.malloc(asset->contents->size());
        if (!buffer.has_value()) return {};
        const std::span<const std::byte> contents{asset->contents->data(), asset->contents->size()};
        if (!memory_.write(*buffer, contents)) {
            (void)heap_.free(*buffer);
            return {};
        }
        asset->materialized_buffer = *buffer;
    }
    state.r[0] = asset->materialized_buffer.value();
    return {};
}

GuestHookResult GuestAndroidAssetThunks::seek_asset(GuestCpuState32& state, bool wide) {
    const auto handle = state.r[0];
    std::int64_t offset = 0;
    std::uint32_t whence = 0;
    if (wide) {
        const auto whence_argument = stack_argument(state, 0);
        if (!whence_argument.has_value()) {
            state.r[0] = std::numeric_limits<std::uint32_t>::max();
            state.r[1] = std::numeric_limits<std::uint32_t>::max();
            return {};
        }
        const auto bits = static_cast<std::uint64_t>(state.r[2])
            | (static_cast<std::uint64_t>(state.r[3]) << 32U);
        offset = std::bit_cast<std::int64_t>(bits);
        whence = *whence_argument;
    } else {
        offset = std::bit_cast<std::int32_t>(state.r[1]);
        whence = state.r[2];
    }

    std::lock_guard lock(state_mutex_);
    auto* asset = find_asset(handle);
    if (asset == nullptr || asset->contents == nullptr || whence > 2U) {
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        if (wide) state.r[1] = std::numeric_limits<std::uint32_t>::max();
        return {};
    }
    const auto length = static_cast<std::int64_t>(asset->contents->size());
    const std::int64_t base = whence == 0U ? 0 : (whence == 1U
        ? static_cast<std::int64_t>(asset->position) : length);
    if (offset < -base || offset > length - base) {
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        if (wide) state.r[1] = std::numeric_limits<std::uint32_t>::max();
        return {};
    }
    const auto target = base + offset;
    if (target < 0 || target > length) {
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        if (wide) state.r[1] = std::numeric_limits<std::uint32_t>::max();
        return {};
    }
    asset->position = static_cast<std::size_t>(target);
    state.r[0] = static_cast<std::uint32_t>(target);
    if (wide) state.r[1] = static_cast<std::uint32_t>(static_cast<std::uint64_t>(target) >> 32U);
    return {};
}

GuestHookResult GuestAndroidAssetThunks::asset_length(GuestCpuState32& state, bool remaining, bool wide) {
    const auto handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto* asset = find_asset(handle);
    std::uint64_t length = 0;
    if (asset != nullptr && asset->contents != nullptr) {
        length = remaining ? asset->contents->size() - asset->position : asset->contents->size();
    }
    state.r[0] = static_cast<std::uint32_t>(length);
    if (wide) state.r[1] = static_cast<std::uint32_t>(length >> 32U);
    return {};
}

GuestHookResult GuestAndroidAssetThunks::close_asset(GuestCpuState32& state) {
    const auto guest_handle = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto alias = external_handles_.find(guest_handle);
    if (alias == external_handles_.end()) return {};
    const auto table_handle = alias->second;
    const auto kind = handles_.kind_of(table_handle);
    const auto token = handles_.resolve(table_handle);
    if (kind.has_value() && *kind == ReferenceKind::Global && token.has_value()
        && *token != kAssetManagerToken
    ) {
        const auto asset = open_assets_.find(*token);
        if (asset != open_assets_.end()) {
            if (asset->second.materialized_buffer.value() != 0) {
                (void)heap_.free(asset->second.materialized_buffer);
            }
            open_assets_.erase(asset);
            (void)handles_.release(table_handle);
            (void)memory_.write_u32(GuestAddress32{guest_handle}, 0U);
            external_handles_.erase(alias);
        }
    }
    return {};
}

bool GuestAndroidAssetThunks::valid_asset_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 4096 || name.front() == '/' || name.find('\\') != std::string_view::npos
        || name.find('\0') != std::string_view::npos
    ) {
        return false;
    }
    std::size_t segment_length = 0;
    std::size_t segment_start = 0;
    for (std::size_t index = 0; index <= name.size(); ++index) {
        if (index < name.size() && name[index] != '/') {
            ++segment_length;
            if (segment_length > 256) return false;
            continue;
        }
        if (segment_length == 0) return false;
        const auto segment = name.substr(segment_start, segment_length);
        if (segment == "." || segment == "..") return false;
        segment_start = index + 1;
        segment_length = 0;
    }
    return true;
}

}  // namespace retrobridge::runtime
