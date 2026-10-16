#include "retrobridge/handle_table.h"

#include <stdexcept>

namespace retrobridge::runtime {

HandleTable::HandleTable(std::size_t capacity) : slots_(capacity) {
    if (capacity == 0 || capacity > 0xffffU) {
        throw std::invalid_argument("HandleTable capacity must be between 1 and 65535");
    }
}

std::optional<GuestHandle32> HandleTable::insert(std::uint64_t host_reference_token, ReferenceKind kind) {
    if (host_reference_token == 0) return GuestHandle32{0};
    std::lock_guard lock(mutex_);
    for (std::size_t index = 0; index < slots_.size(); ++index) {
        auto& slot = slots_[index];
        if (slot.occupied) continue;
        slot.occupied = true;
        slot.host_reference_token = host_reference_token;
        slot.kind = kind;
        return encode(index, slot.generation);
    }
    return std::nullopt;
}

std::optional<std::uint64_t> HandleTable::resolve(GuestHandle32 guest_handle) const {
    if (guest_handle == 0) return std::uint64_t{0};
    std::lock_guard lock(mutex_);
    const auto* slot = find(guest_handle);
    if (slot == nullptr) return std::nullopt;
    return slot->host_reference_token;
}

std::optional<ReferenceKind> HandleTable::kind_of(GuestHandle32 guest_handle) const {
    if (guest_handle == 0) return std::nullopt;
    std::lock_guard lock(mutex_);
    const auto* slot = find(guest_handle);
    if (slot == nullptr) return std::nullopt;
    return slot->kind;
}

bool HandleTable::release(GuestHandle32 guest_handle) {
    if (guest_handle == 0) return false;
    std::lock_guard lock(mutex_);
    auto* slot = find(guest_handle);
    if (slot == nullptr) return false;
    retire(*slot);
    return true;
}

void HandleTable::clear(ReferenceKind kind) {
    std::lock_guard lock(mutex_);
    for (auto& slot : slots_) {
        if (slot.occupied && slot.kind == kind) retire(slot);
    }
}

std::size_t HandleTable::live_count() const {
    std::lock_guard lock(mutex_);
    std::size_t count = 0;
    for (const auto& slot : slots_) {
        if (slot.occupied) ++count;
    }
    return count;
}

GuestHandle32 HandleTable::encode(std::size_t index, std::uint16_t generation) noexcept {
    const auto slot = static_cast<std::uint32_t>(index + 1);
    return (static_cast<std::uint32_t>(generation) << 16) | slot;
}

const HandleTable::Slot* HandleTable::find(GuestHandle32 guest_handle) const noexcept {
    const auto slot_number = guest_handle & 0xffffU;
    const auto generation = static_cast<std::uint16_t>(guest_handle >> 16);
    if (slot_number == 0 || generation == 0) return nullptr;
    const auto index = static_cast<std::size_t>(slot_number - 1);
    if (index >= slots_.size()) return nullptr;
    const auto& slot = slots_[index];
    if (!slot.occupied || slot.generation != generation) return nullptr;
    return &slot;
}

HandleTable::Slot* HandleTable::find(GuestHandle32 guest_handle) noexcept {
    const auto slot_number = guest_handle & 0xffffU;
    const auto generation = static_cast<std::uint16_t>(guest_handle >> 16);
    if (slot_number == 0 || generation == 0) return nullptr;
    const auto index = static_cast<std::size_t>(slot_number - 1);
    if (index >= slots_.size()) return nullptr;
    auto& slot = slots_[index];
    if (!slot.occupied || slot.generation != generation) return nullptr;
    return &slot;
}

void HandleTable::retire(Slot& slot) noexcept {
    slot.occupied = false;
    slot.host_reference_token = 0;
    slot.generation = static_cast<std::uint16_t>(slot.generation + 1);
    if (slot.generation == 0) slot.generation = 1;
}

}  // namespace retrobridge::runtime
