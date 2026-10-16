#include "retrobridge/guest_heap.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <new>

namespace retrobridge::runtime {
namespace {

constexpr std::size_t kGuestAlignment = 8;
constexpr std::size_t kZeroChunkSize = 4096;

[[nodiscard]] bool round_up(std::size_t value, std::size_t alignment, std::size_t& result) noexcept {
    if (alignment == 0 || value > std::numeric_limits<std::size_t>::max() - (alignment - 1U)) return false;
    result = (value + alignment - 1U) & ~(alignment - 1U);
    return true;
}

}  // namespace

GuestHeap32::GuestHeap32(GuestMemory& memory) noexcept : memory_(memory) {}

GuestHeap32::~GuestHeap32() {
    shutdown();
}

bool GuestHeap32::initialize(GuestAddress32 base, std::size_t size, std::string* diagnostic) {
    std::lock_guard lock(mutex_);
    const auto fail = [&](const char* message) {
        if (diagnostic != nullptr) *diagnostic = message;
        return false;
    };
    if (initialized_) return fail("guest heap is already initialized");
    if ((base.value() % kGuestAlignment) != 0 || size < kGuestAlignment) {
        return fail("guest heap base must be 8-byte aligned and size must be at least 8 bytes");
    }
    size &= ~(kGuestAlignment - 1U);
    if (size == 0 || !GuestRange32::create(base, size).has_value()) {
        return fail("guest heap range is empty or exceeds the 32-bit address space");
    }
    if (!memory_.map_zeroed(base, size, GuestPermission::Read | GuestPermission::Write, diagnostic)) return false;
    try {
        free_blocks_.emplace(0, size);
    } catch (...) {
        (void)memory_.unmap(base);
        return fail("host metadata allocation failed while initializing guest heap");
    }
    base_ = base;
    size_ = size;
    initialized_ = true;
    return true;
}

void GuestHeap32::shutdown() noexcept {
    std::lock_guard lock(mutex_);
    if (initialized_) (void)memory_.unmap(base_);
    free_blocks_.clear();
    allocations_.clear();
    base_ = GuestAddress32{0};
    size_ = 0;
    initialized_ = false;
}

std::optional<GuestAddress32> GuestHeap32::malloc(std::size_t size) noexcept {
    std::lock_guard lock(mutex_);
    try {
        return allocate_locked(size, kGuestAlignment, false);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<GuestAddress32> GuestHeap32::calloc(std::size_t count, std::size_t size) noexcept {
    if (count != 0 && size > std::numeric_limits<std::size_t>::max() / count) return std::nullopt;
    std::lock_guard lock(mutex_);
    try {
        return allocate_locked(count * size, kGuestAlignment, true);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<GuestAddress32> GuestHeap32::realloc(GuestAddress32 address, std::size_t size) noexcept {
    if (address.value() == 0) return malloc(size);
    if (size == 0) {
        (void)free(address);
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);
    try {
        const auto old = allocations_.find(address.value());
        if (old == allocations_.end()) return std::nullopt;
        if (size <= old->second) return address;

        const auto replacement = allocate_locked(size, kGuestAlignment, false);
        if (!replacement.has_value()) return std::nullopt;
        std::array<std::byte, kZeroChunkSize> buffer{};
        std::size_t offset = 0;
        while (offset < old->second) {
            const auto count = std::min(buffer.size(), old->second - offset);
            const auto source = GuestAddress32{address.value() + static_cast<std::uint32_t>(offset)};
            const auto destination = GuestAddress32{replacement->value() + static_cast<std::uint32_t>(offset)};
            const auto bytes = std::span<std::byte>{buffer.data(), count};
            if (!memory_.read(source, bytes) || !memory_.write(destination, bytes)) {
                (void)free_locked(*replacement);
                return std::nullopt;
            }
            offset += count;
        }
        if (!free_locked(address)) {
            (void)free_locked(*replacement);
            return std::nullopt;
        }
        return replacement;
    } catch (...) {
        return std::nullopt;
    }
}

bool GuestHeap32::free(GuestAddress32 address) noexcept {
    if (address.value() == 0) return true;
    std::lock_guard lock(mutex_);
    try {
        return free_locked(address);
    } catch (...) {
        return false;
    }
}

std::optional<GuestAddress32> GuestHeap32::memalign(std::size_t alignment, std::size_t size) noexcept {
    if (!valid_alignment(alignment)) return std::nullopt;
    std::lock_guard lock(mutex_);
    try {
        return allocate_locked(size, std::max(alignment, kGuestAlignment), false);
    } catch (...) {
        return std::nullopt;
    }
}

int GuestHeap32::posix_memalign(
    GuestAddress32* output,
    std::size_t alignment,
    std::size_t size) noexcept {
    if (output == nullptr || alignment % sizeof(std::uint32_t) != 0 || !valid_alignment(alignment)) return 22;
    const auto result = memalign(alignment, size);
    if (!result.has_value()) return 12;
    *output = *result;
    return 0;
}

std::optional<std::size_t> GuestHeap32::allocation_size(GuestAddress32 address) const noexcept {
    std::lock_guard lock(mutex_);
    const auto found = allocations_.find(address.value());
    if (found == allocations_.end()) return std::nullopt;
    return found->second;
}

bool GuestHeap32::initialized() const noexcept {
    std::lock_guard lock(mutex_);
    return initialized_;
}

GuestAddress32 GuestHeap32::base() const noexcept {
    std::lock_guard lock(mutex_);
    return base_;
}

std::size_t GuestHeap32::capacity() const noexcept {
    std::lock_guard lock(mutex_);
    return size_;
}

std::optional<GuestAddress32> GuestHeap32::allocate_locked(
    std::size_t size,
    std::size_t alignment,
    bool clear) {
    if (!initialized_ || !valid_alignment(alignment)) return std::nullopt;
    size = std::max<std::size_t>(size, kGuestAlignment);
    std::size_t rounded_size = 0;
    if (!round_up(size, kGuestAlignment, rounded_size) || rounded_size > size_) return std::nullopt;

    for (auto block = free_blocks_.begin(); block != free_blocks_.end(); ++block) {
        const auto block_offset = block->first;
        const auto block_size = block->second;
        const auto current = static_cast<std::uint64_t>(base_.value()) + block_offset;
        const auto align = static_cast<std::uint64_t>(alignment);
        if (current > std::numeric_limits<std::uint64_t>::max() - (align - 1U)) continue;
        const auto aligned = (current + align - 1U) & ~(align - 1U);
        if (aligned >= (std::uint64_t{1} << 32U)) continue;
        const auto allocation_offset = static_cast<std::size_t>(aligned - base_.value());
        const auto prefix = allocation_offset - block_offset;
        if (prefix > block_size || rounded_size > block_size - prefix) continue;
        const auto consumed = prefix + rounded_size;
        const auto suffix = block_size - consumed;

        const auto address = GuestAddress32{static_cast<std::uint32_t>(aligned)};
        if (allocations_.contains(address.value())) return std::nullopt;
        free_blocks_.erase(block);
        if (prefix != 0) free_blocks_.emplace(block_offset, prefix);
        if (suffix != 0) free_blocks_.emplace(allocation_offset + rounded_size, suffix);
        if (clear && !clear_range(address, rounded_size)) {
            if (prefix != 0) free_blocks_.erase(block_offset);
            if (suffix != 0) free_blocks_.erase(allocation_offset + rounded_size);
            free_blocks_.emplace(block_offset, block_size);
            return std::nullopt;
        }
        try {
            allocations_.emplace(address.value(), rounded_size);
        } catch (...) {
            if (prefix != 0) free_blocks_.erase(block_offset);
            if (suffix != 0) free_blocks_.erase(allocation_offset + rounded_size);
            free_blocks_.emplace(block_offset, block_size);
            return std::nullopt;
        }
        return address;
    }
    return std::nullopt;
}

bool GuestHeap32::free_locked(GuestAddress32 address) {
    const auto allocation = allocations_.find(address.value());
    if (allocation == allocations_.end() || address.value() < base_.value()) return false;
    const auto offset = static_cast<std::size_t>(address.value() - base_.value());
    const auto size = allocation->second;
    auto block = free_blocks_.emplace(offset, size).first;
    allocations_.erase(allocation);

    if (block != free_blocks_.begin()) {
        auto previous = std::prev(block);
        if (previous->first + previous->second == block->first) {
            previous->second += block->second;
            free_blocks_.erase(block);
            block = previous;
        }
    }
    auto next = std::next(block);
    if (next != free_blocks_.end() && block->first + block->second == next->first) {
        block->second += next->second;
        free_blocks_.erase(next);
    }
    return true;
}

bool GuestHeap32::clear_range(GuestAddress32 address, std::size_t size) noexcept {
    std::array<std::byte, kZeroChunkSize> zeros{};
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = std::min(zeros.size(), size - offset);
        const auto current = GuestAddress32{address.value() + static_cast<std::uint32_t>(offset)};
        if (!memory_.write(current, std::span<const std::byte>{zeros.data(), count})) return false;
        offset += count;
    }
    return true;
}

bool GuestHeap32::valid_alignment(std::size_t alignment) noexcept {
    return alignment >= sizeof(std::uint32_t) && (alignment & (alignment - 1U)) == 0;
}

}  // namespace retrobridge::runtime
