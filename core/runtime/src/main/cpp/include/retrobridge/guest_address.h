#pragma once

#include <cstdint>
#include <limits>
#include <optional>

namespace retrobridge::runtime {

/** A guest virtual address is always a 32-bit value, never a host pointer. */
class GuestAddress32 final {
public:
    explicit constexpr GuestAddress32(std::uint32_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }

    [[nodiscard]] constexpr std::optional<GuestAddress32> checked_add(std::uint32_t amount) const noexcept {
        const auto sum = static_cast<std::uint64_t>(value_) + amount;
        if (sum > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        return GuestAddress32(static_cast<std::uint32_t>(sum));
    }

    friend constexpr bool operator==(GuestAddress32, GuestAddress32) noexcept = default;

private:
    std::uint32_t value_;
};

/** Half-open guest range. The exclusive end may equal 2^32. */
class GuestRange32 final {
public:
    [[nodiscard]] static constexpr std::optional<GuestRange32> create(
        GuestAddress32 base,
        std::uint64_t size) noexcept {
        constexpr std::uint64_t guest_space_size = std::uint64_t{1} << 32;
        const auto end = static_cast<std::uint64_t>(base.value()) + size;
        if (end > guest_space_size) return std::nullopt;
        return GuestRange32(base, size);
    }

    [[nodiscard]] constexpr GuestAddress32 base() const noexcept { return base_; }
    [[nodiscard]] constexpr std::uint64_t size() const noexcept { return size_; }

    [[nodiscard]] constexpr bool contains(GuestAddress32 address, std::uint64_t length = 1) const noexcept {
        const auto begin = static_cast<std::uint64_t>(address.value());
        const auto range_begin = static_cast<std::uint64_t>(base_.value());
        const auto range_end = range_begin + size_;
        const auto access_end = begin + length;
        return begin >= range_begin && access_end >= begin && access_end <= range_end;
    }

private:
    constexpr GuestRange32(GuestAddress32 base, std::uint64_t size) noexcept : base_(base), size_(size) {}

    GuestAddress32 base_;
    std::uint64_t size_;
};

}  // namespace retrobridge::runtime
