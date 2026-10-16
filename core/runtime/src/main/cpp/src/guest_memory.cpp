#include "retrobridge/guest_memory.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace retrobridge::runtime {

GuestMemory::GuestMemory(std::size_t byte_limit) noexcept : byte_limit_(byte_limit) {}

bool GuestMemory::map_zeroed(
    GuestAddress32 base,
    std::uint64_t size,
    GuestPermission permissions,
    std::string* diagnostic) {
    return map_impl(base, {}, size, permissions, diagnostic);
}

bool GuestMemory::map_bytes(
    GuestAddress32 base,
    std::span<const std::byte> file_bytes,
    std::uint64_t memory_size,
    GuestPermission permissions,
    std::string* diagnostic) {
    return map_impl(base, file_bytes, memory_size, permissions, diagnostic);
}

bool GuestMemory::map_impl(
    GuestAddress32 base,
    std::span<const std::byte> file_bytes,
    std::uint64_t memory_size,
    GuestPermission permissions,
    std::string* diagnostic) {
    const auto fail = [&](const char* message) {
        if (diagnostic != nullptr) *diagnostic = message;
        return false;
    };
    if (memory_size == 0 || file_bytes.size() > memory_size) return fail("invalid guest mapping size");
    const auto range = GuestRange32::create(base, memory_size);
    if (!range.has_value()) return fail("guest mapping wraps the 32-bit address space");
    if (memory_size > std::numeric_limits<std::size_t>::max()) return fail("guest mapping exceeds host size limits");
    const auto size = static_cast<std::size_t>(memory_size);
    if (size > byte_limit_ || mapped_bytes_ > byte_limit_ - size) return fail("guest memory quota exceeded");

    const auto begin = base.value();
    const auto end = static_cast<std::uint64_t>(begin) + memory_size;
    const auto next = regions_.lower_bound(begin);
    if (next != regions_.end() && end > next->first) return fail("guest mapping overlaps an existing region");
    if (next != regions_.begin()) {
        const auto previous = std::prev(next);
        const auto previous_end = static_cast<std::uint64_t>(previous->second.base.value())
            + previous->second.range.size();
        if (previous_end > begin) return fail("guest mapping overlaps an existing region");
    }

    try {
        std::vector<std::byte> bytes(size, std::byte{0});
        std::copy(file_bytes.begin(), file_bytes.end(), bytes.begin());
        Region region{base, *range, permissions, std::move(bytes)};
        regions_.emplace(begin, std::move(region));
    } catch (const std::bad_alloc&) {
        return fail("unable to allocate guest memory mapping");
    } catch (const std::length_error&) {
        return fail("guest memory mapping is too large");
    }
    mapped_bytes_ += size;
    return true;
}

bool GuestMemory::unmap(GuestAddress32 base) noexcept {
    const auto found = regions_.find(base.value());
    if (found == regions_.end()) return false;
    mapped_bytes_ -= found->second.bytes.size();
    regions_.erase(found);
    return true;
}

bool GuestMemory::protect(GuestAddress32 base, GuestPermission permissions) noexcept {
    const auto found = regions_.find(base.value());
    if (found == regions_.end()) return false;
    found->second.permissions = permissions;
    return true;
}

bool GuestMemory::read(
    GuestAddress32 address,
    std::span<std::byte> output,
    GuestPermission required) const noexcept {
    return copy_from(address, output, required, true);
}

bool GuestMemory::write(GuestAddress32 address, std::span<const std::byte> input) noexcept {
    return copy_to(address, input, true);
}

bool GuestMemory::loader_read(GuestAddress32 address, std::span<std::byte> output) const noexcept {
    return copy_from(address, output, GuestPermission::None, false);
}

bool GuestMemory::loader_write(GuestAddress32 address, std::span<const std::byte> input) noexcept {
    return copy_to(address, input, false);
}

std::optional<std::uint8_t> GuestMemory::read_u8(GuestAddress32 address) const noexcept {
    std::array<std::byte, 1> bytes{};
    if (!read(address, bytes)) return std::nullopt;
    return std::to_integer<std::uint8_t>(bytes[0]);
}

std::optional<std::uint16_t> GuestMemory::read_u16(GuestAddress32 address) const noexcept {
    std::array<std::byte, 2> bytes{};
    if (!read(address, bytes)) return std::nullopt;
    const auto low = std::to_integer<std::uint8_t>(bytes[0]);
    const auto high = std::to_integer<std::uint8_t>(bytes[1]);
    return static_cast<std::uint16_t>(low | (static_cast<std::uint16_t>(high) << 8U));
}

std::optional<std::uint32_t> GuestMemory::read_u32(GuestAddress32 address) const noexcept {
    std::array<std::byte, 4> bytes{};
    if (!read(address, bytes)) return std::nullopt;
    std::uint32_t result = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[index])) << (8U * index);
    }
    return result;
}

bool GuestMemory::write_u16(GuestAddress32 address, std::uint16_t value) noexcept {
    const std::array<std::byte, 2> bytes{
        static_cast<std::byte>(value & 0xffU),
        static_cast<std::byte>((value >> 8U) & 0xffU),
    };
    return write(address, bytes);
}

bool GuestMemory::write_u32(GuestAddress32 address, std::uint32_t value) noexcept {
    std::array<std::byte, 4> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (8U * index)) & 0xffU);
    }
    return write(address, bytes);
}

bool GuestMemory::is_mapped(GuestAddress32 address, std::uint64_t length) const noexcept {
    if (length == 0) return true;
    const auto requested_end = static_cast<std::uint64_t>(address.value()) + length;
    if (requested_end > (std::uint64_t{1} << 32)) return false;
    auto cursor = static_cast<std::uint64_t>(address.value());
    while (cursor < requested_end) {
        const auto lookup = regions_.upper_bound(static_cast<std::uint32_t>(cursor));
        if (lookup == regions_.begin()) return false;
        const auto region = std::prev(lookup);
        const auto region_begin = static_cast<std::uint64_t>(region->second.base.value());
        const auto region_end = region_begin + region->second.range.size();
        if (cursor < region_begin || cursor >= region_end) return false;
        cursor = std::min(requested_end, region_end);
    }
    return true;
}

bool GuestMemory::is_accessible(
    GuestAddress32 address,
    std::uint64_t length,
    GuestPermission required) const noexcept {
    if (length == 0) return true;
    const auto requested_end = static_cast<std::uint64_t>(address.value()) + length;
    if (requested_end > (std::uint64_t{1} << 32)) return false;
    auto cursor = static_cast<std::uint64_t>(address.value());
    while (cursor < requested_end) {
        const auto lookup = regions_.upper_bound(static_cast<std::uint32_t>(cursor));
        if (lookup == regions_.begin()) return false;
        const auto region = std::prev(lookup);
        const auto region_begin = static_cast<std::uint64_t>(region->second.base.value());
        const auto region_end = region_begin + region->second.range.size();
        if (cursor < region_begin || cursor >= region_end
            || !has_permission(region->second.permissions, required)) return false;
        cursor = std::min(requested_end, region_end);
    }
    return true;
}

bool GuestMemory::is_executable(GuestAddress32 address) const noexcept {
    const auto lookup = regions_.upper_bound(address.value());
    if (lookup == regions_.begin()) return false;
    const auto region = std::prev(lookup);
    return region->second.range.contains(address)
        && has_permission(region->second.permissions, GuestPermission::Execute);
}

bool GuestMemory::copy_from(
    GuestAddress32 address,
    std::span<std::byte> output,
    GuestPermission required,
    bool check_permissions) const noexcept {
    if (output.empty()) return true;
    const auto requested_end = static_cast<std::uint64_t>(address.value()) + output.size();
    if (requested_end > (std::uint64_t{1} << 32)) return false;
    auto cursor = static_cast<std::uint64_t>(address.value());
    std::size_t copied = 0;
    while (copied < output.size()) {
        const auto lookup = regions_.upper_bound(static_cast<std::uint32_t>(cursor));
        if (lookup == regions_.begin()) return false;
        const auto region = std::prev(lookup);
        const auto region_begin = static_cast<std::uint64_t>(region->second.base.value());
        const auto region_end = region_begin + region->second.range.size();
        if (cursor < region_begin || cursor >= region_end) return false;
        if (check_permissions && !has_permission(region->second.permissions, required)) return false;
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
            output.size() - copied,
            region_end - cursor));
        const auto source_offset = static_cast<std::size_t>(cursor - region_begin);
        std::copy_n(region->second.bytes.begin() + static_cast<std::ptrdiff_t>(source_offset), count,
            output.begin() + static_cast<std::ptrdiff_t>(copied));
        copied += count;
        cursor += count;
    }
    return true;
}

bool GuestMemory::copy_to(
    GuestAddress32 address,
    std::span<const std::byte> input,
    bool check_permissions) noexcept {
    if (input.empty()) return true;
    const auto requested_end = static_cast<std::uint64_t>(address.value()) + input.size();
    if (requested_end > (std::uint64_t{1} << 32)) return false;
    if (check_permissions) {
        auto validation_cursor = static_cast<std::uint64_t>(address.value());
        while (validation_cursor < requested_end) {
            const auto lookup = regions_.upper_bound(static_cast<std::uint32_t>(validation_cursor));
            if (lookup == regions_.begin()) return false;
            const auto region = std::prev(lookup);
            const auto region_begin = static_cast<std::uint64_t>(region->second.base.value());
            const auto region_end = region_begin + region->second.range.size();
            if (validation_cursor < region_begin || validation_cursor >= region_end
                || !has_permission(region->second.permissions, GuestPermission::Write)) return false;
            validation_cursor = std::min(requested_end, region_end);
        }
    }
    auto cursor = static_cast<std::uint64_t>(address.value());
    std::size_t copied = 0;
    while (copied < input.size()) {
        const auto lookup = regions_.upper_bound(static_cast<std::uint32_t>(cursor));
        if (lookup == regions_.begin()) return false;
        auto region = std::prev(lookup);
        const auto region_begin = static_cast<std::uint64_t>(region->second.base.value());
        const auto region_end = region_begin + region->second.range.size();
        if (cursor < region_begin || cursor >= region_end) return false;
        if (check_permissions && !has_permission(region->second.permissions, GuestPermission::Write)) return false;
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
            input.size() - copied,
            region_end - cursor));
        const auto destination_offset = static_cast<std::size_t>(cursor - region_begin);
        std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(copied), count,
            region->second.bytes.begin() + static_cast<std::ptrdiff_t>(destination_offset));
        copied += count;
        cursor += count;
    }
    return true;
}

}  // namespace retrobridge::runtime
