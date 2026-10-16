#pragma once

#include "retrobridge/guest_address.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace retrobridge::runtime {

enum class GuestPermission : std::uint8_t {
    None = 0,
    Read = 1U << 0U,
    Write = 1U << 1U,
    Execute = 1U << 2U,
};

[[nodiscard]] constexpr GuestPermission operator|(GuestPermission left, GuestPermission right) noexcept {
    return static_cast<GuestPermission>(static_cast<std::uint8_t>(left) | static_cast<std::uint8_t>(right));
}

[[nodiscard]] constexpr GuestPermission operator&(GuestPermission left, GuestPermission right) noexcept {
    return static_cast<GuestPermission>(static_cast<std::uint8_t>(left) & static_cast<std::uint8_t>(right));
}

[[nodiscard]] constexpr bool has_permission(GuestPermission set, GuestPermission required) noexcept {
    return (set & required) == required;
}

/** Sparse 32-bit guest address space. Guest addresses are never host pointers. */
class GuestMemory final {
public:
    explicit GuestMemory(std::size_t byte_limit = 512U * 1024U * 1024U) noexcept;

    [[nodiscard]] bool map_zeroed(
        GuestAddress32 base,
        std::uint64_t size,
        GuestPermission permissions,
        std::string* diagnostic = nullptr);

    [[nodiscard]] bool map_bytes(
        GuestAddress32 base,
        std::span<const std::byte> file_bytes,
        std::uint64_t memory_size,
        GuestPermission permissions,
        std::string* diagnostic = nullptr);

    [[nodiscard]] bool unmap(GuestAddress32 base) noexcept;
    [[nodiscard]] bool protect(GuestAddress32 base, GuestPermission permissions) noexcept;

    [[nodiscard]] bool read(
        GuestAddress32 address,
        std::span<std::byte> output,
        GuestPermission required = GuestPermission::Read) const noexcept;
    [[nodiscard]] bool write(
        GuestAddress32 address,
        std::span<const std::byte> input) noexcept;

    /** Loader-only access used for relocations, including patches to RX text. */
    [[nodiscard]] bool loader_read(GuestAddress32 address, std::span<std::byte> output) const noexcept;
    [[nodiscard]] bool loader_write(GuestAddress32 address, std::span<const std::byte> input) noexcept;

    [[nodiscard]] std::optional<std::uint8_t> read_u8(GuestAddress32 address) const noexcept;
    [[nodiscard]] std::optional<std::uint16_t> read_u16(GuestAddress32 address) const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> read_u32(GuestAddress32 address) const noexcept;
    [[nodiscard]] bool write_u16(GuestAddress32 address, std::uint16_t value) noexcept;
    [[nodiscard]] bool write_u32(GuestAddress32 address, std::uint32_t value) noexcept;

    [[nodiscard]] bool is_mapped(GuestAddress32 address, std::uint64_t length = 1) const noexcept;
    [[nodiscard]] bool is_accessible(
        GuestAddress32 address,
        std::uint64_t length,
        GuestPermission required) const noexcept;
    [[nodiscard]] bool is_executable(GuestAddress32 address) const noexcept;
    [[nodiscard]] std::size_t mapped_bytes() const noexcept { return mapped_bytes_; }
    [[nodiscard]] std::size_t byte_limit() const noexcept { return byte_limit_; }

private:
    struct Region final {
        GuestAddress32 base;
        GuestRange32 range;
        GuestPermission permissions;
        std::vector<std::byte> bytes;
    };

    [[nodiscard]] bool map_impl(
        GuestAddress32 base,
        std::span<const std::byte> file_bytes,
        std::uint64_t memory_size,
        GuestPermission permissions,
        std::string* diagnostic);
    [[nodiscard]] bool copy_from(
        GuestAddress32 address,
        std::span<std::byte> output,
        GuestPermission required,
        bool check_permissions) const noexcept;
    [[nodiscard]] bool copy_to(
        GuestAddress32 address,
        std::span<const std::byte> input,
        bool check_permissions) noexcept;

    std::map<std::uint32_t, Region> regions_;
    std::size_t byte_limit_;
    std::size_t mapped_bytes_ = 0;
};

}  // namespace retrobridge::runtime
