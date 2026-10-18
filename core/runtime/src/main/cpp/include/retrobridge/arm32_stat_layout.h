#pragma once

#include "retrobridge/guest_memory.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <sys/stat.h>

namespace retrobridge::runtime {

inline constexpr std::size_t kArm32GuestStat64Size = 96;

/** Serialize the Linux ARM32 stat64 ABI shared by Bionic wrappers and EABI syscalls. */
[[nodiscard]] inline bool write_arm32_guest_stat64(
    GuestMemory& memory,
    GuestAddress32 address,
    const struct stat& status) noexcept {
    if (!memory.is_accessible(address, kArm32GuestStat64Size, GuestPermission::Write)) return false;
    std::array<std::byte, kArm32GuestStat64Size> bytes{};
    const auto put_le = [&bytes](std::size_t offset, std::uint64_t value, std::size_t count) {
        for (std::size_t index = 0; index < count; ++index) {
            bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
        }
    };
    put_le(0, static_cast<std::uint64_t>(status.st_dev), 8);
    put_le(12, static_cast<std::uint32_t>(status.st_ino), 4);
    put_le(16, static_cast<std::uint32_t>(status.st_mode), 4);
    put_le(20, static_cast<std::uint32_t>(status.st_nlink), 4);
    put_le(24, static_cast<std::uint32_t>(status.st_uid), 4);
    put_le(28, static_cast<std::uint32_t>(status.st_gid), 4);
    put_le(32, static_cast<std::uint64_t>(status.st_rdev), 8);
    put_le(44, static_cast<std::uint64_t>(status.st_size), 8);
    put_le(52, static_cast<std::uint32_t>(status.st_blksize), 4);
    put_le(56, static_cast<std::uint64_t>(status.st_blocks), 8);
    put_le(64, static_cast<std::uint32_t>(status.st_atim.tv_sec), 4);
    put_le(68, static_cast<std::uint32_t>(status.st_atim.tv_nsec), 4);
    put_le(72, static_cast<std::uint32_t>(status.st_mtim.tv_sec), 4);
    put_le(76, static_cast<std::uint32_t>(status.st_mtim.tv_nsec), 4);
    put_le(80, static_cast<std::uint32_t>(status.st_ctim.tv_sec), 4);
    put_le(84, static_cast<std::uint32_t>(status.st_ctim.tv_nsec), 4);
    put_le(88, static_cast<std::uint64_t>(status.st_ino), 8);
    return memory.write(address, bytes);
}

}  // namespace retrobridge::runtime
