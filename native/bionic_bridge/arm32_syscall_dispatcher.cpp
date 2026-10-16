#include "arm32_syscall_dispatcher.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

namespace retrobridge::runtime {
namespace {

constexpr std::size_t kPageSize = 4096;
constexpr std::uint32_t kMaxMappingSize = 64U * 1024U * 1024U;
constexpr std::uint32_t kMaxIoSize = 16U * 1024U * 1024U;
constexpr std::uint32_t kBrkLimit = 0x31000000U;
constexpr std::int32_t kAtFdcwd = -100;
constexpr std::uint32_t kMapShared = 0x01U;
constexpr std::uint32_t kMapPrivate = 0x02U;
constexpr std::uint32_t kMapFixed = 0x10U;
constexpr std::uint32_t kMapAnonymous = 0x20U;
constexpr std::uint32_t kProtRead = 1U;
constexpr std::uint32_t kProtWrite = 2U;
constexpr std::uint32_t kProtExec = 4U;

void put_le(std::span<std::byte> output, std::size_t offset, std::uint64_t value, std::size_t byte_count) noexcept {
    for (std::size_t index = 0; index < byte_count; ++index) {
        output[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

[[nodiscard]] bool valid_timespec32(const GuestMemory& memory, std::uint32_t address, std::int32_t& seconds, std::int32_t& nanoseconds) {
    if (address > std::numeric_limits<std::uint32_t>::max() - 4U) return false;
    const auto sec = memory.read_u32(GuestAddress32{address});
    const auto nsec = memory.read_u32(GuestAddress32{address + 4U});
    if (!sec.has_value() || !nsec.has_value()) return false;
    seconds = std::bit_cast<std::int32_t>(*sec);
    nanoseconds = std::bit_cast<std::int32_t>(*nsec);
    return seconds >= 0 && nanoseconds >= 0 && nanoseconds < 1'000'000'000;
}

[[nodiscard]] std::uint64_t combine_u64(std::uint32_t low, std::uint32_t high) noexcept {
    return static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
}

}  // namespace

Arm32SyscallDispatcher::Arm32SyscallDispatcher(
    GuestMemory& memory,
    GuestHeap32& heap,
    NativeVfs& vfs) noexcept
    : memory_(memory), heap_(heap), vfs_(vfs) {}

GuestHookResult Arm32SyscallDispatcher::handle(
    GuestCpuState32& state,
    std::uint32_t svc_immediate,
    GuestMemory& memory) {
    (void)svc_immediate;
    if (&memory != &memory_) {
        state.r[0] = static_cast<std::uint32_t>(-EFAULT);
        return {};
    }
    const auto argument = [&](std::size_t index) { return state.r[index]; };
    const auto result = [&](std::int32_t value) {
        set_result(state, value);
        return GuestHookResult{};
    };
    const auto path_at = [&](std::uint32_t pointer) -> std::optional<std::string> {
        return read_guest_string(pointer);
    };

    try {
        switch (state.r[7]) {
        case 1:  // exit
        case 248: { // exit_group
            return {GuestHookAction::Stop, "guest process exited with status " + std::to_string(state.r[0])};
        }
        case 3: return result(read_call(static_cast<int>(argument(0)), argument(1), argument(2)));
        case 4: return result(write_call(static_cast<int>(argument(0)), argument(1), argument(2)));
        case 5: {
            const auto path = path_at(argument(0));
            if (!path.has_value()) return result(-EFAULT);
            const auto fd = vfs_.open(*path, static_cast<int>(argument(1)), argument(2));
            return result(fd < 0 ? errno_result() : fd);
        }
        case 6: {
            const auto closed = vfs_.close(static_cast<int>(argument(0)));
            return result(closed < 0 ? errno_result() : 0);
        }
        case 19: {
            const auto offset = std::bit_cast<std::int32_t>(argument(1));
            const auto value = vfs_.seek(static_cast<int>(argument(0)), offset, static_cast<int>(argument(2)));
            if (value < 0) return result(errno_result());
            if (value > std::numeric_limits<std::int32_t>::max()) return result(-EOVERFLOW);
            return result(static_cast<std::int32_t>(value));
        }
        case 20: return result(static_cast<std::int32_t>(synthetic_pid_));
        case 33: {
            const auto path = path_at(argument(0));
            if (!path.has_value()) return result(-EFAULT);
            const auto status = vfs_.access(*path, static_cast<int>(argument(1)));
            return result(status < 0 ? errno_result() : status);
        }
        case 45: return result(brk_call(argument(0)));
        case 78: { // gettimeofday: timeval32
            timeval value{};
            if (::gettimeofday(&value, nullptr) != 0) return result(errno_result());
            if (!memory_.is_accessible(GuestAddress32{argument(0)}, 8, GuestPermission::Write)) return result(-EFAULT);
            const std::array<std::byte, 8> bytes{
                static_cast<std::byte>(static_cast<std::uint32_t>(value.tv_sec) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_sec) >> 8U) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_sec) >> 16U) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_sec) >> 24U) & 0xffU),
                static_cast<std::byte>(static_cast<std::uint32_t>(value.tv_usec) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_usec) >> 8U) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_usec) >> 16U) & 0xffU),
                static_cast<std::byte>((static_cast<std::uint32_t>(value.tv_usec) >> 24U) & 0xffU),
            };
            return result(memory_.write(GuestAddress32{argument(0)}, bytes) ? 0 : -EFAULT);
        }
        case 91: return result(munmap_call(argument(0), argument(1)));
        case 125: return result(mprotect_call(argument(0), argument(1), argument(2)));
        case 140: { // _llseek(fd, offset_high, offset_low, result_ptr, whence)
            const auto offset = std::bit_cast<std::int64_t>(combine_u64(argument(2), argument(1)));
            const auto value = vfs_.seek(static_cast<int>(argument(0)), offset, static_cast<int>(argument(4)));
            if (value < 0) return result(errno_result());
            std::array<std::byte, 8> bytes{};
            put_le(bytes, 0, static_cast<std::uint64_t>(value), bytes.size());
            if (!memory_.write(GuestAddress32{argument(3)}, bytes)) return result(-EFAULT);
            return result(0);
        }
        case 162: { // nanosleep(timespec32, remaining32)
            std::int32_t seconds = 0;
            std::int32_t nanoseconds = 0;
            if (!valid_timespec32(memory_, argument(0), seconds, nanoseconds)) return result(-EINVAL);
            if (seconds > 60) return result(-EINTR);
            const timespec request{seconds, nanoseconds};
            timespec remaining{};
            if (::nanosleep(&request, &remaining) != 0) {
                if (argument(1) != 0) {
                    std::array<std::byte, 8> bytes{};
                    put_le(bytes, 0, static_cast<std::uint32_t>(remaining.tv_sec), 4);
                    put_le(bytes, 4, static_cast<std::uint32_t>(remaining.tv_nsec), 4);
                    if (!memory_.write(GuestAddress32{argument(1)}, bytes)) return result(-EFAULT);
                }
                return result(errno_result());
            }
            return result(0);
        }
        case 183: return result(getcwd_call(argument(0), argument(1)));
        case 192: return result(mmap2_call(state));
        case 195:
        case 196: {
            const auto path = path_at(argument(0));
            if (!path.has_value()) return result(-EFAULT);
            return result(stat_call(*path, argument(1), state.r[7] == 196));
        }
        case 197: return result(fstat_call(static_cast<int>(argument(0)), argument(1)));
        case 199: return result(0);
        case 217: return result(getdents64_call(static_cast<int>(argument(0)), argument(1), argument(2)));
        case 224: return result(static_cast<std::int32_t>(synthetic_pid_ + 1U));
        case 240: { // limited futex WAIT/WAKE; no guest thread pool is enabled yet
            const auto operation = argument(1) & 0x7fU;
            if (operation == 1U) return result(0); // FUTEX_WAKE
            if (operation == 0U) {
                const auto current = memory_.read_u32(GuestAddress32{argument(0)});
                if (!current.has_value()) return result(-EFAULT);
                return result(*current == argument(2) ? -ENOSYS : -EAGAIN);
            }
            return result(-ENOSYS);
        }
        case 263: { // clock_gettime(clockid, timespec32)
            timespec value{};
            if (::clock_gettime(static_cast<clockid_t>(argument(0)), &value) != 0) return result(errno_result());
            if (value.tv_sec < 0 || value.tv_sec > std::numeric_limits<std::int32_t>::max()) return result(-EOVERFLOW);
            std::array<std::byte, 8> bytes{};
            put_le(bytes, 0, static_cast<std::uint32_t>(value.tv_sec), 4);
            put_le(bytes, 4, static_cast<std::uint32_t>(value.tv_nsec), 4);
            return result(memory_.write(GuestAddress32{argument(1)}, bytes) ? 0 : -EFAULT);
        }
        case 322: {
            const auto path = path_at(argument(1));
            if (!path.has_value()) return result(-EFAULT);
            const auto fd = vfs_.openat(std::bit_cast<std::int32_t>(argument(0)), *path,
                static_cast<int>(argument(2)), argument(3));
            return result(fd < 0 ? errno_result() : fd);
        }
        case 323: {
            const auto path = path_at(argument(1));
            if (!path.has_value()) return result(-EFAULT);
            const auto status = vfs_.mkdirat(std::bit_cast<std::int32_t>(argument(0)), *path, argument(2));
            return result(status < 0 ? errno_result() : status);
        }
        case 327: {
            const auto path = path_at(argument(1));
            if (!path.has_value()) return result(-EFAULT);
            struct stat status{};
            const auto flags = (argument(3) & 0x100U) != 0 ? AT_SYMLINK_NOFOLLOW : 0;
            if (vfs_.statat(std::bit_cast<std::int32_t>(argument(0)), *path, &status, flags) != 0) {
                return result(errno_result());
            }
            return result(write_stat64(status, argument(2)));
        }
        case 328: {
            const auto path = path_at(argument(1));
            if (!path.has_value()) return result(-EFAULT);
            const auto status = vfs_.unlinkat(std::bit_cast<std::int32_t>(argument(0)), *path,
                static_cast<int>(argument(2)));
            return result(status < 0 ? errno_result() : status);
        }
        case 329: {
            const auto old_path = path_at(argument(1));
            const auto new_path = path_at(argument(3));
            if (!old_path.has_value() || !new_path.has_value()) return result(-EFAULT);
            const auto status = vfs_.renameat(std::bit_cast<std::int32_t>(argument(0)), *old_path,
                std::bit_cast<std::int32_t>(argument(2)), *new_path);
            return result(status < 0 ? errno_result() : status);
        }
        case 334: {
            const auto path = path_at(argument(1));
            if (!path.has_value()) return result(-EFAULT);
            const auto status = vfs_.faccessat(std::bit_cast<std::int32_t>(argument(0)), *path,
                static_cast<int>(argument(2)), static_cast<int>(argument(3)));
            return result(status < 0 ? errno_result() : status);
        }
        default:
            return result(-ENOSYS);
        }
    } catch (...) {
        return result(-ENOMEM);
    }
}

GuestSvcHandler Arm32SyscallDispatcher::as_handler() {
    return [this](GuestCpuState32& state, std::uint32_t immediate, GuestMemory& memory) {
        return handle(state, immediate, memory);
    };
}

std::optional<std::string> Arm32SyscallDispatcher::read_guest_string(std::uint32_t address, std::size_t maximum) const {
    std::string output;
    output.reserve(std::min<std::size_t>(maximum, 256));
    for (std::size_t index = 0; index < maximum; ++index) {
        const auto current = static_cast<std::uint64_t>(address) + index;
        if (current >= (std::uint64_t{1} << 32U)) return std::nullopt;
        const auto byte = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(current)});
        if (!byte.has_value()) return std::nullopt;
        if (*byte == 0) return output;
        output.push_back(static_cast<char>(*byte));
    }
    return std::nullopt;
}

std::int32_t Arm32SyscallDispatcher::openat_call(
    std::int32_t dirfd,
    std::uint32_t path,
    int flags,
    unsigned mode) {
    const auto guest_path = read_guest_string(path);
    if (!guest_path.has_value()) return -EFAULT;
    const auto fd = vfs_.openat(dirfd, *guest_path, flags, mode);
    return fd < 0 ? errno_result() : fd;
}

std::int32_t Arm32SyscallDispatcher::stat_call(std::string_view path, std::uint32_t output, bool no_follow) {
    struct stat status{};
    if (vfs_.stat_path(path, &status, no_follow) != 0) return errno_result();
    return write_stat64(status, output);
}

std::int32_t Arm32SyscallDispatcher::fstat_call(int fd, std::uint32_t output) {
    struct stat status{};
    if (vfs_.fstat(fd, &status) != 0) return errno_result();
    return write_stat64(status, output);
}

std::int32_t Arm32SyscallDispatcher::write_stat64(const struct stat& status, std::uint32_t output) {
    std::array<std::byte, 96> bytes{};
    put_le(bytes, 0, static_cast<std::uint64_t>(status.st_dev), 8);
    put_le(bytes, 8, 0, 4);
    put_le(bytes, 12, static_cast<std::uint32_t>(status.st_ino), 4);
    put_le(bytes, 16, static_cast<std::uint32_t>(status.st_mode), 4);
    put_le(bytes, 20, static_cast<std::uint32_t>(status.st_nlink), 4);
    put_le(bytes, 24, static_cast<std::uint32_t>(status.st_uid), 4);
    put_le(bytes, 28, static_cast<std::uint32_t>(status.st_gid), 4);
    put_le(bytes, 32, static_cast<std::uint64_t>(status.st_rdev), 8);
    put_le(bytes, 40, 0, 4);
    put_le(bytes, 44, static_cast<std::uint64_t>(status.st_size), 8);
    put_le(bytes, 52, static_cast<std::uint32_t>(status.st_blksize), 4);
    put_le(bytes, 56, static_cast<std::uint64_t>(status.st_blocks), 8);
    put_le(bytes, 64, static_cast<std::uint32_t>(status.st_atim.tv_sec), 4);
    put_le(bytes, 68, static_cast<std::uint32_t>(status.st_atim.tv_nsec), 4);
    put_le(bytes, 72, static_cast<std::uint32_t>(status.st_mtim.tv_sec), 4);
    put_le(bytes, 76, static_cast<std::uint32_t>(status.st_mtim.tv_nsec), 4);
    put_le(bytes, 80, static_cast<std::uint32_t>(status.st_ctim.tv_sec), 4);
    put_le(bytes, 84, static_cast<std::uint32_t>(status.st_ctim.tv_nsec), 4);
    put_le(bytes, 88, static_cast<std::uint64_t>(status.st_ino), 8);
    return memory_.write(GuestAddress32{output}, bytes) ? 0 : -EFAULT;
}

std::int32_t Arm32SyscallDispatcher::mmap2_call(GuestCpuState32& state) {
    const auto hint = state.r[0];
    const auto length = state.r[1];
    const auto protection = state.r[2];
    const auto flags = state.r[3];
    const auto guest_fd = std::bit_cast<std::int32_t>(state.r[4]);
    const auto page_offset = state.r[5];
    constexpr std::uint32_t allowed_flags = kMapShared | kMapPrivate | kMapFixed | kMapAnonymous;
    if (length == 0 || length > kMaxMappingSize || (protection & ~(kProtRead | kProtWrite | kProtExec)) != 0
        || (flags & ~allowed_flags) != 0) return -EINVAL;
    if (((flags & kMapShared) != 0) == ((flags & kMapPrivate) != 0)) return -EINVAL;
    const bool anonymous = (flags & kMapAnonymous) != 0;
    const bool fixed = (flags & kMapFixed) != 0;
    if (!anonymous && guest_fd < 0) return -EBADF;
    const bool shared = (flags & kMapShared) != 0;
    if (shared && (protection & kProtWrite) != 0) return -ENOTSUP;

    const auto rounded = (static_cast<std::uint64_t>(length) + kPageSize - 1U) & ~(std::uint64_t{kPageSize - 1U});
    if (rounded > kMaxMappingSize) return -ENOMEM;
    GuestPermission permissions = GuestPermission::None;
    if ((protection & kProtRead) != 0) permissions = permissions | GuestPermission::Read;
    if ((protection & kProtWrite) != 0) permissions = permissions | GuestPermission::Write;
    if ((protection & kProtExec) != 0) permissions = permissions | GuestPermission::Execute;

    std::uint32_t address = hint;
    if (fixed) {
        if ((address & (kPageSize - 1U)) != 0 || memory_.is_mapped(GuestAddress32{address}, rounded)) return -EINVAL;
    } else {
        if (address != 0 && (address & (kPageSize - 1U)) == 0
            && !memory_.is_mapped(GuestAddress32{address}, rounded)) {
            // Honor a free page-aligned hint.
        } else {
            std::lock_guard lock(mutex_);
            address = next_mmap_address_;
            while (static_cast<std::uint64_t>(address) + rounded <= 0x70000000U
                && memory_.is_mapped(GuestAddress32{address}, rounded)) {
                address += static_cast<std::uint32_t>(rounded);
            }
            if (static_cast<std::uint64_t>(address) + rounded > 0x70000000U) return -ENOMEM;
            next_mmap_address_ = address + static_cast<std::uint32_t>(rounded);
        }
    }

    if (!GuestRange32::create(GuestAddress32{address}, rounded).has_value()) return -ENOMEM;

    std::vector<std::byte> file_bytes;
    if (!anonymous) {
        const auto old_offset = vfs_.seek(guest_fd, 0, SEEK_CUR);
        if (old_offset < 0) return errno_result();
        const auto requested_offset = static_cast<std::uint64_t>(page_offset) * kPageSize;
        if (requested_offset > static_cast<std::uint64_t>(std::numeric_limits<long long>::max())) return -EOVERFLOW;
        if (vfs_.seek(guest_fd, static_cast<long long>(requested_offset), SEEK_SET) < 0) return errno_result();
        try {
            file_bytes.resize(static_cast<std::size_t>(rounded), std::byte{0});
        } catch (...) {
            (void)vfs_.seek(guest_fd, old_offset, SEEK_SET);
            return -ENOMEM;
        }
        const auto count = vfs_.read(guest_fd, file_bytes);
        const auto saved_errno = errno;
        (void)vfs_.seek(guest_fd, old_offset, SEEK_SET);
        if (count < 0) {
            errno = saved_errno;
            return errno_result();
        }
        file_bytes.resize(static_cast<std::size_t>(count));
    }

    std::string diagnostic;
    const bool mapped = anonymous
        ? memory_.map_zeroed(GuestAddress32{address}, rounded, permissions, &diagnostic)
        : memory_.map_bytes(GuestAddress32{address}, file_bytes, rounded, permissions, &diagnostic);
    if (!mapped) return -ENOMEM;
    try {
        std::lock_guard lock(mutex_);
        mappings_.emplace(address, Mapping{address, static_cast<std::size_t>(rounded), permissions, guest_fd,
            static_cast<std::uint64_t>(page_offset) * kPageSize, shared});
    } catch (...) {
        (void)memory_.unmap(GuestAddress32{address});
        return -ENOMEM;
    }
    return std::bit_cast<std::int32_t>(address);
}

std::int32_t Arm32SyscallDispatcher::munmap_call(std::uint32_t address, std::uint32_t length) {
    std::lock_guard lock(mutex_);
    const auto mapping = mappings_.find(address);
    const auto rounded = (static_cast<std::uint64_t>(length) + kPageSize - 1U)
        & ~(std::uint64_t{kPageSize - 1U});
    if (mapping == mappings_.end() || length == 0 || mapping->second.size != rounded) return -EINVAL;
    if (!memory_.unmap(GuestAddress32{address})) return -EINVAL;
    mappings_.erase(mapping);
    return 0;
}

std::int32_t Arm32SyscallDispatcher::mprotect_call(
    std::uint32_t address,
    std::uint32_t length,
    std::uint32_t protection) {
    std::lock_guard lock(mutex_);
    const auto mapping = mappings_.find(address);
    const auto rounded = (static_cast<std::uint64_t>(length) + kPageSize - 1U)
        & ~(std::uint64_t{kPageSize - 1U});
    if (mapping == mappings_.end() || length == 0 || mapping->second.size != rounded
        || (protection & ~(kProtRead | kProtWrite | kProtExec)) != 0) return -EINVAL;
    if (mapping->second.shared && (protection & kProtWrite) != 0) return -ENOTSUP;
    GuestPermission permissions = GuestPermission::None;
    if ((protection & kProtRead) != 0) permissions = permissions | GuestPermission::Read;
    if ((protection & kProtWrite) != 0) permissions = permissions | GuestPermission::Write;
    if ((protection & kProtExec) != 0) permissions = permissions | GuestPermission::Execute;
    if (!memory_.protect(GuestAddress32{address}, permissions)) return -ENOMEM;
    mapping->second.permissions = permissions;
    return 0;
}

std::int32_t Arm32SyscallDispatcher::brk_call(std::uint32_t requested) {
    std::lock_guard lock(mutex_);
    if (requested == 0) return std::bit_cast<std::int32_t>(brk_current_);
    if (requested < brk_base_ || requested > kBrkLimit) return std::bit_cast<std::int32_t>(brk_current_);
    const auto rounded = static_cast<std::uint32_t>((static_cast<std::uint64_t>(requested) + kPageSize - 1U)
        & ~(std::uint64_t{kPageSize - 1U}));
    if (rounded > brk_mapped_end_) {
        const auto old_end = brk_mapped_end_;
        for (auto page = old_end; page < rounded; page += static_cast<std::uint32_t>(kPageSize)) {
            if (!memory_.map_zeroed(GuestAddress32{page}, kPageSize, GuestPermission::Read | GuestPermission::Write)) {
                for (auto rollback = old_end; rollback < page; rollback += static_cast<std::uint32_t>(kPageSize)) {
                    (void)memory_.unmap(GuestAddress32{rollback});
                }
                return std::bit_cast<std::int32_t>(brk_current_);
            }
        }
        brk_mapped_end_ = rounded;
    } else if (rounded < brk_mapped_end_) {
        for (auto page = rounded; page < brk_mapped_end_; page += static_cast<std::uint32_t>(kPageSize)) {
            (void)memory_.unmap(GuestAddress32{page});
        }
        brk_mapped_end_ = rounded;
    }
    brk_current_ = requested;
    return std::bit_cast<std::int32_t>(brk_current_);
}

std::int32_t Arm32SyscallDispatcher::read_call(int fd, std::uint32_t address, std::uint32_t count) {
    if (count > kMaxIoSize) return -EINVAL;
    if (!memory_.is_accessible(GuestAddress32{address}, count, GuestPermission::Write)) return -EFAULT;
    std::array<std::byte, 8192> buffer{};
    std::uint32_t copied = 0;
    while (copied < count) {
        const auto request = std::min<std::size_t>(buffer.size(), count - copied);
        const auto result = vfs_.read(fd, std::span<std::byte>{buffer.data(), request});
        if (result < 0) return copied == 0 ? errno_result() : static_cast<std::int32_t>(copied);
        if (result == 0) break;
        const auto destination = GuestAddress32{address + copied};
        if (!memory_.write(destination, std::span<const std::byte>{buffer.data(), static_cast<std::size_t>(result)})) return -EFAULT;
        copied += static_cast<std::uint32_t>(result);
        if (static_cast<std::size_t>(result) < request) break;
    }
    return static_cast<std::int32_t>(copied);
}

std::int32_t Arm32SyscallDispatcher::write_call(int fd, std::uint32_t address, std::uint32_t count) {
    if (count > kMaxIoSize) return -EINVAL;
    if (!memory_.is_accessible(GuestAddress32{address}, count, GuestPermission::Read)) return -EFAULT;
    std::array<std::byte, 8192> buffer{};
    std::uint32_t copied = 0;
    while (copied < count) {
        const auto request = std::min<std::size_t>(buffer.size(), count - copied);
        const auto source = GuestAddress32{address + copied};
        const auto view = std::span<std::byte>{buffer.data(), request};
        if (!memory_.read(source, view)) return copied == 0 ? -EFAULT : static_cast<std::int32_t>(copied);
        const auto result = vfs_.write(fd, std::span<const std::byte>{buffer.data(), request});
        if (result < 0) return copied == 0 ? errno_result() : static_cast<std::int32_t>(copied);
        copied += static_cast<std::uint32_t>(result);
        if (static_cast<std::size_t>(result) < request) break;
    }
    return static_cast<std::int32_t>(copied);
}

std::int32_t Arm32SyscallDispatcher::getdents64_call(int fd, std::uint32_t address, std::uint32_t count) {
    if (count > kMaxIoSize) return -EINVAL;
    if (!memory_.is_accessible(GuestAddress32{address}, count, GuestPermission::Write)) return -EFAULT;
    std::vector<std::byte> buffer;
    try {
        buffer.resize(count);
    } catch (...) {
        return -ENOMEM;
    }
    const auto result = vfs_.getdents64(fd, buffer);
    if (result < 0) return errno_result();
    if (result > 0 && !memory_.write(GuestAddress32{address}, std::span<const std::byte>{buffer.data(), static_cast<std::size_t>(result)})) return -EFAULT;
    return static_cast<std::int32_t>(result);
}

std::int32_t Arm32SyscallDispatcher::getcwd_call(std::uint32_t address, std::uint32_t size) {
    const auto cwd = vfs_.guest_cwd();
    if (size <= cwd.size()) return -ERANGE;
    const auto count = cwd.size() + 1U;
    if (!memory_.is_accessible(GuestAddress32{address}, count, GuestPermission::Write)) return -EFAULT;
    std::vector<std::byte> bytes(count, std::byte{0});
    for (std::size_t index = 0; index < cwd.size(); ++index) bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(cwd[index]));
    return memory_.write(GuestAddress32{address}, bytes) ? static_cast<std::int32_t>(count) : -EFAULT;
}

std::int32_t Arm32SyscallDispatcher::copy_to_guest(std::uint32_t address, const void* input, std::size_t size) {
    if (input == nullptr && size != 0) return -EFAULT;
    const auto* bytes = static_cast<const std::byte*>(input);
    return memory_.write(GuestAddress32{address}, std::span<const std::byte>{bytes, size}) ? 0 : -EFAULT;
}

std::int32_t Arm32SyscallDispatcher::errno_result() const noexcept {
    return -static_cast<std::int32_t>(errno == 0 ? EIO : errno);
}

void Arm32SyscallDispatcher::set_result(GuestCpuState32& state, std::int32_t result) const noexcept {
    state.r[0] = std::bit_cast<std::uint32_t>(result);
}

}  // namespace retrobridge::runtime
