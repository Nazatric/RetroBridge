#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "native_vfs.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** Linux ARM EABI SVC dispatcher. Unsupported calls fail with -ENOSYS instead of falling through. */
class Arm32SyscallDispatcher final {
public:
    Arm32SyscallDispatcher(GuestMemory& memory, GuestHeap32& heap, NativeVfs& vfs) noexcept;

    [[nodiscard]] GuestHookResult handle(
        GuestCpuState32& state,
        std::uint32_t svc_immediate,
        GuestMemory& memory);
    [[nodiscard]] GuestSvcHandler as_handler();

private:
    struct Mapping final {
        std::uint32_t base = 0;
        std::size_t size = 0;
        GuestPermission permissions = GuestPermission::None;
        int guest_fd = -1;
        std::uint64_t file_offset = 0;
        bool shared = false;
    };

    [[nodiscard]] std::optional<std::string> read_guest_string(std::uint32_t address, std::size_t maximum = 4096) const;
    [[nodiscard]] std::int32_t openat_call(std::int32_t dirfd, std::uint32_t path, int flags, unsigned mode);
    [[nodiscard]] std::int32_t stat_call(std::string_view path, std::uint32_t output, bool no_follow);
    [[nodiscard]] std::int32_t fstat_call(int fd, std::uint32_t output);
    [[nodiscard]] std::int32_t write_stat64(const struct stat& status, std::uint32_t output);
    [[nodiscard]] std::int32_t mmap2_call(GuestCpuState32& state);
    [[nodiscard]] std::int32_t munmap_call(std::uint32_t address, std::uint32_t length);
    [[nodiscard]] std::int32_t mprotect_call(std::uint32_t address, std::uint32_t length, std::uint32_t protection);
    [[nodiscard]] std::int32_t brk_call(std::uint32_t requested);
    [[nodiscard]] std::int32_t read_call(int fd, std::uint32_t address, std::uint32_t count);
    [[nodiscard]] std::int32_t write_call(int fd, std::uint32_t address, std::uint32_t count);
    [[nodiscard]] std::int32_t getdents64_call(int fd, std::uint32_t address, std::uint32_t count);
    [[nodiscard]] std::int32_t getcwd_call(std::uint32_t address, std::uint32_t size);
    [[nodiscard]] std::int32_t copy_to_guest(std::uint32_t address, const void* input, std::size_t size);
    [[nodiscard]] std::int32_t errno_result() const noexcept;
    void set_result(GuestCpuState32& state, std::int32_t result) const noexcept;

    GuestMemory& memory_;
    GuestHeap32& heap_;
    NativeVfs& vfs_;
    mutable std::mutex mutex_;
    std::map<std::uint32_t, Mapping> mappings_;
    std::uint32_t next_mmap_address_ = 0x60000000U;
    std::uint32_t brk_base_ = 0x30000000U;
    std::uint32_t brk_current_ = 0x30000000U;
    std::uint32_t brk_mapped_end_ = 0x30000000U;
    std::uint32_t synthetic_pid_ = 10000U;
};

}  // namespace retrobridge::runtime
