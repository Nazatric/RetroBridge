#pragma once

#include "native_vfs_path.h"

#include <cstddef>
#include <dirent.h>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>

namespace retrobridge::runtime {

/** POSIX-backed per-guest descriptor table; every path is opened beneath one app root. */
class NativeVfs final {
public:
    NativeVfs(std::filesystem::path app_root, std::string package_name);
    ~NativeVfs();

    NativeVfs(const NativeVfs&) = delete;
    NativeVfs& operator=(const NativeVfs&) = delete;

    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] int open(std::string_view guest_path, int guest_flags, unsigned mode = 0600);
    [[nodiscard]] int openat(int guest_dirfd, std::string_view guest_path, int guest_flags, unsigned mode = 0600);
    [[nodiscard]] int close(int guest_fd) noexcept;
    [[nodiscard]] long read(int guest_fd, std::span<std::byte> output) noexcept;
    [[nodiscard]] long write(int guest_fd, std::span<const std::byte> input) noexcept;
    [[nodiscard]] long pread(int guest_fd, std::span<std::byte> output, long long offset) noexcept;
    [[nodiscard]] long pwrite(int guest_fd, std::span<const std::byte> input, long long offset) noexcept;
    [[nodiscard]] long long seek(int guest_fd, long long offset, int whence) noexcept;
    [[nodiscard]] int fstat(int guest_fd, struct stat* output) noexcept;
    [[nodiscard]] int stat_path(std::string_view guest_path, struct stat* output, bool no_follow = true);
    [[nodiscard]] int statat(int guest_dirfd, std::string_view guest_path, struct stat* output, int flags);
    [[nodiscard]] int access(std::string_view guest_path, int mode);
    [[nodiscard]] int faccessat(int guest_dirfd, std::string_view guest_path, int mode, int flags);
    [[nodiscard]] int mkdirat(int guest_dirfd, std::string_view guest_path, unsigned mode);
    [[nodiscard]] int unlinkat(int guest_dirfd, std::string_view guest_path, int flags);
    [[nodiscard]] int renameat(
        int old_guest_dirfd,
        std::string_view old_guest_path,
        int new_guest_dirfd,
        std::string_view new_guest_path);
    [[nodiscard]] long getdents64(int guest_fd, std::span<std::byte> output) noexcept;
    [[nodiscard]] std::string guest_cwd() const;
    [[nodiscard]] std::optional<std::filesystem::path> translate_path(
        std::string_view guest_path,
        std::string* diagnostic = nullptr) const;

private:
    struct Descriptor final {
        int host_fd = -1;
        DIR* directory = nullptr;
        std::string guest_path;
    };
    struct Parent final {
        int host_fd = -1;
        std::string leaf;
    };

    [[nodiscard]] std::optional<Parent> open_parent(std::string_view guest_path) const;
    [[nodiscard]] int openat_locked(int guest_dirfd, std::string_view guest_path, int guest_flags, unsigned mode);
    [[nodiscard]] int allocate_guest_fd_locked(int host_fd, DIR* directory, std::string guest_path);
    [[nodiscard]] Descriptor* find_descriptor_locked(int guest_fd) noexcept;
    [[nodiscard]] const Descriptor* find_descriptor_locked(int guest_fd) const noexcept;
    [[nodiscard]] static int translate_flags(int guest_flags, int& host_flags) noexcept;

    NativeVfsPathTranslator translator_;
    mutable std::mutex mutex_;
    std::map<int, Descriptor> descriptors_;
    int root_fd_ = -1;
    int next_guest_fd_ = 3;
};

}  // namespace retrobridge::runtime
