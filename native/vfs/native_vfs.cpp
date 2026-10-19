#include "native_vfs.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr int kAtFdcwd = -100;
constexpr int kGuestLargeFile = 0x8000;
constexpr std::size_t kDirentNameOffset = 19;

[[nodiscard]] std::vector<std::string> split_relative(const std::string& value) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= value.size()) {
        const auto end = value.find('/', start);
        const auto count = (end == std::string::npos ? value.size() : end) - start;
        if (count == 0) {
            errno = EACCES;
            return {};
        }
        parts.push_back(value.substr(start, count));
        if (end == std::string::npos) break;
        start = end + 1U;
    }
    return parts;
}

void store_little(std::span<std::byte> output, std::size_t offset, std::uint64_t value, std::size_t count) noexcept {
    for (std::size_t index = 0; index < count; ++index) {
        output[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

[[nodiscard]] std::string join_guest_path(std::string_view directory, std::string_view path) {
    if (!path.empty() && path.front() == '/') return std::string(path);
    std::string result(directory);
    if (result.empty() || result.front() != '/') {
        errno = EACCES;
        return {};
    }
    if (result.back() != '/') result.push_back('/');
    result.append(path);
    return result;
}

}  // namespace

NativeVfs::NativeVfs(std::filesystem::path app_root, std::string package_name)
    : translator_(std::move(app_root), std::move(package_name)) {
    if (!translator_.valid()) {
        errno = EINVAL;
        return;
    }
    root_fd_ = ::open(translator_.app_root().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

NativeVfs::~NativeVfs() {
    std::lock_guard lock(mutex_);
    for (auto& [guest_fd, descriptor] : descriptors_) {
        (void)guest_fd;
        if (descriptor.directory != nullptr) (void)::closedir(descriptor.directory);
        if (descriptor.host_fd >= 0) (void)::close(descriptor.host_fd);
    }
    descriptors_.clear();
    if (root_fd_ >= 0) (void)::close(root_fd_);
}

bool NativeVfs::available() const noexcept {
    return translator_.valid() && root_fd_ >= 0;
}

int NativeVfs::open(std::string_view guest_path, int guest_flags, unsigned mode) {
    return openat(kAtFdcwd, guest_path, guest_flags, mode);
}

int NativeVfs::openat(int guest_dirfd, std::string_view guest_path, int guest_flags, unsigned mode) {
    std::lock_guard lock(mutex_);
    return openat_locked(guest_dirfd, guest_path, guest_flags, mode);
}

int NativeVfs::close(int guest_fd) noexcept {
    std::lock_guard lock(mutex_);
    const auto found = descriptors_.find(guest_fd);
    if (found == descriptors_.end()) {
        errno = EBADF;
        return -1;
    }
    auto descriptor = found->second;
    descriptors_.erase(found);
    int result = 0;
    if (descriptor.directory != nullptr) result = ::closedir(descriptor.directory);
    if (descriptor.host_fd >= 0 && ::close(descriptor.host_fd) != 0) result = -1;
    return result;
}

long NativeVfs::read(int guest_fd, std::span<std::byte> output) noexcept {
    std::lock_guard lock(mutex_);
    if (guest_fd == 0) return static_cast<long>(::read(STDIN_FILENO, output.data(), output.size()));
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        errno = EBADF;
        return -1;
    }
    const auto result = ::read(descriptor->host_fd, output.data(), output.size());
    return static_cast<long>(result);
}

long NativeVfs::write(int guest_fd, std::span<const std::byte> input) noexcept {
    std::lock_guard lock(mutex_);
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        if (guest_fd == 1 || guest_fd == 2) {
            const auto host_fd = guest_fd;
            return static_cast<long>(::write(host_fd, input.data(), input.size()));
        }
        errno = EBADF;
        return -1;
    }
    return static_cast<long>(::write(descriptor->host_fd, input.data(), input.size()));
}

long NativeVfs::pread(int guest_fd, std::span<std::byte> output, long long offset) noexcept {
    if (offset < 0 || static_cast<unsigned long long>(offset)
            > static_cast<unsigned long long>(std::numeric_limits<off_t>::max())) {
        errno = EINVAL;
        return -1;
    }
    std::lock_guard lock(mutex_);
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        errno = EBADF;
        return -1;
    }
    return static_cast<long>(::pread(descriptor->host_fd, output.data(), output.size(), static_cast<off_t>(offset)));
}

long NativeVfs::pwrite(int guest_fd, std::span<const std::byte> input, long long offset) noexcept {
    if (offset < 0 || static_cast<unsigned long long>(offset)
            > static_cast<unsigned long long>(std::numeric_limits<off_t>::max())) {
        errno = EINVAL;
        return -1;
    }
    std::lock_guard lock(mutex_);
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        errno = EBADF;
        return -1;
    }
    return static_cast<long>(::pwrite(descriptor->host_fd, input.data(), input.size(), static_cast<off_t>(offset)));
}

long long NativeVfs::seek(int guest_fd, long long offset, int whence) noexcept {
    std::lock_guard lock(mutex_);
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        errno = EBADF;
        return -1;
    }
    const auto result = ::lseek(descriptor->host_fd, static_cast<off_t>(offset), whence);
    if (result == static_cast<off_t>(-1)) return -1;
    return static_cast<long long>(result);
}

int NativeVfs::fstat(int guest_fd, struct stat* output) noexcept {
    if (output == nullptr) {
        errno = EFAULT;
        return -1;
    }
    std::lock_guard lock(mutex_);
    const auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr) {
        errno = EBADF;
        return -1;
    }
    return ::fstat(descriptor->host_fd, output);
}

int NativeVfs::stat_path(std::string_view guest_path, struct stat* output, bool no_follow) {
    if (output == nullptr) {
        errno = EFAULT;
        return -1;
    }
    const auto parent = open_parent(guest_path);
    if (!parent.has_value()) return -1;
    const auto flags = no_follow ? AT_SYMLINK_NOFOLLOW : 0;
    const auto result = ::fstatat(parent->host_fd, parent->leaf.c_str(), output, flags);
    (void)::close(parent->host_fd);
    return result;
}

int NativeVfs::statat(int guest_dirfd, std::string_view guest_path, struct stat* output, int flags) {
    if (output == nullptr) {
        errno = EFAULT;
        return -1;
    }
    if (flags != 0 && flags != AT_SYMLINK_NOFOLLOW) {
        errno = EINVAL;
        return -1;
    }
    std::string absolute;
    {
        std::lock_guard lock(mutex_);
        std::string base = translator_.guest_cwd();
        if (guest_dirfd != kAtFdcwd) {
            const auto* descriptor = find_descriptor_locked(guest_dirfd);
            if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
                errno = EBADF;
                return -1;
            }
            base = descriptor->guest_path;
        }
        absolute = join_guest_path(base, guest_path);
        if (absolute.empty()) return -1;
    }
    const auto parent = open_parent(absolute);
    if (!parent.has_value()) return -1;
    const auto result = ::fstatat(parent->host_fd, parent->leaf.c_str(), output, flags);
    (void)::close(parent->host_fd);
    return result;
}

int NativeVfs::access(std::string_view guest_path, int mode) {
    return faccessat(kAtFdcwd, guest_path, mode, 0);
}

int NativeVfs::faccessat(int guest_dirfd, std::string_view guest_path, int mode, int flags) {
    if ((flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW)) != 0) {
        errno = EINVAL;
        return -1;
    }
    std::string absolute;
    {
        std::lock_guard lock(mutex_);
        std::string base = translator_.guest_cwd();
        if (guest_dirfd != kAtFdcwd) {
            const auto* descriptor = find_descriptor_locked(guest_dirfd);
            if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
                errno = EBADF;
                return -1;
            }
            base = descriptor->guest_path;
        }
        absolute = join_guest_path(base, guest_path);
        if (absolute.empty()) return -1;
    }
    const auto parent = open_parent(absolute);
    if (!parent.has_value()) return -1;
    const auto result = ::faccessat(parent->host_fd, parent->leaf.c_str(), mode, flags);
    (void)::close(parent->host_fd);
    return result;
}

int NativeVfs::mkdirat(int guest_dirfd, std::string_view guest_path, unsigned mode) {
    std::string absolute;
    {
        std::lock_guard lock(mutex_);
        std::string base = translator_.guest_cwd();
        if (guest_dirfd != kAtFdcwd) {
            const auto* descriptor = find_descriptor_locked(guest_dirfd);
            if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
                errno = EBADF;
                return -1;
            }
            base = descriptor->guest_path;
        }
        absolute = join_guest_path(base, guest_path);
        if (absolute.empty()) return -1;
    }
    const auto parent = open_parent(absolute);
    if (!parent.has_value()) return -1;
    const auto result = ::mkdirat(parent->host_fd, parent->leaf.c_str(), static_cast<mode_t>(mode));
    (void)::close(parent->host_fd);
    return result;
}

int NativeVfs::unlinkat(int guest_dirfd, std::string_view guest_path, int flags) {
    if (flags != 0 && flags != AT_REMOVEDIR) {
        errno = EINVAL;
        return -1;
    }
    std::string absolute;
    {
        std::lock_guard lock(mutex_);
        std::string base = translator_.guest_cwd();
        if (guest_dirfd != kAtFdcwd) {
            const auto* descriptor = find_descriptor_locked(guest_dirfd);
            if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
                errno = EBADF;
                return -1;
            }
            base = descriptor->guest_path;
        }
        absolute = join_guest_path(base, guest_path);
        if (absolute.empty()) return -1;
    }
    const auto parent = open_parent(absolute);
    if (!parent.has_value()) return -1;
    const auto result = ::unlinkat(parent->host_fd, parent->leaf.c_str(), flags);
    (void)::close(parent->host_fd);
    return result;
}

int NativeVfs::renameat(
    int old_guest_dirfd,
    std::string_view old_guest_path,
    int new_guest_dirfd,
    std::string_view new_guest_path) {
    std::string old_absolute;
    std::string new_absolute;
    {
        std::lock_guard lock(mutex_);
        const auto directory_for = [&](int guest_fd, std::string& output) -> bool {
            if (guest_fd == kAtFdcwd) {
                output = translator_.guest_cwd();
                return true;
            }
            const auto* descriptor = find_descriptor_locked(guest_fd);
            if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
                errno = EBADF;
                return false;
            }
            output = descriptor->guest_path;
            return true;
        };
        std::string old_base;
        std::string new_base;
        if (!directory_for(old_guest_dirfd, old_base) || !directory_for(new_guest_dirfd, new_base)) return -1;
        old_absolute = join_guest_path(old_base, old_guest_path);
        new_absolute = join_guest_path(new_base, new_guest_path);
        if (old_absolute.empty() || new_absolute.empty()) return -1;
    }
    const auto old_parent = open_parent(old_absolute);
    if (!old_parent.has_value()) return -1;
    const auto new_parent = open_parent(new_absolute);
    if (!new_parent.has_value()) {
        (void)::close(old_parent->host_fd);
        return -1;
    }
    const auto result = ::renameat(old_parent->host_fd, old_parent->leaf.c_str(),
        new_parent->host_fd, new_parent->leaf.c_str());
    (void)::close(old_parent->host_fd);
    (void)::close(new_parent->host_fd);
    return result;
}

long NativeVfs::getdents64(int guest_fd, std::span<std::byte> output) noexcept {
    std::lock_guard lock(mutex_);
    auto* descriptor = find_descriptor_locked(guest_fd);
    if (descriptor == nullptr || descriptor->directory == nullptr) {
        errno = EBADF;
        return -1;
    }
    std::size_t written = 0;
    while (written < output.size()) {
        errno = 0;
        const auto position = ::telldir(descriptor->directory);
        const auto* entry = ::readdir(descriptor->directory);
        if (entry == nullptr) {
            if (errno != 0) return written == 0 ? -1 : static_cast<long>(written);
            break;
        }
        const auto name_length = std::char_traits<char>::length(entry->d_name);
        const auto raw_length = kDirentNameOffset + name_length + 1U;
        const auto record_length = (raw_length + 7U) & ~std::size_t{7U};
        if (record_length > std::numeric_limits<std::uint16_t>::max()) {
            errno = EOVERFLOW;
            return written == 0 ? -1 : static_cast<long>(written);
        }
        if (record_length > output.size() - written) {
            ::seekdir(descriptor->directory, position);
            if (written == 0) {
                errno = EINVAL;
                return -1;
            }
            break;
        }
        auto record = output.subspan(written, record_length);
        std::fill(record.begin(), record.end(), std::byte{0});
        store_little(record, 0, static_cast<std::uint64_t>(entry->d_ino), 8);
        store_little(record, 8, static_cast<std::uint64_t>(::telldir(descriptor->directory)), 8);
        store_little(record, 16, record_length, 2);
        record[18] = static_cast<std::byte>(entry->d_type);
        for (std::size_t index = 0; index <= name_length; ++index) {
            record[kDirentNameOffset + index] = static_cast<std::byte>(static_cast<unsigned char>(entry->d_name[index]));
        }
        written += record_length;
    }
    return static_cast<long>(written);
}

std::string NativeVfs::guest_cwd() const {
    return translator_.guest_cwd();
}

std::optional<std::filesystem::path> NativeVfs::translate_path(
    std::string_view guest_path,
    std::string* diagnostic) const {
    return translator_.translate(guest_path, diagnostic);
}

std::optional<NativeVfs::Parent> NativeVfs::open_parent(std::string_view guest_path) const {
    if (root_fd_ < 0) {
        errno = EACCES;
        return std::nullopt;
    }
    std::string diagnostic;
    const auto host_path = translator_.translate(guest_path, &diagnostic);
    if (!host_path.has_value()) {
        errno = EACCES;
        return std::nullopt;
    }
    const auto relative = translator_.relative_to_app_root(*host_path);
    if (!relative.has_value() || relative->empty()) {
        errno = EACCES;
        return std::nullopt;
    }
    const auto components = split_relative(*relative);
    if (components.empty()) return std::nullopt;

    int current = ::dup(root_fd_);
    if (current < 0) return std::nullopt;
    for (std::size_t index = 0; index + 1U < components.size(); ++index) {
        const auto next = ::openat(current, components[index].c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        const auto saved_errno = errno;
        (void)::close(current);
        if (next < 0) {
            errno = saved_errno;
            return std::nullopt;
        }
        current = next;
    }
    return Parent{current, components.back()};
}

int NativeVfs::openat_locked(int guest_dirfd, std::string_view guest_path, int guest_flags, unsigned mode) {
    if (!available()) {
        errno = EACCES;
        return -1;
    }
    std::string base = translator_.guest_cwd();
    if (guest_dirfd != kAtFdcwd) {
        const auto* descriptor = find_descriptor_locked(guest_dirfd);
        if (descriptor == nullptr || descriptor->directory == nullptr || descriptor->guest_path.empty()) {
            errno = EBADF;
            return -1;
        }
        base = descriptor->guest_path;
    }
    const auto absolute = join_guest_path(base, guest_path);
    if (absolute.empty()) return -1;
    const auto parent = open_parent(absolute);
    if (!parent.has_value()) return -1;
    int host_flags = 0;
    if (translate_flags(guest_flags, host_flags) != 0) {
        (void)::close(parent->host_fd);
        return -1;
    }
    const auto host_fd = ::openat(parent->host_fd, parent->leaf.c_str(), host_flags,
        static_cast<mode_t>(mode));
    const auto saved_errno = errno;
    (void)::close(parent->host_fd);
    if (host_fd < 0) {
        errno = saved_errno;
        return -1;
    }

    struct stat status{};
    DIR* directory = nullptr;
    if (::fstat(host_fd, &status) == 0 && S_ISDIR(status.st_mode)) {
        const auto duplicate = ::dup(host_fd);
        if (duplicate >= 0) directory = ::fdopendir(duplicate);
        if (directory == nullptr && duplicate >= 0) (void)::close(duplicate);
    }
    const auto guest_fd = allocate_guest_fd_locked(host_fd, directory, absolute);
    if (guest_fd < 0) {
        const auto error = errno;
        if (directory != nullptr) (void)::closedir(directory);
        (void)::close(host_fd);
        errno = error;
    }
    return guest_fd;
}

int NativeVfs::allocate_guest_fd_locked(int host_fd, DIR* directory, std::string guest_path) {
    if (next_guest_fd_ < 3 || next_guest_fd_ == std::numeric_limits<int>::max()) {
        errno = EMFILE;
        return -1;
    }
    const auto guest_fd = next_guest_fd_++;
    try {
        descriptors_.emplace(guest_fd, Descriptor{host_fd, directory, std::move(guest_path)});
    } catch (...) {
        errno = ENOMEM;
        return -1;
    }
    return guest_fd;
}

NativeVfs::Descriptor* NativeVfs::find_descriptor_locked(int guest_fd) noexcept {
    const auto found = descriptors_.find(guest_fd);
    return found == descriptors_.end() ? nullptr : &found->second;
}

const NativeVfs::Descriptor* NativeVfs::find_descriptor_locked(int guest_fd) const noexcept {
    const auto found = descriptors_.find(guest_fd);
    return found == descriptors_.end() ? nullptr : &found->second;
}

int NativeVfs::translate_flags(int guest_flags, int& host_flags) noexcept {
    const auto flags = guest_flags & ~kGuestLargeFile;
    int supported = O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | O_EXCL | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
#ifdef O_NONBLOCK
    supported |= O_NONBLOCK;
#endif
#ifdef O_SYNC
    supported |= O_SYNC;
#endif
    if ((flags & ~supported) != 0 || (flags & O_ACCMODE) == 3) {
        errno = EINVAL;
        return -1;
    }
    host_flags = flags | O_CLOEXEC | O_NOFOLLOW;
    return 0;
}

}  // namespace retrobridge::runtime
