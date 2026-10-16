#include "native_vfs_path.h"

#include <array>
#include <cctype>
#include <system_error>
#include <utility>
#include <vector>

namespace retrobridge::runtime {
namespace {

[[nodiscard]] bool valid_package_name(std::string_view package_name) noexcept {
    std::size_t segment_start = 0;
    unsigned segments = 0;
    for (std::size_t index = 0; index <= package_name.size(); ++index) {
        if (index != package_name.size() && package_name[index] != '.') continue;
        if (index == segment_start) return false;
        const auto first = static_cast<unsigned char>(package_name[segment_start]);
        if (!(std::isalpha(first) || first == '_')) return false;
        for (std::size_t character = segment_start + 1U; character < index; ++character) {
            const auto value = static_cast<unsigned char>(package_name[character]);
            if (!(std::isalnum(value) || value == '_')) return false;
        }
        ++segments;
        segment_start = index + 1U;
    }
    return segments >= 2;
}

[[nodiscard]] bool has_prefix(std::string_view path, std::string_view prefix) noexcept {
    return path == prefix || (path.size() > prefix.size()
        && path.substr(0, prefix.size()) == prefix && path[prefix.size()] == '/');
}

}  // namespace

NativeVfsPathTranslator::NativeVfsPathTranslator(
    std::filesystem::path app_root,
    std::string package_name)
    : package_name_(std::move(package_name)) {
    if (!valid_package_name(package_name_)) return;
    try {
        app_root_ = std::filesystem::absolute(std::move(app_root)).lexically_normal();
        valid_ = app_root_.is_absolute() && app_root_ != app_root_.root_path();
    } catch (const std::filesystem::filesystem_error&) {
        valid_ = false;
    }
}

std::string NativeVfsPathTranslator::guest_cwd() const {
    return "/data/data/" + package_name_ + "/files";
}

std::optional<std::filesystem::path> NativeVfsPathTranslator::translate(
    std::string_view guest_path,
    std::string* diagnostic) const {
    return translate_absolute(guest_path, diagnostic);
}

std::optional<std::filesystem::path> NativeVfsPathTranslator::translate_relative(
    std::string_view guest_path,
    std::string_view guest_directory,
    std::string* diagnostic) const {
    if (!guest_path.empty() && guest_path.front() == '/') return translate_absolute(guest_path, diagnostic);
    if (guest_path.empty() || guest_path.size() > 4096 || guest_directory.empty()
        || guest_directory.front() != '/' || guest_path.find('\0') != std::string_view::npos
        || guest_path.find('\\') != std::string_view::npos) {
        if (diagnostic != nullptr) *diagnostic = "relative guest path or working directory is invalid";
        return std::nullopt;
    }
    std::string combined(guest_directory);
    if (combined.back() != '/') combined.push_back('/');
    combined.append(guest_path);
    return translate_absolute(combined, diagnostic);
}

std::optional<std::string> NativeVfsPathTranslator::relative_to_app_root(
    const std::filesystem::path& host_path) const {
    if (!valid_) return std::nullopt;
    const auto normalized = host_path.lexically_normal();
    const auto relative = normalized.lexically_relative(app_root_);
    if (relative.empty() || relative.is_absolute()) {
        if (normalized == app_root_) return std::string{};
        return std::nullopt;
    }
    for (const auto& part : relative) {
        if (part == ".." || part == ".") return std::nullopt;
    }
    return relative.generic_string();
}

std::optional<std::filesystem::path> NativeVfsPathTranslator::translate_absolute(
    std::string_view guest_path,
    std::string* diagnostic) const {
    const auto fail = [&](const char* message) -> std::optional<std::filesystem::path> {
        if (diagnostic != nullptr) *diagnostic = message;
        return std::nullopt;
    };
    if (!valid_) return fail("VFS app root or package name is invalid");
    if (guest_path.empty() || guest_path.size() > 4096 || guest_path.front() != '/') {
        return fail("guest path must be an absolute path within the supported VFS");
    }
    if (guest_path.find('\0') != std::string_view::npos || guest_path.find('\\') != std::string_view::npos) {
        return fail("guest path contains a forbidden NUL or backslash");
    }
    std::size_t segment_start = 1;
    for (std::size_t index = 1; index <= guest_path.size(); ++index) {
        if (index != guest_path.size() && guest_path[index] != '/') continue;
        const auto segment = guest_path.substr(segment_start, index - segment_start);
        if (segment.empty() || segment == "." || segment == "..") {
            return fail("guest path contains an empty, dot, or traversal component");
        }
        segment_start = index + 1U;
    }

    struct Mapping final {
        std::string prefix;
        std::filesystem::path destination;
    };
    const std::array mappings{
        Mapping{"/data/data/" + package_name_, "internal"},
        Mapping{"/data/user/0/" + package_name_, "internal"},
        Mapping{"/sdcard/Android/data/" + package_name_, "external/data"},
        Mapping{"/storage/emulated/0/Android/data/" + package_name_, "external/data"},
        Mapping{"/sdcard/Android/obb/" + package_name_, "obb"},
        Mapping{"/storage/emulated/0/Android/obb/" + package_name_, "obb"},
    };

    for (const auto& mapping : mappings) {
        if (!has_prefix(guest_path, mapping.prefix)) continue;
        auto candidate = app_root_ / mapping.destination;
        if (guest_path.size() > mapping.prefix.size()) {
            auto suffix = guest_path.substr(mapping.prefix.size() + 1U);
            std::size_t start = 0;
            for (std::size_t index = 0; index <= suffix.size(); ++index) {
                if (index != suffix.size() && suffix[index] != '/') continue;
                const auto segment = suffix.substr(start, index - start);
                if (segment.empty() || segment == "." || segment == "..") {
                    return fail("guest path contains an unsafe suffix component");
                }
                candidate /= std::string(segment);
                start = index + 1U;
            }
        }
        candidate = candidate.lexically_normal();
        if (!candidate.is_absolute() || !candidate.starts_with(app_root_)) {
            return fail("translated guest path escaped the application root");
        }
        if (!reject_symlinks(candidate)) return fail("guest path crosses a symbolic link");
        return candidate;
    }
    return fail("guest path is outside supported app-private roots");
}

bool NativeVfsPathTranslator::reject_symlinks(const std::filesystem::path& candidate) const {
    std::error_code error;
    auto current = app_root_;
    const auto root_status = std::filesystem::symlink_status(current, error);
    if (!error && std::filesystem::is_symlink(root_status)) return false;
    if (error && error != std::errc::no_such_file_or_directory) return false;
    error.clear();

    const auto relative = candidate.lexically_relative(app_root_);
    if (relative.empty() && candidate != app_root_) return false;
    for (const auto& component : relative) {
        if (component == "." || component == "..") return false;
        current /= component;
        const auto status = std::filesystem::symlink_status(current, error);
        if (!error && std::filesystem::is_symlink(status)) return false;
        if (error && error != std::errc::no_such_file_or_directory) return false;
        error.clear();
    }
    return true;
}

}  // namespace retrobridge::runtime
