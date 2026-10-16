#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace retrobridge::runtime {

/** Translates supported Android app-private guest paths below one isolated application root. */
class NativeVfsPathTranslator final {
public:
    NativeVfsPathTranslator(std::filesystem::path app_root, std::string package_name);

    [[nodiscard]] bool valid() const noexcept { return valid_; }
    [[nodiscard]] const std::filesystem::path& app_root() const noexcept { return app_root_; }
    [[nodiscard]] const std::string& package_name() const noexcept { return package_name_; }
    [[nodiscard]] std::string guest_cwd() const;

    [[nodiscard]] std::optional<std::filesystem::path> translate(
        std::string_view guest_path,
        std::string* diagnostic = nullptr) const;
    [[nodiscard]] std::optional<std::filesystem::path> translate_relative(
        std::string_view guest_path,
        std::string_view guest_directory,
        std::string* diagnostic = nullptr) const;
    [[nodiscard]] std::optional<std::string> relative_to_app_root(
        const std::filesystem::path& host_path) const;

private:
    [[nodiscard]] std::optional<std::filesystem::path> translate_absolute(
        std::string_view guest_path,
        std::string* diagnostic) const;
    [[nodiscard]] bool reject_symlinks(const std::filesystem::path& candidate) const;

    std::filesystem::path app_root_;
    std::string package_name_;
    bool valid_ = false;
};

}  // namespace retrobridge::runtime
