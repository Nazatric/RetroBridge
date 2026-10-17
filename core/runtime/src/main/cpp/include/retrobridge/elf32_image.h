#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace retrobridge::runtime {

enum class ElfDiagnosticCode {
    FileTooSmall,
    BadMagic,
    UnsupportedClass,
    UnsupportedByteOrder,
    UnsupportedMachine,
    UnsupportedFileType,
    InvalidHeader,
    InvalidProgramHeaderTable,
    InvalidSegment,
    MissingLoadSegment,
    InvalidDynamicSection,
    MissingDynamicStringTable,
    InvalidNeededLibraryName,
    InvalidLoadBias,
    MappingFailed,
    InvalidDynamicSymbolTable,
    InvalidHashTable,
    InvalidRelocationTable,
    UnsupportedRelocation,
    UndefinedSymbol,
    InvalidRelocationTarget,
    UnsupportedDynamicFeature,
};

struct ElfDiagnostic final {
    ElfDiagnosticCode code;
    std::string source;
    std::string package_name;
    std::string detail;

    [[nodiscard]] std::string format() const;
};

struct ElfSegment32 final {
    std::uint32_t type = 0;
    std::uint32_t file_offset = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t file_size = 0;
    std::uint32_t memory_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t alignment = 0;
};

/**
 * Validated ELF32/EM_ARM metadata only. This class does not map segments, relocate symbols,
 * resolve dependencies, or execute guest code.
 */
class Elf32Image final {
public:
    [[nodiscard]] static std::variant<Elf32Image, ElfDiagnostic> parse(
        std::span<const std::byte> file,
        std::string source = {},
        std::string package_name = {});

    [[nodiscard]] std::uint16_t type() const noexcept { return type_; }
    [[nodiscard]] std::uint32_t entry_point() const noexcept { return entry_point_; }
    [[nodiscard]] const std::vector<ElfSegment32>& segments() const noexcept { return segments_; }
    [[nodiscard]] const std::vector<std::string>& needed_libraries() const noexcept { return needed_libraries_; }
    [[nodiscard]] const std::optional<std::string>& soname() const noexcept { return soname_; }
    [[nodiscard]] std::size_t load_segment_count() const noexcept;

private:
    std::uint16_t type_ = 0;
    std::uint32_t entry_point_ = 0;
    std::vector<ElfSegment32> segments_;
    std::vector<std::string> needed_libraries_;
    std::optional<std::string> soname_;
};

}  // namespace retrobridge::runtime
