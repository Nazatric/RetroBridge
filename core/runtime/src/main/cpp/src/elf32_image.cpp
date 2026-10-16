#include "retrobridge/elf32_image.h"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::size_t kElfHeaderSize = 52;
constexpr std::size_t kProgramHeaderSize = 32;
constexpr std::size_t kDynamicEntrySize = 8;
constexpr std::uint8_t kElfClass32 = 1;
constexpr std::uint8_t kElfDataLittleEndian = 1;
constexpr std::uint32_t kElfVersionCurrent = 1;
constexpr std::uint16_t kMachineArm = 40;
constexpr std::uint16_t kTypeExecutable = 2;
constexpr std::uint16_t kTypeSharedObject = 3;
constexpr std::uint32_t kProgramLoad = 1;
constexpr std::uint32_t kProgramDynamic = 2;
constexpr std::uint32_t kMaximumDynamicEntries = 65'536U;
constexpr std::uint32_t kDynamicNull = 0;
constexpr std::uint32_t kDynamicNeeded = 1;
constexpr std::uint32_t kDynamicStringTable = 5;
constexpr std::uint32_t kDynamicStringSize = 10;

[[nodiscard]] bool range_fits(std::size_t total, std::uint64_t offset, std::uint64_t length) noexcept {
    return offset <= total && length <= static_cast<std::uint64_t>(total) - offset;
}

[[nodiscard]] std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    const auto low = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto high = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    return static_cast<std::uint16_t>(low | (static_cast<std::uint16_t>(high) << 8));
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    const auto b0 = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto b1 = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    const auto b2 = std::to_integer<std::uint8_t>(bytes[offset + 2]);
    const auto b3 = std::to_integer<std::uint8_t>(bytes[offset + 3]);
    return static_cast<std::uint32_t>(b0)
        | (static_cast<std::uint32_t>(b1) << 8)
        | (static_cast<std::uint32_t>(b2) << 16)
        | (static_cast<std::uint32_t>(b3) << 24);
}

[[nodiscard]] std::string_view code_name(ElfDiagnosticCode code) noexcept {
    switch (code) {
        case ElfDiagnosticCode::FileTooSmall: return "file-too-small";
        case ElfDiagnosticCode::BadMagic: return "bad-magic";
        case ElfDiagnosticCode::UnsupportedClass: return "unsupported-class";
        case ElfDiagnosticCode::UnsupportedByteOrder: return "unsupported-byte-order";
        case ElfDiagnosticCode::UnsupportedMachine: return "unsupported-machine";
        case ElfDiagnosticCode::UnsupportedFileType: return "unsupported-file-type";
        case ElfDiagnosticCode::InvalidHeader: return "invalid-header";
        case ElfDiagnosticCode::InvalidProgramHeaderTable: return "invalid-program-header-table";
        case ElfDiagnosticCode::InvalidSegment: return "invalid-segment";
        case ElfDiagnosticCode::MissingLoadSegment: return "missing-load-segment";
        case ElfDiagnosticCode::InvalidDynamicSection: return "invalid-dynamic-section";
        case ElfDiagnosticCode::MissingDynamicStringTable: return "missing-dynamic-string-table";
        case ElfDiagnosticCode::InvalidNeededLibraryName: return "invalid-needed-library-name";
        case ElfDiagnosticCode::InvalidLoadBias: return "invalid-load-bias";
        case ElfDiagnosticCode::MappingFailed: return "mapping-failed";
        case ElfDiagnosticCode::InvalidDynamicSymbolTable: return "invalid-dynamic-symbol-table";
        case ElfDiagnosticCode::InvalidHashTable: return "invalid-hash-table";
        case ElfDiagnosticCode::InvalidRelocationTable: return "invalid-relocation-table";
        case ElfDiagnosticCode::UnsupportedRelocation: return "unsupported-relocation";
        case ElfDiagnosticCode::UndefinedSymbol: return "undefined-symbol";
        case ElfDiagnosticCode::InvalidRelocationTarget: return "invalid-relocation-target";
        case ElfDiagnosticCode::UnsupportedDynamicFeature: return "unsupported-dynamic-feature";
    }
    return "unknown-elf-error";
}

}  // namespace

std::string ElfDiagnostic::format() const {
    std::string message = "ELF validation failed [" + std::string(code_name(code)) + "]";
    if (!package_name.empty()) message += " package=" + package_name;
    if (!source.empty()) message += " file=" + source;
    if (!detail.empty()) message += ": " + detail;
    return message;
}

std::variant<Elf32Image, ElfDiagnostic> Elf32Image::parse(
    std::span<const std::byte> file,
    std::string source,
    std::string package_name) {
    const auto fail = [&](ElfDiagnosticCode code, std::string detail) -> std::variant<Elf32Image, ElfDiagnostic> {
        return ElfDiagnostic{code, source, package_name, std::move(detail)};
    };

    if (file.size() < kElfHeaderSize) {
        return fail(ElfDiagnosticCode::FileTooSmall, "ELF32 header is truncated");
    }
    constexpr std::array<std::uint8_t, 4> magic{0x7f, 'E', 'L', 'F'};
    for (std::size_t index = 0; index < magic.size(); ++index) {
        if (std::to_integer<std::uint8_t>(file[index]) != magic[index]) {
            return fail(ElfDiagnosticCode::BadMagic, "ELF magic bytes do not match");
        }
    }
    if (std::to_integer<std::uint8_t>(file[4]) != kElfClass32) {
        return fail(ElfDiagnosticCode::UnsupportedClass, "expected ELFCLASS32");
    }
    if (std::to_integer<std::uint8_t>(file[5]) != kElfDataLittleEndian) {
        return fail(ElfDiagnosticCode::UnsupportedByteOrder, "only little-endian ARM ELF is supported");
    }
    if (std::to_integer<std::uint8_t>(file[6]) != kElfVersionCurrent || read_u32(file, 20) != kElfVersionCurrent) {
        return fail(ElfDiagnosticCode::InvalidHeader, "unsupported ELF version");
    }

    const auto type = read_u16(file, 16);
    if (type != kTypeExecutable && type != kTypeSharedObject) {
        return fail(ElfDiagnosticCode::UnsupportedFileType, "expected ET_EXEC or ET_DYN");
    }
    if (read_u16(file, 18) != kMachineArm) {
        return fail(ElfDiagnosticCode::UnsupportedMachine, "expected e_machine=EM_ARM (40)");
    }
    if (read_u16(file, 40) != kElfHeaderSize) {
        return fail(ElfDiagnosticCode::InvalidHeader, "unexpected e_ehsize");
    }

    const auto entry_point = read_u32(file, 24);
    const auto program_header_offset = read_u32(file, 28);
    const auto program_header_entry_size = read_u16(file, 42);
    const auto program_header_count = read_u16(file, 44);
    if (program_header_count == 0 || program_header_entry_size != kProgramHeaderSize) {
        return fail(ElfDiagnosticCode::InvalidProgramHeaderTable, "invalid ELF32 program-header dimensions");
    }
    const auto table_size = static_cast<std::uint64_t>(program_header_entry_size) * program_header_count;
    if (!range_fits(file.size(), program_header_offset, table_size)) {
        return fail(ElfDiagnosticCode::InvalidProgramHeaderTable, "program-header table extends past end of file");
    }

    Elf32Image image;
    image.type_ = type;
    image.entry_point_ = entry_point;
    std::optional<ElfSegment32> dynamic_segment;

    for (std::uint32_t index = 0; index < program_header_count; ++index) {
        const auto offset = static_cast<std::size_t>(program_header_offset)
            + static_cast<std::size_t>(index) * program_header_entry_size;
        ElfSegment32 segment{
            .type = read_u32(file, offset),
            .file_offset = read_u32(file, offset + 4),
            .virtual_address = read_u32(file, offset + 8),
            .file_size = read_u32(file, offset + 16),
            .memory_size = read_u32(file, offset + 20),
            .flags = read_u32(file, offset + 24),
            .alignment = read_u32(file, offset + 28),
        };

        if (!range_fits(file.size(), segment.file_offset, segment.file_size)) {
            return fail(ElfDiagnosticCode::InvalidSegment, "program segment data extends past end of file");
        }
        if (segment.type == kProgramLoad) {
            const auto virtual_end = static_cast<std::uint64_t>(segment.virtual_address) + segment.memory_size;
            if (segment.memory_size < segment.file_size || virtual_end > (std::uint64_t{1} << 32)) {
                return fail(ElfDiagnosticCode::InvalidSegment, "PT_LOAD has invalid file/memory size or guest address range");
            }
            if (segment.alignment > 1) {
                const bool power_of_two = (segment.alignment & (segment.alignment - 1)) == 0;
                if (!power_of_two || segment.file_offset % segment.alignment != segment.virtual_address % segment.alignment) {
                    return fail(ElfDiagnosticCode::InvalidSegment, "PT_LOAD alignment is invalid");
                }
            }
        }
        if (segment.type == kProgramDynamic) {
            if (dynamic_segment.has_value()) {
                return fail(ElfDiagnosticCode::InvalidDynamicSection, "multiple PT_DYNAMIC segments are not supported");
            }
            dynamic_segment = segment;
        }
        image.segments_.push_back(segment);
    }

    if (image.load_segment_count() == 0) {
        return fail(ElfDiagnosticCode::MissingLoadSegment, "ELF contains no PT_LOAD segments");
    }

    if (!dynamic_segment.has_value()) return image;
    const auto& dynamic = *dynamic_segment;
    if (dynamic.file_size % kDynamicEntrySize != 0 || dynamic.file_size > dynamic.memory_size
        || dynamic.file_size / kDynamicEntrySize > kMaximumDynamicEntries) {
        return fail(ElfDiagnosticCode::InvalidDynamicSection, "dynamic section has invalid size or entry count");
    }

    std::optional<std::uint32_t> string_table_address;
    std::optional<std::uint32_t> string_table_size;
    std::vector<std::uint32_t> needed_offsets;
    bool terminated = false;
    const auto dynamic_count = dynamic.file_size / kDynamicEntrySize;
    for (std::uint32_t index = 0; index < dynamic_count; ++index) {
        const auto offset = static_cast<std::size_t>(dynamic.file_offset)
            + static_cast<std::size_t>(index) * kDynamicEntrySize;
        const auto tag = read_u32(file, offset);
        const auto value = read_u32(file, offset + 4);
        if (tag == kDynamicNull) {
            terminated = true;
            break;
        }
        if (tag == kDynamicNeeded) needed_offsets.push_back(value);
        if (tag == kDynamicStringTable) string_table_address = value;
        if (tag == kDynamicStringSize) string_table_size = value;
    }
    if (!terminated) {
        return fail(ElfDiagnosticCode::InvalidDynamicSection, "PT_DYNAMIC has no DT_NULL terminator");
    }
    if (needed_offsets.empty()) return image;
    if (!string_table_address.has_value() || !string_table_size.has_value() || *string_table_size == 0) {
        return fail(ElfDiagnosticCode::MissingDynamicStringTable, "DT_NEEDED entries have no usable DT_STRTAB/DT_STRSZ");
    }

    std::optional<std::uint64_t> string_table_file_offset;
    for (const auto& segment : image.segments_) {
        if (segment.type != kProgramLoad || *string_table_address < segment.virtual_address) continue;
        const auto relative = static_cast<std::uint64_t>(*string_table_address) - segment.virtual_address;
        if (relative <= segment.file_size
            && *string_table_size <= static_cast<std::uint64_t>(segment.file_size) - relative) {
            string_table_file_offset = static_cast<std::uint64_t>(segment.file_offset) + relative;
            break;
        }
    }
    if (!string_table_file_offset.has_value()
        || !range_fits(file.size(), *string_table_file_offset, *string_table_size)) {
        return fail(ElfDiagnosticCode::MissingDynamicStringTable, "DT_STRTAB is not inside a file-backed PT_LOAD segment");
    }

    for (const auto name_offset : needed_offsets) {
        if (name_offset >= *string_table_size) {
            return fail(ElfDiagnosticCode::InvalidNeededLibraryName, "DT_NEEDED string offset exceeds DT_STRSZ");
        }
        const auto name_begin = static_cast<std::size_t>(*string_table_file_offset + name_offset);
        const auto available = static_cast<std::size_t>(*string_table_size - name_offset);
        auto name_end = name_begin;
        while (name_end < name_begin + available && file[name_end] != std::byte{0}) ++name_end;
        if (name_end == name_begin + available || name_end == name_begin) {
            return fail(ElfDiagnosticCode::InvalidNeededLibraryName, "DT_NEEDED string is empty or unterminated");
        }
        std::string name;
        name.reserve(name_end - name_begin);
        for (auto cursor = name_begin; cursor < name_end; ++cursor) {
            name.push_back(static_cast<char>(std::to_integer<unsigned char>(file[cursor])));
        }
        image.needed_libraries_.push_back(std::move(name));
    }

    return image;
}

std::size_t Elf32Image::load_segment_count() const noexcept {
    return static_cast<std::size_t>(std::count_if(segments_.begin(), segments_.end(), [](const ElfSegment32& segment) {
        return segment.type == kProgramLoad;
    }));
}

}  // namespace retrobridge::runtime
