#include "retrobridge/elf32_loader.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::uint32_t kProgramLoad = 1;
constexpr std::uint32_t kProgramDynamic = 2;
constexpr std::uint32_t kPfExecute = 1U;
constexpr std::uint32_t kPfWrite = 2U;
constexpr std::uint32_t kPfRead = 4U;
constexpr std::uint16_t kTypeExecutable = 2;
constexpr std::uint16_t kTypeSharedObject = 3;
constexpr std::uint32_t kPageSize = 4096;
constexpr std::uint32_t kDynamicNull = 0;
constexpr std::uint32_t kDynamicNeeded = 1;
constexpr std::uint32_t kDynamicPltRelSize = 2;
constexpr std::uint32_t kDynamicHash = 4;
constexpr std::uint32_t kDynamicStringTable = 5;
constexpr std::uint32_t kDynamicSymbolTable = 6;
constexpr std::uint32_t kDynamicRela = 7;
constexpr std::uint32_t kDynamicRelaSize = 8;
constexpr std::uint32_t kDynamicRelaEntry = 9;
constexpr std::uint32_t kDynamicStringSize = 10;
constexpr std::uint32_t kDynamicSymbolEntry = 11;
constexpr std::uint32_t kDynamicInit = 12;
constexpr std::uint32_t kDynamicFini = 13;
constexpr std::uint32_t kDynamicSoname = 14;
constexpr std::uint32_t kDynamicRel = 17;
constexpr std::uint32_t kDynamicRelSize = 18;
constexpr std::uint32_t kDynamicRelEntry = 19;
constexpr std::uint32_t kDynamicPltRel = 20;
constexpr std::uint32_t kDynamicJumpRel = 23;
constexpr std::uint32_t kDynamicInitArray = 25;
constexpr std::uint32_t kDynamicFiniArray = 26;
constexpr std::uint32_t kDynamicInitArraySize = 27;
constexpr std::uint32_t kDynamicFiniArraySize = 28;
constexpr std::uint32_t kDynamicRelrSize = 35;
constexpr std::uint32_t kDynamicRelr = 36;
constexpr std::uint32_t kDynamicRelrEntry = 37;
constexpr std::uint32_t kDynamicGnuHash = 0x6ffffef5U;
constexpr std::uint32_t kDynamicAndroidRel = 0x6000000fU;
constexpr std::uint32_t kDynamicAndroidRelSize = 0x60000010U;
constexpr std::uint32_t kDynamicAndroidRela = 0x60000011U;
constexpr std::uint32_t kDynamicAndroidRelaSize = 0x60000012U;
constexpr std::uint16_t kSectionUndefined = 0;
constexpr std::uint16_t kSectionAbsolute = 0xfff1;
constexpr std::uint8_t kBindingLocal = 0;
constexpr std::uint8_t kBindingGlobal = 1;
constexpr std::uint8_t kBindingWeak = 2;
constexpr std::uint8_t kBindingGnuUnique = 10;
constexpr std::uint8_t kVisibilityInternal = 1;
constexpr std::uint8_t kVisibilityHidden = 2;
constexpr std::uint8_t kSymbolTypeIfunc = 10;
constexpr std::uint32_t kMaximumDynamicTableBytes = 64U * 1024U * 1024U;
constexpr std::uint32_t kMaximumDynamicEntries = 65'536U;

struct DynamicEntry final {
    std::uint32_t tag;
    std::uint32_t value;
};

[[nodiscard]] bool range_fits(std::size_t total, std::uint64_t offset, std::uint64_t length) noexcept {
    return offset <= total && length <= static_cast<std::uint64_t>(total) - offset;
}

[[nodiscard]] std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    const auto low = std::to_integer<std::uint8_t>(bytes[offset]);
    const auto high = std::to_integer<std::uint8_t>(bytes[offset + 1]);
    return static_cast<std::uint16_t>(low | (static_cast<std::uint16_t>(high) << 8U));
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + index])) << (8U * index);
    }
    return value;
}

void write_u16(std::span<std::byte> bytes, std::size_t offset, std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::byte>(value & 0xffU);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void write_u32(std::span<std::byte> bytes, std::size_t offset, std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (8U * index)) & 0xffU);
    }
}

[[nodiscard]] std::int64_t sign_extend(std::uint32_t value, unsigned bit_count) noexcept {
    const auto range = std::uint64_t{1} << bit_count;
    const auto sign_bit = range >> 1U;
    const auto normalized = static_cast<std::uint64_t>(value) & (range - 1U);
    if ((normalized & sign_bit) == 0) return static_cast<std::int64_t>(normalized);
    return static_cast<std::int64_t>(normalized) - static_cast<std::int64_t>(range);
}

[[nodiscard]] std::optional<std::size_t> file_offset_for_vaddr(
    const Elf32Image& image,
    std::uint32_t address,
    std::uint64_t size,
    std::size_t file_size) noexcept {
    for (const auto& segment : image.segments()) {
        if (segment.type != kProgramLoad || address < segment.virtual_address) continue;
        const auto relative = static_cast<std::uint64_t>(address) - segment.virtual_address;
        if (relative > segment.file_size || size > static_cast<std::uint64_t>(segment.file_size) - relative) continue;
        const auto offset = static_cast<std::uint64_t>(segment.file_offset) + relative;
        if (range_fits(file_size, offset, size)) return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint32_t> add_load_bias(
    std::uint32_t load_bias,
    std::uint32_t value) noexcept {
    const auto result = static_cast<std::uint64_t>(load_bias) + value;
    if (result > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return static_cast<std::uint32_t>(result);
}

[[nodiscard]] GuestPermission segment_permissions(std::uint32_t flags) noexcept {
    auto result = GuestPermission::None;
    if ((flags & kPfRead) != 0) result = result | GuestPermission::Read;
    if ((flags & kPfWrite) != 0) result = result | GuestPermission::Write;
    if ((flags & kPfExecute) != 0) result = result | GuestPermission::Execute;
    return result;
}

[[nodiscard]] std::optional<std::uint32_t> dynamic_value(
    const std::map<std::uint32_t, std::vector<std::uint32_t>>& tags,
    std::uint32_t tag) noexcept {
    const auto found = tags.find(tag);
    if (found == tags.end() || found->second.empty()) return std::nullopt;
    return found->second.back();
}

[[nodiscard]] std::uint32_t elf_hash(std::string_view name) noexcept {
    std::uint32_t hash = 0;
    for (const auto character : name) {
        hash = (hash << 4U) + static_cast<unsigned char>(character);
        const auto high = hash & 0xf0000000U;
        if (high != 0) hash ^= high >> 24U;
        hash &= ~high;
    }
    return hash;
}

[[nodiscard]] std::uint32_t gnu_hash(std::string_view name) noexcept {
    std::uint32_t hash = 5381U;
    for (const auto character : name) {
        hash = hash * 33U + static_cast<unsigned char>(character);
    }
    return hash;
}

[[nodiscard]] std::optional<std::string> string_at(
    std::span<const std::byte> file,
    std::size_t string_table_offset,
    std::uint32_t string_table_size,
    std::uint32_t name_offset) {
    if (name_offset >= string_table_size
        || !range_fits(file.size(), string_table_offset, string_table_size)) return std::nullopt;
    const auto begin = string_table_offset + name_offset;
    const auto end_limit = string_table_offset + string_table_size;
    auto end = begin;
    while (end < end_limit && file[end] != std::byte{0}) ++end;
    if (end == end_limit) return std::nullopt;
    std::string result;
    result.reserve(end - begin);
    for (auto cursor = begin; cursor < end; ++cursor) {
        result.push_back(static_cast<char>(std::to_integer<unsigned char>(file[cursor])));
    }
    return result;
}

[[nodiscard]] std::optional<std::uint32_t> read_runtime_u32(
    const GuestMemory& memory,
    std::uint32_t address) noexcept {
    std::array<std::byte, 4> bytes{};
    if (!memory.loader_read(GuestAddress32{address}, bytes)) return std::nullopt;
    return read_u32(bytes, 0);
}

[[nodiscard]] bool write_runtime_u32(GuestMemory& memory, std::uint32_t address, std::uint32_t value) noexcept {
    std::array<std::byte, 4> bytes{};
    write_u32(bytes, 0, value);
    return memory.loader_write(GuestAddress32{address}, bytes);
}

[[nodiscard]] std::optional<std::uint16_t> read_runtime_u16(
    const GuestMemory& memory,
    std::uint32_t address) noexcept {
    std::array<std::byte, 2> bytes{};
    if (!memory.loader_read(GuestAddress32{address}, bytes)) return std::nullopt;
    return read_u16(bytes, 0);
}

[[nodiscard]] bool write_runtime_u16(GuestMemory& memory, std::uint32_t address, std::uint16_t value) noexcept {
    std::array<std::byte, 2> bytes{};
    write_u16(bytes, 0, value);
    return memory.loader_write(GuestAddress32{address}, bytes);
}

[[nodiscard]] std::int64_t decode_arm_mov_immediate(std::uint32_t instruction) noexcept {
    const auto imm4 = (instruction >> 16U) & 0xfU;
    const auto imm12 = instruction & 0xfffU;
    return static_cast<std::int64_t>((imm4 << 12U) | imm12);
}

[[nodiscard]] std::uint32_t patch_arm_mov_immediate(std::uint32_t instruction, std::uint16_t immediate) noexcept {
    instruction &= ~((0xfU << 16U) | 0xfffU);
    instruction |= (static_cast<std::uint32_t>(immediate & 0xf000U) << 4U)
        | static_cast<std::uint32_t>(immediate & 0x0fffU);
    return instruction;
}

[[nodiscard]] std::uint16_t decode_thumb_mov_immediate(std::uint16_t first, std::uint16_t second) noexcept {
    const auto imm4 = first & 0x000fU;
    const auto i = (first >> 10U) & 1U;
    const auto imm3 = (second >> 12U) & 7U;
    const auto imm8 = second & 0x00ffU;
    return static_cast<std::uint16_t>((imm4 << 12U) | (i << 11U) | (imm3 << 8U) | imm8);
}

void patch_thumb_mov_immediate(std::uint16_t& first, std::uint16_t& second, std::uint16_t immediate) noexcept {
    first = static_cast<std::uint16_t>((first & 0xfbf0U)
        | (((immediate >> 11U) & 1U) << 10U)
        | ((immediate >> 12U) & 0xfU));
    second = static_cast<std::uint16_t>((second & 0x8f00U)
        | (((immediate >> 8U) & 7U) << 12U)
        | (immediate & 0xffU));
}

[[nodiscard]] bool is_thumb_movw(std::uint16_t first, std::uint16_t second, bool movt) noexcept {
    const auto expected = movt ? 0xf2c0U : 0xf240U;
    return (first & 0xfbf0U) == expected && (second & 0x8000U) == 0;
}

[[nodiscard]] bool parse_relocation_table(
    std::span<const std::byte> file,
    const Elf32Image& parsed,
    std::uint32_t address,
    std::uint32_t size,
    std::string table_name,
    std::size_t maximum_relocations,
    std::vector<Elf32Relocation>& output,
    std::set<std::pair<std::uint32_t, std::uint32_t>>& seen,
    std::optional<ElfDiagnostic>& error,
    const std::string& source,
    const std::string& package_name) {
    if (size == 0) return true;
    if (size % 8U != 0 || size > kMaximumDynamicTableBytes) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTable, source, package_name,
            table_name + " has an invalid byte count"};
        return false;
    }
    const auto offset = file_offset_for_vaddr(parsed, address, size, file.size());
    if (!offset.has_value()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTable, source, package_name,
            table_name + " is not contained in file-backed PT_LOAD memory"};
        return false;
    }
    for (std::uint32_t cursor = 0; cursor < size; cursor += 8U) {
        const auto relocation_offset = read_u32(file, *offset + cursor);
        const auto info = read_u32(file, *offset + cursor + 4U);
        if (seen.emplace(relocation_offset, info).second) {
            if (output.size() >= maximum_relocations) {
                error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTable, source, package_name,
                    "relocation count exceeds configured safety limit"};
                return false;
            }
            output.push_back(Elf32Relocation{
                relocation_offset,
                info >> 8U,
                static_cast<ArmRelocationType>(info & 0xffU),
                table_name,
            });
        }
    }
    return true;
}

[[nodiscard]] bool resolve_relocation_symbol(
    const Elf32LoadedImage& image,
    std::uint32_t symbol_index,
    const ExternalSymbolResolver& resolver,
    std::uint32_t& address,
    std::optional<ElfDiagnostic>& error) {
    if (symbol_index == 0) {
        address = 0;
        return true;
    }
    if (symbol_index >= image.symbols.size()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTable, image.name, image.package_name,
            "relocation symbol index exceeds dynamic symbol table"};
        return false;
    }
    const auto& symbol = image.symbols[symbol_index];
    if (symbol.type == kSymbolTypeIfunc) {
        error = ElfDiagnostic{ElfDiagnosticCode::UnsupportedDynamicFeature, image.name, image.package_name,
            "GNU indirect functions are not supported: " + symbol.name};
        return false;
    }

    if (symbol.section_index == kSectionUndefined) {
        if (resolver) {
            if (const auto resolved = resolver(symbol.name); resolved.has_value()) {
                address = *resolved;
                return true;
            }
        }
        if (symbol.binding == kBindingWeak) {
            address = 0;
            return true;
        }
        error = ElfDiagnostic{ElfDiagnosticCode::UndefinedSymbol, image.name, image.package_name,
            "unresolved guest symbol " + symbol.name + " referenced by " + image.name};
        return false;
    }
    if (symbol.section_index == kSectionAbsolute) {
        address = symbol.value;
        return true;
    }
    const auto loaded_address = add_load_bias(image.load_bias, symbol.value);
    if (!loaded_address.has_value()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSymbolTable, image.name, image.package_name,
            "symbol address overflows guest address space: " + symbol.name};
        return false;
    }
    address = *loaded_address;
    return true;
}

[[nodiscard]] bool relocate_arm_branch(
    const Elf32LoadedImage& image,
    GuestMemory& memory,
    std::uint32_t place,
    std::uint32_t symbol,
    ArmRelocationType type,
    std::optional<ElfDiagnostic>& error) {
    const auto instruction = read_runtime_u32(memory, place);
    if (!instruction.has_value()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "ARM branch relocation target is not mapped"};
        return false;
    }
    const auto addend = sign_extend((*instruction & 0x00ffffffU) << 2U, 26U);
    const auto is_call = type == ArmRelocationType::Call;
    const auto target_thumb = (symbol & 1U) != 0;
    const auto target = static_cast<std::int64_t>(symbol & ~1U) + addend;
    const auto displacement = target - static_cast<std::int64_t>(place);

    if (target_thumb) {
        if (!is_call) {
            error = ElfDiagnostic{ElfDiagnosticCode::UnsupportedRelocation, image.name, image.package_name,
                "ARM JUMP24/PC24 interworking to Thumb is not supported"};
            return false;
        }
        if ((displacement & 1) != 0 || displacement < -(1LL << 25U) || displacement >= (1LL << 25U)) {
            error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "ARM-to-Thumb BLX displacement is out of range or misaligned"};
            return false;
        }
        const auto encoded = static_cast<std::uint32_t>(static_cast<std::uint64_t>(displacement));
        const auto blx = 0xfa000000U | (((encoded >> 1U) & 1U) << 24U) | ((encoded >> 2U) & 0x00ffffffU);
        if (!write_runtime_u32(memory, place, blx)) {
            error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "unable to write ARM-to-Thumb BLX relocation"};
            return false;
        }
        return true;
    }

    if ((displacement & 3) != 0 || displacement < -(1LL << 25U) || displacement >= (1LL << 25U)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "ARM branch relocation displacement is out of range or misaligned"};
        return false;
    }
    const auto encoded_imm = static_cast<std::uint32_t>(static_cast<std::uint64_t>(displacement) >> 2U) & 0x00ffffffU;
    const auto patched = (*instruction & 0xff000000U) | encoded_imm;
    if (!write_runtime_u32(memory, place, patched)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "unable to write ARM branch relocation"};
        return false;
    }
    return true;
}

[[nodiscard]] bool relocate_thumb_branch(
    const Elf32LoadedImage& image,
    GuestMemory& memory,
    std::uint32_t place,
    std::uint32_t symbol,
    std::optional<ElfDiagnostic>& error) {
    const auto first = read_runtime_u16(memory, place);
    const auto second = read_runtime_u16(memory, place + 2U);
    if (!first.has_value() || !second.has_value()
        || (*first & 0xf800U) != 0xf000U
        || ((*second & 0xd000U) != 0x9000U && (*second & 0xd000U) != 0xd000U)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "Thumb branch relocation does not point at a valid 32-bit B.W/BL instruction"};
        return false;
    }
    if ((symbol & 1U) == 0) {
        error = ElfDiagnostic{ElfDiagnosticCode::UnsupportedRelocation, image.name, image.package_name,
            "Thumb-to-ARM interworking relocation requires BLX instruction decoding"};
        return false;
    }

    const auto s = static_cast<std::uint32_t>((*first >> 10U) & 1U);
    const auto j1 = static_cast<std::uint32_t>((*second >> 13U) & 1U);
    const auto j2 = static_cast<std::uint32_t>((*second >> 11U) & 1U);
    const auto i1 = (~(j1 ^ s)) & 1U;
    const auto i2 = (~(j2 ^ s)) & 1U;
    const auto immediate = (s << 24U) | (i1 << 23U) | (i2 << 22U)
        | (static_cast<std::uint32_t>(*first & 0x03ffU) << 12U)
        | (static_cast<std::uint32_t>(*second & 0x07ffU) << 1U);
    const auto addend = sign_extend(immediate, 25U);
    const auto target = static_cast<std::int64_t>(symbol & ~1U) + addend;
    const auto displacement = target - static_cast<std::int64_t>(place);
    if ((displacement & 1) != 0 || displacement < -(1LL << 24U) || displacement >= (1LL << 24U)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "Thumb branch relocation displacement is out of range or misaligned"};
        return false;
    }

    const auto encoded = static_cast<std::uint32_t>(displacement) & 0x01ffffffU;
    const auto new_s = (encoded >> 24U) & 1U;
    const auto new_i1 = (encoded >> 23U) & 1U;
    const auto new_i2 = (encoded >> 22U) & 1U;
    const auto new_j1 = (~(new_i1 ^ new_s)) & 1U;
    const auto new_j2 = (~(new_i2 ^ new_s)) & 1U;
    auto patched_first = static_cast<std::uint16_t>((*first & 0xf800U)
        | (new_s << 10U) | ((encoded >> 12U) & 0x03ffU));
    auto patched_second = static_cast<std::uint16_t>((*second & 0xd000U)
        | (new_j1 << 13U) | (1U << 12U) | (new_j2 << 11U) | ((encoded >> 1U) & 0x07ffU));
    if (!write_runtime_u16(memory, place, patched_first)
        || !write_runtime_u16(memory, place + 2U, patched_second)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "unable to write Thumb branch relocation"};
        return false;
    }
    return true;
}

[[nodiscard]] bool relocate_arm_mov(
    const Elf32LoadedImage& image,
    GuestMemory& memory,
    std::uint32_t place,
    std::uint32_t symbol,
    std::int64_t addend,
    ArmRelocationType type,
    std::optional<ElfDiagnostic>& error) {
    const auto instruction = read_runtime_u32(memory, place);
    if (!instruction.has_value()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "ARM MOVW/MOVT relocation target is not mapped"};
        return false;
    }
    const bool movt = type == ArmRelocationType::MovtAbs || type == ArmRelocationType::MovtPrel;
    const bool prel = type == ArmRelocationType::MovwPrelNc || type == ArmRelocationType::MovtPrel;
    const auto opcode = *instruction & 0x0ff00000U;
    const auto expected = movt ? 0x03400000U : 0x03000000U;
    if (opcode != expected) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "relocation points at an ARM instruction other than MOVW/MOVT"};
        return false;
    }
    const auto encoded_addend = decode_arm_mov_immediate(*instruction);
    const auto full_addend = movt ? (encoded_addend << 16U) : encoded_addend;
    const auto value = static_cast<std::int64_t>(symbol) + full_addend + addend
        - (prel ? static_cast<std::int64_t>(place) : 0);
    const auto immediate = static_cast<std::uint16_t>(movt
        ? (static_cast<std::uint64_t>(value) >> 16U) & 0xffffU
        : static_cast<std::uint64_t>(value) & 0xffffU);
    const auto patched = patch_arm_mov_immediate(*instruction, immediate);
    if (!write_runtime_u32(memory, place, patched)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "unable to write ARM MOVW/MOVT relocation"};
        return false;
    }
    return true;
}

[[nodiscard]] bool relocate_thumb_mov(
    const Elf32LoadedImage& image,
    GuestMemory& memory,
    std::uint32_t place,
    std::uint32_t symbol,
    std::int64_t addend,
    ArmRelocationType type,
    std::optional<ElfDiagnostic>& error) {
    const auto first = read_runtime_u16(memory, place);
    const auto second = read_runtime_u16(memory, place + 2U);
    if (!first.has_value() || !second.has_value()) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "Thumb MOVW/MOVT relocation target is not mapped"};
        return false;
    }
    const bool movt = type == ArmRelocationType::ThmMovtAbs || type == ArmRelocationType::ThmMovtPrel;
    const bool prel = type == ArmRelocationType::ThmMovwPrelNc || type == ArmRelocationType::ThmMovtPrel;
    if (!is_thumb_movw(*first, *second, movt)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "relocation points at a Thumb instruction other than MOVW/MOVT"};
        return false;
    }
    const auto encoded_addend = decode_thumb_mov_immediate(*first, *second);
    const auto full_addend = movt ? (static_cast<std::int64_t>(encoded_addend) << 16U) : encoded_addend;
    const auto value = static_cast<std::int64_t>(symbol) + full_addend + addend
        - (prel ? static_cast<std::int64_t>(place) : 0);
    const auto immediate = static_cast<std::uint16_t>(movt
        ? (static_cast<std::uint64_t>(value) >> 16U) & 0xffffU
        : static_cast<std::uint64_t>(value) & 0xffffU);
    auto patched_first = *first;
    auto patched_second = *second;
    patch_thumb_mov_immediate(patched_first, patched_second, immediate);
    if (!write_runtime_u16(memory, place, patched_first)
        || !write_runtime_u16(memory, place + 2U, patched_second)) {
        error = ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "unable to write Thumb MOVW/MOVT relocation"};
        return false;
    }
    return true;
}

}  // namespace

std::optional<std::uint32_t> Elf32LoadedImage::lookup_symbol(std::string_view symbol_name) const noexcept {
    const auto acceptable = [&](std::uint32_t index) -> std::optional<std::uint32_t> {
        if (index >= symbols.size()) return std::nullopt;
        const auto& symbol = symbols[index];
        if (symbol.name != symbol_name || symbol.section_index == kSectionUndefined
            || symbol.binding == kBindingLocal
            || symbol.visibility == kVisibilityHidden
            || symbol.visibility == kVisibilityInternal) return std::nullopt;
        if (symbol.binding != kBindingGlobal && symbol.binding != kBindingWeak && symbol.binding != kBindingGnuUnique) {
            return std::nullopt;
        }
        if (symbol.section_index == kSectionAbsolute) return symbol.value;
        return add_load_bias(load_bias, symbol.value);
    };

    if (!sysv_buckets.empty() && !sysv_chains.empty()) {
        const auto bucket = elf_hash(symbol_name) % sysv_buckets.size();
        auto index = sysv_buckets[bucket];
        std::size_t steps = 0;
        while (index != 0 && index < sysv_chains.size() && steps++ < sysv_chains.size()) {
            if (const auto match = acceptable(index); match.has_value()) return match;
            index = sysv_chains[index];
        }
    }

    if (!gnu_buckets.empty() && !gnu_bloom.empty()) {
        const auto hash = gnu_hash(symbol_name);
        const auto bloom_index = (hash / 32U) % static_cast<std::uint32_t>(gnu_bloom.size());
        const auto bloom = gnu_bloom[bloom_index];
        const auto first_bit = hash % 32U;
        const auto second_bit = (hash >> gnu_bloom_shift) % 32U;
        if ((bloom & (1U << first_bit)) != 0 && (bloom & (1U << second_bit)) != 0) {
            const auto bucket = gnu_buckets[hash % gnu_buckets.size()];
            if (bucket >= gnu_symbol_offset) {
                auto index = bucket;
                while (true) {
                    const auto chain_index = index - gnu_symbol_offset;
                    if (chain_index >= gnu_chains.size() || index >= symbols.size()) break;
                    const auto chain = gnu_chains[chain_index];
                    if ((chain | 1U) == (hash | 1U)) {
                        if (const auto match = acceptable(index); match.has_value()) return match;
                    }
                    if ((chain & 1U) != 0) break;
                    ++index;
                }
            }
        }
    }

    if (sysv_buckets.empty() && gnu_buckets.empty()) {
        for (std::uint32_t index = 1; index < symbols.size(); ++index) {
            if (const auto match = acceptable(index); match.has_value()) return match;
        }
    }
    return std::nullopt;
}

namespace {

[[nodiscard]] std::variant<std::vector<GuestAddress32>, ElfDiagnostic> lifecycle_addresses(
    const Elf32LoadedImage& image,
    const GuestMemory& memory,
    bool constructors) {
    std::vector<GuestAddress32> result;
    const auto direct = constructors ? image.init_function : image.fini_function;
    const auto array_address = constructors ? image.init_array_address : image.fini_array_address;
    const auto array_size = constructors ? image.init_array_size : image.fini_array_size;
    const auto append_address = [&](std::uint32_t address) -> bool {
        if (address == 0 || address == 0xffffffffU) return true;
        if (!memory.is_executable(GuestAddress32{address & ~1U})) return false;
        result.emplace_back(address);
        return true;
    };
    if (constructors && direct.has_value() && !append_address(*direct)) {
        return ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSection, image.name, image.package_name,
            "DT_INIT does not point into executable guest memory"};
    }
    if (array_address.has_value()) {
        if ((array_size % 4U) != 0 || !memory.is_mapped(GuestAddress32{*array_address}, array_size)) {
            return ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSection, image.name, image.package_name,
                "constructor/destructor array is not mapped or has an invalid size"};
        }
        for (std::uint32_t offset = 0; offset < array_size; offset += 4U) {
            const auto value = read_runtime_u32(memory, *array_address + offset);
            if (!value.has_value()) {
                return ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSection, image.name, image.package_name,
                    "unable to read constructor/destructor array"};
            }
            const auto appended = append_address(*value);
            if (!appended) {
                return ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSection, image.name, image.package_name,
                    "constructor/destructor array contains a non-executable function"};
            }
        }
        if (!constructors) std::reverse(result.begin(), result.end());
    }
    if (!constructors && direct.has_value() && !append_address(*direct)) {
        return ElfDiagnostic{ElfDiagnosticCode::InvalidDynamicSection, image.name, image.package_name,
            "DT_FINI does not point into executable guest memory"};
    }
    return result;
}

}  // namespace

std::variant<std::vector<GuestAddress32>, ElfDiagnostic> Elf32LoadedImage::constructor_addresses(
    const GuestMemory& memory) const {
    return lifecycle_addresses(*this, memory, true);
}

std::variant<std::vector<GuestAddress32>, ElfDiagnostic> Elf32LoadedImage::destructor_addresses(
    const GuestMemory& memory) const {
    return lifecycle_addresses(*this, memory, false);
}

std::variant<Elf32LoadedImage, ElfDiagnostic> Elf32Loader::load(
    std::span<const std::byte> file,
    GuestMemory& memory,
    Elf32LoadOptions options,
    std::string source,
    std::string package_name) {
    auto parsed_result = Elf32Image::parse(file, source, package_name);
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&parsed_result)) return *diagnostic;
    const auto& parsed = std::get<Elf32Image>(parsed_result);
    const auto fail = [&](ElfDiagnosticCode code, std::string detail) -> std::variant<Elf32LoadedImage, ElfDiagnostic> {
        return ElfDiagnostic{code, source, package_name, std::move(detail)};
    };

    const auto type = parsed.type();
    if ((type == kTypeExecutable && options.load_bias != 0)
        || (type == kTypeSharedObject && options.load_bias % kPageSize != 0)) {
        return fail(ElfDiagnosticCode::InvalidLoadBias, "ET_EXEC requires zero bias and ET_DYN requires a page-aligned bias");
    }

    Elf32LoadedImage loaded;
    loaded.name = source.empty() ? "<memory>" : source;
    loaded.package_name = package_name;
    loaded.file_type = type;
    loaded.load_bias = options.load_bias;
    loaded.needed_libraries = parsed.needed_libraries();

    std::vector<DynamicEntry> dynamic_entries;
    std::optional<ElfSegment32> dynamic_segment;
    for (const auto& segment : parsed.segments()) {
        if (segment.type == kProgramDynamic) {
            if (dynamic_segment.has_value()) return fail(ElfDiagnosticCode::InvalidDynamicSection, "multiple PT_DYNAMIC segments");
            dynamic_segment = segment;
        }
    }
    if (dynamic_segment.has_value()) {
        const auto& segment = *dynamic_segment;
        if (segment.file_size % 8U != 0 || segment.file_size / 8U > kMaximumDynamicEntries) {
            return fail(ElfDiagnosticCode::InvalidDynamicSection, "PT_DYNAMIC has invalid size");
        }
        bool terminated = false;
        for (std::uint32_t offset = 0; offset < segment.file_size; offset += 8U) {
            const auto entry_offset = static_cast<std::size_t>(segment.file_offset) + offset;
            const DynamicEntry entry{read_u32(file, entry_offset), read_u32(file, entry_offset + 4U)};
            if (entry.tag == kDynamicNull) {
                terminated = true;
                break;
            }
            dynamic_entries.push_back(entry);
        }
        if (!terminated) return fail(ElfDiagnosticCode::InvalidDynamicSection, "PT_DYNAMIC has no DT_NULL terminator");
    }

    std::map<std::uint32_t, std::vector<std::uint32_t>> dynamic_tags;
    for (const auto& entry : dynamic_entries) dynamic_tags[entry.tag].push_back(entry.value);
    for (const auto& [tag, values] : dynamic_tags) {
        if (tag != kDynamicNeeded && values.size() > 1
            && std::any_of(values.begin() + 1, values.end(), [&](std::uint32_t value) { return value != values.front(); })) {
            return fail(ElfDiagnosticCode::InvalidDynamicSection, "dynamic tag appears more than once with conflicting values");
        }
    }
    const auto get_tag = [&](std::uint32_t tag) { return dynamic_value(dynamic_tags, tag); };

    if (get_tag(kDynamicRelaSize).value_or(0) != 0 || get_tag(kDynamicRela).has_value()
        || get_tag(kDynamicRelaEntry).has_value() || get_tag(kDynamicRelr).has_value()
        || get_tag(kDynamicRelrSize).value_or(0) != 0 || get_tag(kDynamicRelrEntry).has_value()
        || get_tag(kDynamicAndroidRel).has_value() || get_tag(kDynamicAndroidRelSize).value_or(0) != 0
        || get_tag(kDynamicAndroidRela).has_value() || get_tag(kDynamicAndroidRelaSize).value_or(0) != 0) {
        return fail(ElfDiagnosticCode::UnsupportedDynamicFeature,
            "RELA, RELR, and Android packed relocation tables are not supported by the ARM32 loader");
    }

    const auto string_table_address = get_tag(kDynamicStringTable);
    const auto string_table_size = get_tag(kDynamicStringSize);
    std::optional<std::size_t> string_table_file_offset;
    if (string_table_address.has_value() && string_table_size.has_value()) {
        if (*string_table_size == 0 || *string_table_size > kMaximumDynamicTableBytes) {
            return fail(ElfDiagnosticCode::MissingDynamicStringTable, "DT_STRSZ is empty or exceeds the safety limit");
        }
        string_table_file_offset = file_offset_for_vaddr(parsed, *string_table_address, *string_table_size, file.size());
        if (!string_table_file_offset.has_value()) {
            return fail(ElfDiagnosticCode::MissingDynamicStringTable, "DT_STRTAB is not inside file-backed PT_LOAD memory");
        }
    }

    if (!dynamic_entries.empty() && (!string_table_address.has_value() || !string_table_size.has_value())) {
        const auto has_names = get_tag(kDynamicNeeded).has_value() || get_tag(kDynamicSymbolTable).has_value()
            || get_tag(kDynamicSoname).has_value();
        if (has_names) return fail(ElfDiagnosticCode::MissingDynamicStringTable, "dynamic names lack DT_STRTAB/DT_STRSZ");
    }
    if (string_table_file_offset.has_value() && string_table_size.has_value()) {
        if (const auto soname_offset = get_tag(kDynamicSoname); soname_offset.has_value()) {
            const auto soname = string_at(file, *string_table_file_offset, *string_table_size, *soname_offset);
            if (!soname.has_value() || soname->empty()) {
                return fail(ElfDiagnosticCode::InvalidNeededLibraryName, "DT_SONAME contains an invalid string offset");
            }
            loaded.soname = *soname;
        }
    }

    std::set<std::pair<std::uint32_t, std::uint32_t>> seen_relocations;
    std::optional<ElfDiagnostic> relocation_error;
    const auto rel_address = get_tag(kDynamicRel);
    const auto rel_size = get_tag(kDynamicRelSize).value_or(0);
    if (rel_size != 0) {
        if (!rel_address.has_value() || get_tag(kDynamicRelEntry).value_or(8) != 8) {
            return fail(ElfDiagnosticCode::InvalidRelocationTable, "DT_REL/DT_RELSZ/DT_RELENT are inconsistent");
        }
        if (!parse_relocation_table(file, parsed, *rel_address, rel_size, "DT_REL",
            options.maximum_relocations, loaded.relocations, seen_relocations, relocation_error, source, package_name)) {
            return *relocation_error;
        }
    }
    const auto plt_size = get_tag(kDynamicPltRelSize).value_or(0);
    if (plt_size != 0) {
        const auto plt_address = get_tag(kDynamicJumpRel);
        if (!plt_address.has_value() || get_tag(kDynamicPltRel).value_or(kDynamicRel) != kDynamicRel) {
            return fail(ElfDiagnosticCode::InvalidRelocationTable, "DT_JMPREL must describe an ELF32 REL table");
        }
        if (!parse_relocation_table(file, parsed, *plt_address, plt_size, "DT_JMPREL",
            options.maximum_relocations, loaded.relocations, seen_relocations, relocation_error, source, package_name)) {
            return *relocation_error;
        }
    }

    const auto symbol_table_address = get_tag(kDynamicSymbolTable);
    std::optional<std::size_t> symbol_table_file_offset;
    const auto symbol_entry_size = get_tag(kDynamicSymbolEntry).value_or(16);
    if (symbol_table_address.has_value()) {
        if (!string_table_file_offset.has_value() || !string_table_size.has_value() || symbol_entry_size != 16) {
            return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "DT_SYMTAB requires DT_STRTAB and 16-byte DT_SYMENT");
        }
        symbol_table_file_offset = file_offset_for_vaddr(parsed, *symbol_table_address, 16, file.size());
        if (!symbol_table_file_offset.has_value()) {
            return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "DT_SYMTAB is not in file-backed PT_LOAD memory");
        }
    } else if (!loaded.relocations.empty()) {
        if (std::any_of(loaded.relocations.begin(), loaded.relocations.end(), [](const auto& relocation) {
            return relocation.symbol_index != 0;
        })) {
            return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "symbol relocations exist without DT_SYMTAB");
        }
    }

    std::optional<std::size_t> sysv_symbol_count;
    if (const auto hash_address = get_tag(kDynamicHash); hash_address.has_value()) {
        const auto hash_header = file_offset_for_vaddr(parsed, *hash_address, 8, file.size());
        if (!hash_header.has_value()) return fail(ElfDiagnosticCode::InvalidHashTable, "DT_HASH header is not file-backed");
        const auto bucket_count = read_u32(file, *hash_header);
        const auto chain_count = read_u32(file, *hash_header + 4U);
        if (bucket_count > options.maximum_symbols || chain_count > options.maximum_symbols
            || bucket_count == 0 || chain_count == 0) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_HASH has invalid bucket or symbol count");
        }
        const auto word_count = static_cast<std::uint64_t>(bucket_count) + chain_count;
        const auto table_bytes = 8U + word_count * 4U;
        const auto full_hash = file_offset_for_vaddr(parsed, *hash_address, table_bytes, file.size());
        if (table_bytes > kMaximumDynamicTableBytes || !full_hash.has_value() || *full_hash != *hash_header) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_HASH table is not fully file-backed or exceeds limit");
        }
        loaded.sysv_buckets.reserve(bucket_count);
        loaded.sysv_chains.reserve(chain_count);
        auto cursor = *hash_header + 8U;
        for (std::uint32_t index = 0; index < bucket_count; ++index, cursor += 4U) {
            const auto value = read_u32(file, cursor);
            if (value >= chain_count) return fail(ElfDiagnosticCode::InvalidHashTable, "DT_HASH bucket index is out of range");
            loaded.sysv_buckets.push_back(value);
        }
        for (std::uint32_t index = 0; index < chain_count; ++index, cursor += 4U) {
            const auto value = read_u32(file, cursor);
            if (value >= chain_count) return fail(ElfDiagnosticCode::InvalidHashTable, "DT_HASH chain index is out of range");
            loaded.sysv_chains.push_back(value);
        }
        sysv_symbol_count = chain_count;
    }

    std::optional<std::size_t> gnu_symbol_count;
    if (const auto hash_address = get_tag(kDynamicGnuHash); hash_address.has_value()) {
        const auto hash_header = file_offset_for_vaddr(parsed, *hash_address, 16, file.size());
        if (!hash_header.has_value()) return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH header is not file-backed");
        const auto bucket_count = read_u32(file, *hash_header);
        loaded.gnu_symbol_offset = read_u32(file, *hash_header + 4U);
        const auto bloom_count = read_u32(file, *hash_header + 8U);
        loaded.gnu_bloom_shift = read_u32(file, *hash_header + 12U);
        if (bucket_count == 0 || bloom_count == 0 || bucket_count > options.maximum_symbols
            || bloom_count > options.maximum_symbols || loaded.gnu_symbol_offset > options.maximum_symbols
            || loaded.gnu_bloom_shift >= 32U) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH has invalid dimensions");
        }
        const auto bucket_bytes = static_cast<std::uint64_t>(bucket_count) * 4U;
        const auto bloom_bytes = static_cast<std::uint64_t>(bloom_count) * 4U;
        const auto arrays_offset = static_cast<std::uint64_t>(*hash_header) + 16U;
        const auto minimum_table_bytes = 16U + bloom_bytes + bucket_bytes;
        const auto arrays_file_offset = file_offset_for_vaddr(parsed, *hash_address, minimum_table_bytes, file.size());
        if (arrays_offset + bloom_bytes + bucket_bytes > file.size()
            || minimum_table_bytes > kMaximumDynamicTableBytes
            || !arrays_file_offset.has_value() || *arrays_file_offset != *hash_header) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH arrays are not file-backed or exceed limit");
        }
        auto cursor = static_cast<std::size_t>(arrays_offset);
        loaded.gnu_bloom.reserve(bloom_count);
        for (std::uint32_t index = 0; index < bloom_count; ++index, cursor += 4U) {
            loaded.gnu_bloom.push_back(read_u32(file, cursor));
        }
        loaded.gnu_buckets.reserve(bucket_count);
        for (std::uint32_t index = 0; index < bucket_count; ++index, cursor += 4U) {
            const auto value = read_u32(file, cursor);
            if (value != 0 && value < loaded.gnu_symbol_offset) {
                return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH bucket precedes symbol offset");
            }
            loaded.gnu_buckets.push_back(value);
        }
        const auto chain_file_offset = cursor;
        const auto available_chain_words = std::min({
            options.maximum_symbols - loaded.gnu_symbol_offset,
            (file.size() - chain_file_offset) / 4U,
            static_cast<std::size_t>(kMaximumDynamicTableBytes / 4U),
        });
        std::vector<std::uint32_t> chain_scan;
        chain_scan.reserve(available_chain_words);
        for (std::size_t index = 0; index < available_chain_words; ++index) {
            chain_scan.push_back(read_u32(file, chain_file_offset + index * 4U));
        }
        const auto no_terminal = std::numeric_limits<std::size_t>::max();
        std::vector<std::size_t> next_terminal(available_chain_words, no_terminal);
        for (std::size_t index = available_chain_words; index-- > 0;) {
            if ((chain_scan[index] & 1U) != 0) next_terminal[index] = index;
            else if (index + 1U < available_chain_words) next_terminal[index] = next_terminal[index + 1U];
        }
        std::size_t highest_symbol = loaded.gnu_symbol_offset;
        for (const auto bucket : loaded.gnu_buckets) {
            if (bucket == 0) continue;
            const auto start = static_cast<std::size_t>(bucket - loaded.gnu_symbol_offset);
            if (start >= next_terminal.size() || next_terminal[start] == no_terminal) {
                return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH chain is unterminated or out of bounds");
            }
            highest_symbol = std::max(highest_symbol,
                static_cast<std::size_t>(loaded.gnu_symbol_offset) + next_terminal[start] + 1U);
        }
        if (sysv_symbol_count.has_value() && highest_symbol > *sysv_symbol_count) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH references a symbol past DT_HASH nchain");
        }
        const auto count = sysv_symbol_count.value_or(highest_symbol);
        if (count < loaded.gnu_symbol_offset || count > options.maximum_symbols) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH symbol count is invalid");
        }
        const auto chain_count = count - loaded.gnu_symbol_offset;
        const auto full_table_size = minimum_table_bytes + chain_count * 4U;
        const auto complete_hash_file_offset = file_offset_for_vaddr(parsed, *hash_address, full_table_size, file.size());
        if (full_table_size > kMaximumDynamicTableBytes
            || !complete_hash_file_offset.has_value() || *complete_hash_file_offset != *hash_header) {
            return fail(ElfDiagnosticCode::InvalidHashTable, "DT_GNU_HASH chain array is not fully file-backed");
        }
        loaded.gnu_chains.reserve(chain_count);
        for (std::size_t index = 0; index < chain_count; ++index) {
            loaded.gnu_chains.push_back(read_u32(file, chain_file_offset + index * 4U));
        }
        gnu_symbol_count = count;
    }

    std::size_t symbol_count = 0;
    if (sysv_symbol_count.has_value()) symbol_count = *sysv_symbol_count;
    else if (gnu_symbol_count.has_value()) symbol_count = *gnu_symbol_count;
    else if (!loaded.relocations.empty()) {
        for (const auto& relocation : loaded.relocations) {
            symbol_count = std::max(symbol_count, static_cast<std::size_t>(relocation.symbol_index) + 1U);
        }
    }
    if (symbol_count > options.maximum_symbols) {
        return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "dynamic symbol count exceeds configured safety limit");
    }
    if (symbol_count != 0 && !symbol_table_address.has_value()) {
        return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "symbol hash table exists without DT_SYMTAB");
    }
    if (symbol_table_address.has_value()) {
        if (!string_table_file_offset.has_value() || !string_table_size.has_value()) {
            return fail(ElfDiagnosticCode::MissingDynamicStringTable, "DT_SYMTAB has no dynamic string table");
        }
        const auto symbol_bytes = static_cast<std::uint64_t>(symbol_count) * symbol_entry_size;
        symbol_table_file_offset = file_offset_for_vaddr(parsed, *symbol_table_address, symbol_bytes, file.size());
        if (!symbol_table_file_offset.has_value()) {
            return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "dynamic symbol array is not fully file-backed");
        }
        loaded.symbols.reserve(symbol_count);
        for (std::size_t index = 0; index < symbol_count; ++index) {
            const auto offset = *symbol_table_file_offset + index * symbol_entry_size;
            const auto name_offset = read_u32(file, offset);
            const auto value = read_u32(file, offset + 4U);
            const auto size = read_u32(file, offset + 8U);
            const auto info = std::to_integer<std::uint8_t>(file[offset + 12U]);
            const auto other = std::to_integer<std::uint8_t>(file[offset + 13U]);
            const auto section_index = read_u16(file, offset + 14U);
            const auto name = string_at(file, *string_table_file_offset, *string_table_size, name_offset);
            if (!name.has_value()) return fail(ElfDiagnosticCode::InvalidDynamicSymbolTable, "dynamic symbol name is invalid or unterminated");
            loaded.symbols.push_back(Elf32DynamicSymbol{
                *name,
                value,
                size,
                static_cast<std::uint8_t>(info >> 4U),
                static_cast<std::uint8_t>(info & 0x0fU),
                static_cast<std::uint8_t>(other & 0x03U),
                section_index,
            });
        }
    }

    const auto set_lifecycle_address = [&](std::uint32_t tag, std::optional<std::uint32_t>& output) -> bool {
        const auto value = get_tag(tag);
        if (!value.has_value() || *value == 0) return true;
        const auto address = add_load_bias(options.load_bias, *value);
        if (!address.has_value()) return false;
        output = *address;
        return true;
    };
    if (!set_lifecycle_address(kDynamicInit, loaded.init_function)
        || !set_lifecycle_address(kDynamicFini, loaded.fini_function)
        || !set_lifecycle_address(kDynamicInitArray, loaded.init_array_address)
        || !set_lifecycle_address(kDynamicFiniArray, loaded.fini_array_address)) {
        return fail(ElfDiagnosticCode::InvalidDynamicSection, "constructor/destructor address overflows guest address space");
    }
    loaded.init_array_size = get_tag(kDynamicInitArraySize).value_or(0);
    loaded.fini_array_size = get_tag(kDynamicFiniArraySize).value_or(0);
    if ((loaded.init_array_size % 4U) != 0 || (loaded.fini_array_size % 4U) != 0
        || (loaded.init_array_size != 0 && !loaded.init_array_address.has_value())
        || (loaded.fini_array_size != 0 && !loaded.fini_array_address.has_value())) {
        return fail(ElfDiagnosticCode::InvalidDynamicSection, "constructor/destructor array dimensions are invalid");
    }

    std::vector<GuestAddress32> newly_mapped;
    const auto rollback = [&]() {
        for (auto it = newly_mapped.rbegin(); it != newly_mapped.rend(); ++it) memory.unmap(*it);
    };
    const auto entry = add_load_bias(options.load_bias, parsed.entry_point());
    if (!entry.has_value()) return fail(ElfDiagnosticCode::InvalidSegment, "ELF entry point overflows guest address space");
    loaded.entry_point = GuestAddress32{*entry};

    for (const auto& segment : parsed.segments()) {
        if (segment.type != kProgramLoad || segment.memory_size == 0) continue;
        const auto address = add_load_bias(options.load_bias, segment.virtual_address);
        if (!address.has_value()) {
            rollback();
            return fail(ElfDiagnosticCode::InvalidSegment, "PT_LOAD guest address overflows 32-bit space");
        }
        const auto start = static_cast<std::size_t>(segment.file_offset);
        const auto count = static_cast<std::size_t>(segment.file_size);
        std::string map_error;
        if (!memory.map_bytes(
            GuestAddress32{*address},
            file.subspan(start, count),
            segment.memory_size,
            GuestPermission::Read | GuestPermission::Write,
            &map_error)) {
            rollback();
            return fail(ElfDiagnosticCode::MappingFailed, map_error);
        }
        newly_mapped.emplace_back(*address);
        loaded.mapped_regions.emplace_back(*address);
    }

    for (const auto& segment : parsed.segments()) {
        if (segment.type != kProgramLoad || segment.memory_size == 0) continue;
        const auto address = add_load_bias(options.load_bias, segment.virtual_address);
        if (!address.has_value() || !memory.protect(GuestAddress32{*address}, segment_permissions(segment.flags))) {
            rollback();
            return fail(ElfDiagnosticCode::MappingFailed, "unable to apply PT_LOAD permissions");
        }
    }

    const auto validate_array = [&](const std::optional<std::uint32_t>& address, std::uint32_t size) {
        if (!address.has_value() || size == 0) return true;
        return memory.is_mapped(GuestAddress32{*address}, size);
    };
    if (!validate_array(loaded.init_array_address, loaded.init_array_size)
        || !validate_array(loaded.fini_array_address, loaded.fini_array_size)) {
        rollback();
        return fail(ElfDiagnosticCode::InvalidDynamicSection, "constructor/destructor array is outside mapped PT_LOAD memory");
    }
    if (type == kTypeExecutable && parsed.entry_point() != 0) {
        const auto executable_entry = *entry & ~1U;
        if (!memory.is_executable(GuestAddress32{executable_entry})) {
            rollback();
            return fail(ElfDiagnosticCode::InvalidSegment, "executable entry point is not in an executable PT_LOAD segment");
        }
    }
    return loaded;
}

std::optional<ElfDiagnostic> Elf32Loader::relocate(
    const Elf32LoadedImage& image,
    GuestMemory& memory,
    const ExternalSymbolResolver& resolver) {
    for (const auto& relocation : image.relocations) {
        if (relocation.type == ArmRelocationType::None) continue;
        const auto place_value = add_load_bias(image.load_bias, relocation.offset);
        if (!place_value.has_value()) {
            return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "relocation target overflows guest address space in " + relocation.table};
        }
        const auto place = *place_value;
        if (!memory.is_mapped(GuestAddress32{place}, 4)) {
            return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "relocation target is outside mapped PT_LOAD memory: " + relocation.table};
        }
        if (relocation.type == ArmRelocationType::Relative) {
            const auto addend = read_runtime_u32(memory, place);
            if (!addend.has_value()) return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "R_ARM_RELATIVE addend cannot be read"};
            const auto value = static_cast<std::uint32_t>(image.load_bias + *addend);
            if (!write_runtime_u32(memory, place, value)) return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget,
                image.name, image.package_name, "R_ARM_RELATIVE target cannot be written"};
            continue;
        }

        std::uint32_t symbol_address = 0;
        std::optional<ElfDiagnostic> symbol_error;
        if (!resolve_relocation_symbol(image, relocation.symbol_index, resolver, symbol_address, symbol_error)) {
            return symbol_error;
        }
        if (relocation.type == ArmRelocationType::Call || relocation.type == ArmRelocationType::Jump24
            || relocation.type == ArmRelocationType::Pc24) {
            std::optional<ElfDiagnostic> error;
            if (!relocate_arm_branch(image, memory, place, symbol_address, relocation.type, error)) return error;
            continue;
        }
        if (relocation.type == ArmRelocationType::ThmCall || relocation.type == ArmRelocationType::ThmJump24) {
            std::optional<ElfDiagnostic> error;
            if (!relocate_thumb_branch(image, memory, place, symbol_address, error)) return error;
            continue;
        }
        if (relocation.type == ArmRelocationType::MovwAbsNc || relocation.type == ArmRelocationType::MovtAbs
            || relocation.type == ArmRelocationType::MovwPrelNc || relocation.type == ArmRelocationType::MovtPrel) {
            std::optional<ElfDiagnostic> error;
            if (!relocate_arm_mov(image, memory, place, symbol_address, 0, relocation.type, error)) return error;
            continue;
        }
        if (relocation.type == ArmRelocationType::ThmMovwAbsNc || relocation.type == ArmRelocationType::ThmMovtAbs
            || relocation.type == ArmRelocationType::ThmMovwPrelNc || relocation.type == ArmRelocationType::ThmMovtPrel) {
            std::optional<ElfDiagnostic> error;
            if (!relocate_thumb_mov(image, memory, place, symbol_address, 0, relocation.type, error)) return error;
            continue;
        }

        const auto original = read_runtime_u32(memory, place);
        if (!original.has_value()) return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
            "relocation addend cannot be read"};
        std::uint32_t value = 0;
        switch (relocation.type) {
            case ArmRelocationType::Abs32:
            case ArmRelocationType::Target1:
                value = symbol_address + *original;
                break;
            case ArmRelocationType::Rel32:
                value = static_cast<std::uint32_t>(static_cast<std::int64_t>(symbol_address)
                    + sign_extend(*original, 32U) - static_cast<std::int64_t>(place));
                break;
            case ArmRelocationType::GlobDat:
            case ArmRelocationType::JumpSlot:
                value = symbol_address;
                break;
            case ArmRelocationType::Prel31: {
                const auto addend = sign_extend(*original & 0x7fffffffU, 31U);
                const auto relative = static_cast<std::int64_t>(symbol_address) + addend - place;
                value = (*original & 0x80000000U) | (static_cast<std::uint32_t>(relative) & 0x7fffffffU);
                break;
            }
            case ArmRelocationType::V4Bx:
                // ARMv7 supports BX directly; keep the instruction unchanged.
                continue;
            default:
                return ElfDiagnostic{ElfDiagnosticCode::UnsupportedRelocation, image.name, image.package_name,
                    "unsupported ARM relocation type " + std::to_string(static_cast<unsigned>(relocation.type))
                        + " at " + relocation.table};
        }
        if (!write_runtime_u32(memory, place, value)) {
            return ElfDiagnostic{ElfDiagnosticCode::InvalidRelocationTarget, image.name, image.package_name,
                "relocation target cannot be written"};
        }
    }
    return std::nullopt;
}

}  // namespace retrobridge::runtime
