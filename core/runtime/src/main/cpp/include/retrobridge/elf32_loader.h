#pragma once

#include "retrobridge/elf32_image.h"
#include "retrobridge/guest_memory.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace retrobridge::runtime {

enum class ArmRelocationType : std::uint8_t {
    None = 0,
    Pc24 = 1,
    Abs32 = 2,
    Rel32 = 3,
    ThmCall = 10,
    Call = 28,
    Jump24 = 29,
    ThmJump24 = 30,
    Target1 = 38,
    V4Bx = 40,
    Prel31 = 42,
    MovwAbsNc = 43,
    MovtAbs = 44,
    MovwPrelNc = 45,
    MovtPrel = 46,
    ThmMovwAbsNc = 47,
    ThmMovtAbs = 48,
    ThmMovwPrelNc = 49,
    ThmMovtPrel = 50,
    GlobDat = 21,
    JumpSlot = 22,
    Relative = 23,
};

struct Elf32DynamicSymbol final {
    std::string name;
    std::uint32_t value = 0;
    std::uint32_t size = 0;
    std::uint8_t binding = 0;
    std::uint8_t type = 0;
    std::uint8_t visibility = 0;
    std::uint16_t section_index = 0;
};

struct Elf32Relocation final {
    std::uint32_t offset = 0;
    std::uint32_t symbol_index = 0;
    ArmRelocationType type = ArmRelocationType::None;
    std::string table;
};

struct Elf32LoadOptions final {
    /** ET_DYN load bias. ET_EXEC images require zero. */
    std::uint32_t load_bias = 0x40000000U;
    std::size_t maximum_symbols = 1'000'000;
    std::size_t maximum_relocations = 1'000'000;
};

struct Elf32LoadedImage final {
    std::string name;
    std::string package_name;
    std::uint16_t file_type = 0;
    std::uint32_t load_bias = 0;
    GuestAddress32 entry_point{0};
    std::vector<GuestAddress32> mapped_regions;
    std::vector<std::string> needed_libraries;
    std::optional<std::string> soname;
    std::vector<Elf32DynamicSymbol> symbols;
    std::vector<Elf32Relocation> relocations;
    std::vector<std::uint32_t> sysv_buckets;
    std::vector<std::uint32_t> sysv_chains;
    std::vector<std::uint32_t> gnu_bloom;
    std::vector<std::uint32_t> gnu_buckets;
    std::vector<std::uint32_t> gnu_chains;
    std::uint32_t gnu_symbol_offset = 0;
    std::uint32_t gnu_bloom_shift = 0;
    std::optional<std::uint32_t> init_function;
    std::optional<std::uint32_t> init_array_address;
    std::uint32_t init_array_size = 0;
    std::optional<std::uint32_t> fini_function;
    std::optional<std::uint32_t> fini_array_address;
    std::uint32_t fini_array_size = 0;

    [[nodiscard]] std::optional<std::uint32_t> lookup_symbol(std::string_view symbol_name) const noexcept;
    [[nodiscard]] std::variant<std::vector<GuestAddress32>, ElfDiagnostic> constructor_addresses(
        const GuestMemory& memory) const;
    [[nodiscard]] std::variant<std::vector<GuestAddress32>, ElfDiagnostic> destructor_addresses(
        const GuestMemory& memory) const;
};

using ExternalSymbolResolver = std::function<std::optional<std::uint32_t>(std::string_view)>;

/**
 * Maps validated PT_LOAD segments, parses dynamic symbols/hash tables and REL relocations,
 * and applies the supported ARM32 relocation set. It never casts guest addresses to pointers.
 */
class Elf32Loader final {
public:
    [[nodiscard]] static std::variant<Elf32LoadedImage, ElfDiagnostic> load(
        std::span<const std::byte> file,
        GuestMemory& memory,
        Elf32LoadOptions options = {},
        std::string source = {},
        std::string package_name = {});

    [[nodiscard]] static std::optional<ElfDiagnostic> relocate(
        const Elf32LoadedImage& image,
        GuestMemory& memory,
        const ExternalSymbolResolver& resolver = {});
};

}  // namespace retrobridge::runtime
