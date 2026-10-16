#include "retrobridge/elf32_image.h"
#include "retrobridge/guest_address.h"
#include "retrobridge/handle_table.h"
#include "retrobridge/runtime_capabilities.h"
#include "retrobridge/translation_engine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value & 0xffU);
    bytes.at(offset + 1) = static_cast<std::byte>((value >> 8) & 0xffU);
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::byte>((value >> (index * 8)) & 0xffU);
    }
}

std::vector<std::byte> make_dynamic_arm_elf() {
    std::vector<std::byte> bytes(0x200, std::byte{0});
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{1};  // ELFCLASS32
    bytes[5] = std::byte{1};  // little-endian
    bytes[6] = std::byte{1};  // current version
    put_u16(bytes, 16, 3);    // ET_DYN
    put_u16(bytes, 18, 40);   // EM_ARM
    put_u32(bytes, 20, 1);
    put_u32(bytes, 24, 0x1000);
    put_u32(bytes, 28, 52);
    put_u16(bytes, 40, 52);
    put_u16(bytes, 42, 32);
    put_u16(bytes, 44, 2);

    // PT_LOAD maps the complete fixture at guest virtual address zero.
    put_u32(bytes, 52, 1);
    put_u32(bytes, 56, 0);
    put_u32(bytes, 60, 0);
    put_u32(bytes, 68, static_cast<std::uint32_t>(bytes.size()));
    put_u32(bytes, 72, static_cast<std::uint32_t>(bytes.size()));
    put_u32(bytes, 76, 5);
    put_u32(bytes, 80, 0x1000);

    // PT_DYNAMIC references a tiny in-file DT_STRTAB and one DT_NEEDED entry.
    put_u32(bytes, 84, 2);
    put_u32(bytes, 88, 0x100);
    put_u32(bytes, 92, 0x100);
    put_u32(bytes, 100, 32);
    put_u32(bytes, 104, 32);
    put_u32(bytes, 108, 4);
    put_u32(bytes, 112, 4);

    put_u32(bytes, 0x100, 5);       // DT_STRTAB
    put_u32(bytes, 0x104, 0x180);
    put_u32(bytes, 0x108, 10);      // DT_STRSZ
    put_u32(bytes, 0x10c, 15);
    put_u32(bytes, 0x110, 1);       // DT_NEEDED
    put_u32(bytes, 0x114, 1);
    put_u32(bytes, 0x118, 0);       // DT_NULL
    put_u32(bytes, 0x11c, 0);
    const std::string needed("\0libfixture.so\0", 15);
    for (std::size_t index = 0; index < needed.size(); ++index) {
        bytes[0x180 + index] = static_cast<std::byte>(static_cast<unsigned char>(needed[index]));
    }
    return bytes;
}

void test_guest_address_boundary() {
    using retrobridge::runtime::GuestAddress32;
    using retrobridge::runtime::GuestRange32;
    const auto range = GuestRange32::create(GuestAddress32{0xfffffff0U}, 16);
    check(range.has_value(), "a guest range may end exactly at 2^32");
    check(range->contains(GuestAddress32{0xffffffffU}), "last byte of guest space is in range");
    check(!GuestAddress32{0xfffffff0U}.checked_add(16).has_value(), "address addition detects 32-bit overflow");
    check(!GuestRange32::create(GuestAddress32{0xfffffff0U}, 17).has_value(), "guest range creation detects overflow");
    check(!range->contains(GuestAddress32{0xffffffffU}, 2), "range access detects end overflow");
}

void test_elf_validation_and_dependencies() {
    auto bytes = make_dynamic_arm_elf();
    auto result = retrobridge::runtime::Elf32Image::parse(bytes, "fixture.so", "org.example.test");
    const auto* image = std::get_if<retrobridge::runtime::Elf32Image>(&result);
    check(image != nullptr, "valid synthetic ELF32/EM_ARM parses");
    if (image != nullptr) {
        check(image->type() == 3, "ELF type is retained");
        check(image->load_segment_count() == 1, "PT_LOAD is retained");
        check(image->needed_libraries().size() == 1, "DT_NEEDED is extracted");
        if (image->needed_libraries().size() == 1) {
            check(image->needed_libraries().front() == "libfixture.so", "DT_NEEDED name resolves through DT_STRTAB");
        }
    }

    bytes[18] = std::byte{3};
    bytes[19] = std::byte{0};
    auto wrong_machine = retrobridge::runtime::Elf32Image::parse(bytes, "wrong.so", "org.example.test");
    const auto* diagnostic = std::get_if<retrobridge::runtime::ElfDiagnostic>(&wrong_machine);
    check(diagnostic != nullptr, "non-ARM machine is rejected");
    if (diagnostic != nullptr) {
        check(diagnostic->format().find("org.example.test") != std::string::npos, "failure includes guest package context");
    }

    std::array<std::byte, 4> short_file{};
    auto truncated = retrobridge::runtime::Elf32Image::parse(short_file, "short.elf", "org.example.test");
    check(std::get_if<retrobridge::runtime::ElfDiagnostic>(&truncated) != nullptr, "truncated ELF is rejected");
}

void test_opaque_handles_and_generation() {
    using retrobridge::runtime::HandleTable;
    using retrobridge::runtime::ReferenceKind;
    HandleTable table(2);
    constexpr std::uint64_t opaque_host_token = 0xf123456789abcdefULL;
    const auto local = table.insert(opaque_host_token, ReferenceKind::Local);
    const auto global = table.insert(0x123456789abcdef0ULL, ReferenceKind::Global);
    check(local.has_value() && *local != 0, "local host ref receives nonzero guest handle");
    check(global.has_value() && *global != 0, "global host ref receives nonzero guest handle");
    if (local.has_value() && global.has_value()) {
        check(table.resolve(*local) == opaque_host_token, "guest handle resolves to opaque 64-bit token");
        check(table.release(*local), "live handle releases");
        check(!table.resolve(*local).has_value(), "released stale handle cannot resolve");
        const auto replacement = table.insert(0x55, ReferenceKind::Local);
        check(replacement.has_value() && *replacement != *local, "slot reuse increments handle generation");
        table.clear(ReferenceKind::Local);
        check(!replacement.has_value() || !table.resolve(*replacement).has_value(), "clearing local refs leaves no local handle live");
        check(table.resolve(*global).has_value(), "clearing local refs preserves global refs");
    }
}

void test_execution_is_explicitly_disabled() {
    retrobridge::runtime::UnavailableTranslationEngine engine;
    retrobridge::runtime::GuestCpuState32 state{};
    const auto result = engine.run(state, retrobridge::runtime::GuestAddress32{0x1000}, 100);
    check(!engine.available(), "placeholder translator reports unavailable");
    check(result.status == retrobridge::runtime::ExecutionStatus::BackendUnavailable, "placeholder refuses guest execution");
    check(retrobridge::runtime::current_capabilities().arm32_elf_metadata_validation, "ELF metadata validation is reported available");
    check(!retrobridge::runtime::current_capabilities().arbitrary_guest_execution, "arbitrary guest execution is reported unavailable");
}

}  // namespace

int main() {
    test_guest_address_boundary();
    test_elf_validation_and_dependencies();
    test_opaque_handles_and_generation();
    test_execution_is_explicitly_disabled();
    if (failures != 0) {
        std::cerr << failures << " native verification check(s) failed\n";
        return 1;
    }
    std::cout << "Native verification checks passed\n";
    return 0;
}
