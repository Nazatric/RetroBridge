#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/elf32_image.h"
#include "retrobridge/elf32_loader.h"
#include "retrobridge/guest_address.h"
#include "retrobridge/guest_memory.h"
#include "retrobridge/guest_lifecycle.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/guest_jni_bridge.h"
#include "retrobridge/handle_table.h"
#include "retrobridge/runtime_capabilities.h"
#include "arm32_syscall_dispatcher.h"
#include "native_vfs.h"
#include "native_vfs_path.h"
#include "retrobridge/translation_engine.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <unistd.h>
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

std::uint32_t test_gnu_hash(const std::string& name) {
    std::uint32_t hash = 5381U;
    for (const auto character : name) hash = hash * 33U + static_cast<unsigned char>(character);
    return hash;
}

std::vector<std::byte> make_loadable_arm_elf(bool include_sysv_hash = true) {
    std::vector<std::byte> bytes(0x1200, std::byte{0});
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{1};
    bytes[5] = std::byte{1};
    bytes[6] = std::byte{1};
    put_u16(bytes, 16, 3); // ET_DYN
    put_u16(bytes, 18, 40);
    put_u32(bytes, 20, 1);
    put_u32(bytes, 24, 0x300);
    put_u32(bytes, 28, 52);
    put_u16(bytes, 40, 52);
    put_u16(bytes, 42, 32);
    put_u16(bytes, 44, 3);

    // Read/execute image segment, read/write data segment, then PT_DYNAMIC.
    put_u32(bytes, 52, 1);
    put_u32(bytes, 56, 0);
    put_u32(bytes, 60, 0);
    put_u32(bytes, 68, 0x400);
    put_u32(bytes, 72, 0x400);
    put_u32(bytes, 76, 5);
    put_u32(bytes, 80, 0x1000);
    put_u32(bytes, 84, 1);
    put_u32(bytes, 88, 0x1000);
    put_u32(bytes, 92, 0x1000);
    put_u32(bytes, 100, 0x200);
    put_u32(bytes, 104, 0x300);
    put_u32(bytes, 108, 6);
    put_u32(bytes, 112, 0x1000);
    put_u32(bytes, 116, 2);
    put_u32(bytes, 120, 0x100);
    put_u32(bytes, 124, 0x100);
    put_u32(bytes, 132, 0x80);
    put_u32(bytes, 136, 0x80);
    put_u32(bytes, 140, 4);
    put_u32(bytes, 144, 4);

    const std::array<std::pair<std::uint32_t, std::uint32_t>, 16> dynamic_entries{{
        {include_sysv_hash ? 4U : 21U, 0x180}, // DT_HASH or harmless DT_DEBUG
        {0x6ffffef5U, 0x1a0},                 // DT_GNU_HASH
        {5, 0x240},                           // DT_STRTAB
        {6, 0x200},                           // DT_SYMTAB
        {10, 19},                             // DT_STRSZ
        {11, 16},                             // DT_SYMENT
        {17, 0x280},                          // DT_REL
        {18, 24},                             // DT_RELSZ
        {19, 8},                              // DT_RELENT
        {12, 0x300},                          // DT_INIT
        {25, 0x1020},                         // DT_INIT_ARRAY
        {27, 4},                              // DT_INIT_ARRAYSZ
        {13, 0x340},                          // DT_FINI
        {26, 0x1024},                         // DT_FINI_ARRAY
        {28, 4},                              // DT_FINI_ARRAYSZ
        {0, 0},                               // DT_NULL
    }};
    for (std::size_t index = 0; index < dynamic_entries.size(); ++index) {
        put_u32(bytes, 0x100 + index * 8, dynamic_entries[index].first);
        put_u32(bytes, 0x104 + index * 8, dynamic_entries[index].second);
    }

    // SysV hash: one bucket, three dynsym entries, and a two-symbol chain.
    put_u32(bytes, 0x180, 1);
    put_u32(bytes, 0x184, 3);
    put_u32(bytes, 0x188, 1);
    put_u32(bytes, 0x18c, 0);
    put_u32(bytes, 0x190, 2);
    put_u32(bytes, 0x194, 0);

    // GNU hash: all names pass the bloom filter; two chain entries end at symbol 2.
    put_u32(bytes, 0x1a0, 1);
    put_u32(bytes, 0x1a4, 1);
    put_u32(bytes, 0x1a8, 1);
    put_u32(bytes, 0x1ac, 5);
    put_u32(bytes, 0x1b0, 0xffffffffU);
    put_u32(bytes, 0x1b4, 1);
    put_u32(bytes, 0x1b8, test_gnu_hash("exported") & ~1U);
    put_u32(bytes, 0x1bc, test_gnu_hash("imported") | 1U);

    // ELF32_Dyn symbols: null, exported function, undefined imported function.
    put_u32(bytes, 0x210, 1);
    put_u32(bytes, 0x214, 0x300);
    put_u32(bytes, 0x218, 4);
    bytes[0x21c] = std::byte{0x12}; // STB_GLOBAL | STT_FUNC
    put_u16(bytes, 0x21e, 1);
    put_u32(bytes, 0x220, 10);
    bytes[0x22c] = std::byte{0x12};
    put_u16(bytes, 0x22e, 0); // SHN_UNDEF
    const std::string strings("\0exported\0imported\0", 19);
    for (std::size_t index = 0; index < strings.size(); ++index) {
        bytes[0x240 + index] = static_cast<std::byte>(static_cast<unsigned char>(strings[index]));
    }

    put_u32(bytes, 0x280, 0x1010);
    put_u32(bytes, 0x284, (2U << 8U) | 2U); // R_ARM_ABS32 against imported
    put_u32(bytes, 0x288, 0x1020);
    put_u32(bytes, 0x28c, 23U);              // R_ARM_RELATIVE for init_array entry
    put_u32(bytes, 0x290, 0x1024);
    put_u32(bytes, 0x294, 23U);              // R_ARM_RELATIVE for fini_array entry
    put_u32(bytes, 0x1010, 4);
    put_u32(bytes, 0x1020, 0x321);
    put_u32(bytes, 0x1024, 0x345);

    put_u32(bytes, 0x300, 0xe3a00001U); // A32 constructor: mov r0, #1
    put_u32(bytes, 0x304, 0xe12fff1eU); // bx lr
    put_u16(bytes, 0x320, 0x2102U);    // T32 constructor: movs r1, #2
    put_u16(bytes, 0x322, 0x4770U);    // bx lr
    put_u32(bytes, 0x340, 0xe12fff1eU); // A32 destructor: bx lr
    put_u16(bytes, 0x344, 0x2203U);    // T32 destructor: movs r2, #3
    put_u16(bytes, 0x346, 0x4770U);    // bx lr
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

void test_guest_memory_permissions_and_bounds() {
    using retrobridge::runtime::GuestAddress32;
    using retrobridge::runtime::GuestMemory;
    using retrobridge::runtime::GuestPermission;

    GuestMemory memory(16);
    const std::array<std::byte, 2> initial{std::byte{0x11}, std::byte{0x22}};
    check(memory.map_bytes(GuestAddress32{0x1000}, initial, 4,
        GuestPermission::Read | GuestPermission::Write), "guest region maps with zero-filled BSS");
    check(memory.map_zeroed(GuestAddress32{0x1004}, 4,
        GuestPermission::Read | GuestPermission::Execute), "adjacent guest region maps");
    check(!memory.map_zeroed(GuestAddress32{0x1002}, 4, GuestPermission::Read), "overlapping guest region is rejected");

    std::array<std::byte, 8> joined{};
    check(memory.read(GuestAddress32{0x1000}, joined), "read crosses adjacent mapped regions");
    check(joined[0] == std::byte{0x11} && joined[1] == std::byte{0x22}
        && joined[2] == std::byte{0} && joined[7] == std::byte{0}, "guest memory is zero-filled after file data");
    check(!memory.write(GuestAddress32{0x1003}, initial), "write cannot cross into a read-only region");
    check(memory.read_u8(GuestAddress32{0x1003}).value_or(1U) == 0,
        "failed cross-region write has no partial side effects");
    check(memory.protect(GuestAddress32{0x1000}, GuestPermission::Read), "guest region permissions can be tightened");
    check(!memory.write(GuestAddress32{0x1000}, initial), "read-only guest region rejects writes");
    check(memory.loader_write(GuestAddress32{0x1000}, initial), "loader can patch protected memory");
    check(memory.is_executable(GuestAddress32{0x1004}), "execute permission is tracked independently");
    check(!memory.is_executable(GuestAddress32{0x1000}), "non-executable region remains non-executable");
    check(memory.is_accessible(GuestAddress32{0x1000}, 4, GuestPermission::Read),
        "permission-aware guest buffer checks accept readable ranges");
    check(!memory.is_accessible(GuestAddress32{0x1000}, 4, GuestPermission::Write),
        "permission-aware guest buffer checks reject read-only ranges");
    check(!memory.map_zeroed(GuestAddress32{0x2000}, 32, GuestPermission::Read), "memory quota is enforced");
}

void test_elf32_loader_maps_symbols_relocations_and_constructors() {
    using namespace retrobridge::runtime;
    auto bytes = make_loadable_arm_elf();
    GuestMemory memory(0x10000);
    auto result = Elf32Loader::load(bytes, memory, {}, "fixture.so", "org.example.fixture");
    const auto* loaded = std::get_if<Elf32LoadedImage>(&result);
    if (loaded == nullptr) {
        const auto* diagnostic = std::get_if<ElfDiagnostic>(&result);
        std::cerr << "ELF loader fixture failed: " << (diagnostic == nullptr ? "unknown" : diagnostic->format()) << '\n';
        check(false, "synthetic ET_DYN is loaded");
        return;
    }

    check(loaded->mapped_regions.size() == 2, "all PT_LOAD regions are mapped");
    check(loaded->entry_point.value() == 0x40000300U, "ET_DYN entry point includes load bias");
    check(memory.is_executable(GuestAddress32{0x40000300U}), "PT_LOAD execute permission is applied");
    check(!memory.is_executable(GuestAddress32{0x40001000U}), "data segment is not executable");
    const std::array<std::byte, 1> guest_code_patch{std::byte{0}};
    check(!memory.write(GuestAddress32{0x40000300U}, guest_code_patch),
        "RX segment is not writable to guest code");
    check(memory.read_u32(GuestAddress32{0x40001250U}).value_or(1U) == 0,
        "PT_LOAD memory beyond p_filesz is zero-filled");
    check(loaded->lookup_symbol("exported").value_or(0U) == 0x40000300U,
        "SysV/GNU dynamic symbol lookup returns a guest address");
    check(!loaded->lookup_symbol("imported").has_value(), "undefined imports are not exported symbols");

    const auto unresolved = Elf32Loader::relocate(*loaded, memory);
    check(unresolved.has_value() && unresolved->code == ElfDiagnosticCode::UndefinedSymbol,
        "unresolved strong imports produce a symbol diagnostic");
    const auto relocation_error = Elf32Loader::relocate(*loaded, memory, [](std::string_view name) -> std::optional<std::uint32_t> {
        if (name == "imported") return 0x50000000U;
        return std::nullopt;
    });
    check(!relocation_error.has_value(), "supported ABS32 and RELATIVE relocations apply");
    check(memory.read_u32(GuestAddress32{0x40001010U}).value_or(0U) == 0x50000004U,
        "R_ARM_ABS32 uses external guest symbol and implicit addend");
    check(memory.read_u32(GuestAddress32{0x40001020U}).value_or(0U) == 0x40000321U,
        "R_ARM_RELATIVE adds the module load bias");

    const auto constructors_result = loaded->constructor_addresses(memory);
    const auto* constructors = std::get_if<std::vector<GuestAddress32>>(&constructors_result);
    check(constructors != nullptr && constructors->size() == 2,
        "DT_INIT and relocated DT_INIT_ARRAY functions are exposed");
    if (constructors != nullptr && constructors->size() == 2) {
        check((*constructors)[0].value() == 0x40000300U && (*constructors)[1].value() == 0x40000321U,
            "constructors retain order and Thumb entry state");
    }
    const auto destructors_result = loaded->destructor_addresses(memory);
    const auto* destructors = std::get_if<std::vector<GuestAddress32>>(&destructors_result);
    check(destructors != nullptr && destructors->size() == 2,
        "DT_FINI and relocated DT_FINI_ARRAY functions are exposed");
    if (destructors != nullptr && destructors->size() == 2) {
        check((*destructors)[0].value() == 0x40000345U && (*destructors)[1].value() == 0x40000340U,
            "destructors run in reverse array order before DT_FINI");
    }

    GuestTrampolineRegistry lifecycle_trampolines;
    Arm32Interpreter interpreter(memory, lifecycle_trampolines, {});
    GuestLifecycleExecutor lifecycle(memory, interpreter, lifecycle_trampolines);
    constexpr std::uint32_t stack_base = 0x70000000U;
    check(memory.map_zeroed(GuestAddress32{stack_base}, 0x1000,
        GuestPermission::Read | GuestPermission::Write), "constructor test stack maps RW");
    GuestCpuState32 lifecycle_state{};
    lifecycle_state.r[13] = stack_base + 0xff0U;
    const auto constructor_execution = lifecycle.run_constructors(*loaded, lifecycle_state, 64);
    check(constructor_execution.status == ExecutionStatus::Completed
            && lifecycle_state.r[0] == 1 && lifecycle_state.r[1] == 2,
        "DT_INIT and DT_INIT_ARRAY A32/T32 functions execute and return in order");
    check(constructor_execution.guest_instructions == 6,
        "constructor execution counts each guest instruction and return thunk");
    check(lifecycle_trampolines.register_trampoline("lifecycle_cleanup_probe", GuestAddress32{0xfffffff1U},
        [](GuestCpuState32&, GuestMemory&) { return GuestHookResult{}; }),
        "temporary constructor return thunk is removed after execution");
    check(lifecycle_trampolines.unregister_trampoline(GuestAddress32{0xfffffff1U}),
        "lifecycle thunk cleanup releases its guest address");
    const auto destructor_execution = lifecycle.run_destructors(*loaded, lifecycle_state, 64);
    check(destructor_execution.status == ExecutionStatus::Completed && lifecycle_state.r[2] == 3,
        "DT_FINI_ARRAY and DT_FINI A32/T32 functions execute before unload");
    check(destructor_execution.guest_instructions == 5,
        "destructor execution honors reverse array and direct-finalizer order");

    auto gnu_only_bytes = make_loadable_arm_elf(false);
    GuestMemory gnu_only_memory(0x10000);
    const auto gnu_only_result = Elf32Loader::load(
        gnu_only_bytes, gnu_only_memory, {}, "gnu-only.so", "org.example.fixture");
    const auto* gnu_only = std::get_if<Elf32LoadedImage>(&gnu_only_result);
    check(gnu_only != nullptr && gnu_only->lookup_symbol("exported").value_or(0U) == 0x40000300U,
        "GNU hash lookup works without a SysV hash table");
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

void test_native_vfs_path_translation() {
    using retrobridge::runtime::NativeVfsPathTranslator;
    const auto root = std::filesystem::temp_directory_path() / "retrobridge-vfs-path-test";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root / "internal/files");
    std::filesystem::create_directories(root / "external/data/files");
    std::filesystem::create_directories(root / "obb");
    NativeVfsPathTranslator translator(root, "org.example.app");
    check(translator.valid(), "native VFS translator accepts normalized app root and package");
    const auto internal = translator.translate("/data/data/org.example.app/files/save.bin");
    const auto alias = translator.translate("/data/user/0/org.example.app/databases/state.db");
    const auto external = translator.translate("/storage/emulated/0/Android/data/org.example.app/files/user.bin");
    const auto obb = translator.translate("/sdcard/Android/obb/org.example.app/main.1.org.example.app.obb");
    check(internal.has_value() && *internal == root / "internal/files/save.bin",
        "private data paths map beneath guest internal storage");
    check(alias.has_value() && *alias == root / "internal/databases/state.db",
        "legacy /data/user/0 package alias maps to the same root");
    check(external.has_value() && *external == root / "external/data/files/user.bin",
        "Android/data paths map beneath guest external storage");
    check(obb.has_value() && *obb == root / "obb/main.1.org.example.app.obb",
        "OBB paths map beneath guest expansion storage");
    check(!translator.translate("/data/data/org.example.app/../../outside").has_value(),
        "native VFS rejects traversal before host path normalization");
    check(!translator.translate("/data/data/org.example.app.attacker/files/x").has_value(),
        "native VFS rejects package-prefix confusion");
    check(!translator.translate("/etc/passwd").has_value(), "native VFS has no host-root fallback");
    std::filesystem::create_directory_symlink(root / "external/data", root / "internal/link", error);
    if (!error) {
        check(!translator.translate("/data/data/org.example.app/link/files/user.bin").has_value(),
            "native VFS rejects symlink components beneath the app root");
    } else {
        check(false, "native VFS symlink fixture is created");
    }
    std::filesystem::remove_all(root, error);
}

void test_native_vfs_io_and_descriptors() {
    using retrobridge::runtime::NativeVfs;
    const auto root = std::filesystem::temp_directory_path() / "retrobridge-vfs-io-test";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root / "internal/files");
    std::filesystem::create_directories(root / "external/data/files");
    std::filesystem::create_directories(root / "obb");
    NativeVfs vfs(root, "org.example.app");
    check(vfs.available(), "native VFS opens the per-app root directory");

    const auto path = "/data/data/org.example.app/files/state.bin";
    const int fd = vfs.open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    check(fd >= 3, "native VFS returns a guest descriptor, not a host path");
    if (fd >= 3) {
        const std::array<std::byte, 5> contents{std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
        check(vfs.write(fd, contents) == 5, "guest writes route into isolated internal storage");
        check(vfs.seek(fd, 0, SEEK_SET) == 0, "guest lseek updates the virtual descriptor position");
        std::array<std::byte, 8> readback{};
        check(vfs.read(fd, readback) == 5 && readback[0] == std::byte{'h'} && readback[4] == std::byte{'o'},
            "guest reads recover file contents through the VFS");
        struct stat status{};
        check(vfs.fstat(fd, &status) == 0 && status.st_size == 5, "guest fstat reports file metadata");
        check(vfs.close(fd) == 0 && vfs.close(fd) == -1, "guest descriptors close once and stale fds are rejected");
    }
    check(vfs.access(path, F_OK) == 0, "VFS access checks a path within the guest root");
    check(vfs.mkdirat(-100, "/storage/emulated/0/Android/data/org.example.app/files/cache", 0700) == 0,
        "mkdirat redirects Android/data into isolated external storage");
    const int directory_fd = vfs.open("/data/data/org.example.app/files", O_RDONLY | O_DIRECTORY);
    check(directory_fd >= 3, "guest directory opens through a virtual descriptor");
    if (directory_fd >= 3) {
        std::array<std::byte, 1024> entries{};
        const auto count = vfs.getdents64(directory_fd, entries);
        check(count > 0, "getdents64 serializes guest dirent64 records");
        const int relative_fd = vfs.openat(directory_fd, "relative.bin", O_CREAT | O_TRUNC | O_RDWR, 0600);
        check(relative_fd >= 3, "openat resolves a relative path against a guest directory descriptor");
        if (relative_fd >= 3) {
            const std::array<std::byte, 3> relative_contents{std::byte{'a'}, std::byte{'t'}, std::byte{'!'}};
            check(vfs.write(relative_fd, relative_contents) == 3, "relative openat descriptor writes inside its directory");
            struct stat relative_status{};
            check(vfs.statat(directory_fd, "relative.bin", &relative_status, 0) == 0
                    && relative_status.st_size == 3,
                "fstatat honors the guest directory descriptor");
            check(vfs.faccessat(directory_fd, "relative.bin", R_OK, 0) == 0,
                "faccessat honors the guest directory descriptor");
            check(vfs.close(relative_fd) == 0, "relative openat descriptor closes");
            check(vfs.unlinkat(directory_fd, "relative.bin", 0) == 0,
                "unlinkat honors the guest directory descriptor");
        }
        check(vfs.close(directory_fd) == 0, "guest directory descriptor closes");
    }
    check(vfs.renameat(-100, path, -100, "/data/data/org.example.app/files/renamed.bin") == 0,
        "renameat stays inside the translated guest root");
    struct stat path_status{};
    check(vfs.stat_path("/data/data/org.example.app/files/renamed.bin", &path_status) == 0
            && path_status.st_size == 5,
        "stat64 path lookup is restricted to app-private storage");
    check(vfs.unlinkat(-100, "/data/data/org.example.app/files/renamed.bin", 0) == 0,
        "unlinkat removes only a guest-owned file");
    check(vfs.open("/etc/passwd", O_RDONLY) == -1, "VFS refuses host-root path fallback");
    std::filesystem::remove_all(root, error);
}

void test_arm32_syscall_dispatcher_and_guest_vfs() {
    using namespace retrobridge::runtime;
    const auto root = std::filesystem::temp_directory_path() / "retrobridge-syscall-test";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root / "internal/files");
    std::filesystem::create_directories(root / "external/data/files");
    std::filesystem::create_directories(root / "obb");

    GuestMemory memory(2U * 1024U * 1024U);
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x10000000U}, 64U * 1024U), "syscall guest heap initializes");
    NativeVfs vfs(root, "org.example.syscall");
    Arm32SyscallDispatcher dispatcher(memory, heap, vfs);
    check(memory.map_zeroed(GuestAddress32{0x50000000U}, 0x10000,
        GuestPermission::Read | GuestPermission::Write), "syscall string and buffer memory maps RW");

    const auto write_string = [&](std::uint32_t address, std::string_view value) {
        std::vector<std::byte> bytes(value.size() + 1U, std::byte{0});
        for (std::size_t index = 0; index < value.size(); ++index) {
            bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(value[index]));
        }
        return memory.write(GuestAddress32{address}, bytes);
    };
    constexpr std::uint32_t path_address = 0x50000000U;
    constexpr std::uint32_t buffer_address = 0x50000100U;
    constexpr std::uint32_t stat_address = 0x50000200U;
    constexpr std::uint32_t cwd_address = 0x50000300U;
    check(write_string(path_address, "/data/data/org.example.syscall/files/svc.txt"),
        "guest path string is staged in guest memory");

    GuestCpuState32 state{};
    state.r[7] = 322; // openat
    state.r[0] = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(-100));
    state.r[1] = path_address;
    state.r[2] = O_CREAT | O_TRUNC | O_RDWR;
    state.r[3] = 0600;
    const auto open_result = dispatcher.handle(state, 0, memory);
    const auto guest_fd = std::bit_cast<std::int32_t>(state.r[0]);
    check(open_result.action == GuestHookAction::Continue && guest_fd >= 3,
        "ARM EABI openat dispatch returns a guest descriptor");

    const std::array<std::byte, 7> payload{std::byte{'g'}, std::byte{'u'}, std::byte{'e'}, std::byte{'s'},
        std::byte{'t'}, std::byte{'!'}, std::byte{'\n'}};
    check(memory.write(GuestAddress32{buffer_address}, payload), "guest payload is writable");
    state.r[7] = 4; // write
    state.r[0] = static_cast<std::uint32_t>(guest_fd);
    state.r[1] = buffer_address;
    state.r[2] = payload.size();
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == static_cast<std::int32_t>(payload.size()),
        "ARM EABI write copies guest bytes through the VFS");

    state.r[7] = 19; // lseek
    state.r[0] = static_cast<std::uint32_t>(guest_fd);
    state.r[1] = 0;
    state.r[2] = SEEK_SET;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0, "ARM EABI lseek resets the guest file position");
    std::array<std::byte, 16> cleared{};
    check(memory.write(GuestAddress32{buffer_address}, cleared), "guest read destination is cleared");
    state.r[7] = 3; // read
    state.r[0] = static_cast<std::uint32_t>(guest_fd);
    state.r[1] = buffer_address;
    state.r[2] = payload.size();
    (void)dispatcher.handle(state, 0, memory);
    std::array<std::byte, 7> readback{};
    check(std::bit_cast<std::int32_t>(state.r[0]) == static_cast<std::int32_t>(payload.size())
            && memory.read(GuestAddress32{buffer_address}, readback) && readback == payload,
        "ARM EABI read copies VFS contents back to guest memory");

    state.r[7] = 197; // fstat64
    state.r[0] = static_cast<std::uint32_t>(guest_fd);
    state.r[1] = stat_address;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0
            && memory.read_u32(GuestAddress32{stat_address + 44U}).value_or(0U) == payload.size(),
        "ARM EABI fstat64 writes the 32-bit guest stat64 layout");
    state.r[7] = 6; // close
    state.r[0] = static_cast<std::uint32_t>(guest_fd);
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0, "ARM EABI close releases the virtual descriptor");

    state.r[7] = 183; // getcwd
    state.r[0] = cwd_address;
    state.r[1] = 256;
    (void)dispatcher.handle(state, 0, memory);
    const auto cwd = std::string("/data/data/org.example.syscall/files");
    std::vector<std::byte> cwd_bytes(cwd.size());
    check(std::bit_cast<std::int32_t>(state.r[0]) == static_cast<std::int32_t>(cwd.size() + 1U)
            && memory.read(GuestAddress32{cwd_address}, cwd_bytes)
            && std::equal(cwd.begin(), cwd.end(), cwd_bytes.begin(), [](char left, std::byte right) {
                return static_cast<unsigned char>(left) == std::to_integer<unsigned char>(right);
            }),
        "ARM EABI getcwd returns the guest virtual path");

    check(write_string(path_address, "/data/data/org.example.syscall/../../host"),
        "hostile guest path is staged");
    state.r[7] = 5; // open
    state.r[0] = path_address;
    state.r[1] = O_RDONLY;
    state.r[2] = 0;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == -EACCES,
        "SVC open rejects path traversal rather than reaching the host filesystem");

    state.r[7] = 192; // mmap2 anonymous, private, RW
    state.r[0] = 0;
    state.r[1] = 4096;
    state.r[2] = 3;
    state.r[3] = 0x22;
    state.r[4] = 0xffffffffU;
    state.r[5] = 0;
    (void)dispatcher.handle(state, 0, memory);
    const auto mapping = state.r[0];
    check(mapping == 0x60000000U && memory.is_accessible(GuestAddress32{mapping}, 4096, GuestPermission::Write),
        "ARM EABI mmap2 allocates a bounded guest-memory mapping");
    state.r[7] = 125; // mprotect
    state.r[0] = mapping;
    state.r[1] = 4096;
    state.r[2] = 1;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0
            && memory.is_accessible(GuestAddress32{mapping}, 4096, GuestPermission::Read)
            && !memory.is_accessible(GuestAddress32{mapping}, 4096, GuestPermission::Write),
        "ARM EABI mprotect updates guest mapping permissions");
    state.r[7] = 125;
    state.r[0] = mapping;
    state.r[1] = 4096;
    state.r[2] = 3;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0, "ARM EABI mprotect restores guest mapping permissions");
    state.r[7] = 91; // munmap
    state.r[0] = mapping;
    state.r[1] = 4096;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == 0 && !memory.is_mapped(GuestAddress32{mapping}),
        "ARM EABI munmap releases the guest mapping");

    state.r[7] = 45; // brk
    state.r[0] = 0x30000010U;
    (void)dispatcher.handle(state, 0, memory);
    check(state.r[0] == 0x30000010U && memory.is_mapped(GuestAddress32{0x30000000U}, 16),
        "ARM EABI brk grows a bounded 32-bit guest heap segment");

    state.r[7] = 999999;
    (void)dispatcher.handle(state, 0, memory);
    check(std::bit_cast<std::int32_t>(state.r[0]) == -ENOSYS,
        "unknown ARM EABI syscalls fail closed with ENOSYS");
    state.r[7] = 1;
    state.r[0] = 42;
    const auto exit = dispatcher.handle(state, 0, memory);
    check(exit.action == GuestHookAction::Stop && exit.diagnostic.find("42") != std::string::npos,
        "ARM EABI exit stops the guest execution loop with its status");
    std::filesystem::remove_all(root, error);
}

void test_guest_heap_allocation_and_coalescing() {
    using namespace retrobridge::runtime;
    GuestMemory memory(8192);
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x10000000U}, 4096), "guest heap maps into guest address space");
    check(heap.initialized() && heap.capacity() == 4096, "guest heap reports its mapped capacity");

    const auto first = heap.malloc(13);
    const auto second = heap.calloc(4, 4);
    check(first.has_value() && (first->value() & 7U) == 0,
        "malloc returns an 8-byte-aligned 32-bit guest address");
    check(second.has_value() && (second->value() & 7U) == 0,
        "calloc returns an 8-byte-aligned guest address");
    if (first.has_value() && second.has_value()) {
        std::array<std::byte, 16> zeroes{};
        check(memory.read(*second, zeroes) && std::all_of(zeroes.begin(), zeroes.end(),
            [](std::byte value) { return value == std::byte{0}; }), "calloc zeroes reused guest memory");
        const std::array<std::byte, 4> marker{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
        check(memory.write(*first, marker), "guest heap allocations are writable guest memory");
        const auto grown = heap.realloc(*first, 64);
        check(grown.has_value() && heap.allocation_size(*grown).value_or(0) >= 64,
            "realloc grows a guest allocation");
        if (grown.has_value()) {
            std::array<std::byte, 4> retained{};
            check(memory.read(*grown, retained) && retained == marker,
                "realloc preserves the original guest bytes");
            check(heap.free(*grown), "grown guest allocation frees");
        }
        check(heap.free(*second), "calloc allocation frees");
    }
    check(!heap.free(first.value_or(GuestAddress32{0})), "realloc-invalidated guest address cannot be freed twice");

    GuestAddress32 aligned{0};
    check(heap.posix_memalign(&aligned, 64, 100) == 0 && (aligned.value() & 63U) == 0,
        "posix_memalign honors guest alignment");
    check(heap.free(aligned), "posix_memalign allocation frees");
    check(heap.posix_memalign(&aligned, 12, 16) == 22, "invalid POSIX alignment returns EINVAL");
    check(!heap.calloc(std::numeric_limits<std::size_t>::max(), 2).has_value(),
        "calloc detects size multiplication overflow");

    const auto whole_heap = heap.malloc(4096);
    check(whole_heap.has_value(), "free-list blocks coalesce to recover the complete heap");
    if (whole_heap.has_value()) check(heap.free(*whole_heap), "full guest heap allocation frees");
    heap.shutdown();
    check(!memory.is_mapped(GuestAddress32{0x10000000U}), "heap shutdown unmaps its guest arena");
}

void test_synthetic_jni_java_vm_tables_and_handles() {
    using namespace retrobridge::runtime;
    GuestMemory memory(1024U * 1024U);
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x10000000U}, 64U * 1024U), "JNI guest heap initializes");
    GuestTrampolineRegistry trampolines;
    GuestJniBridge jni(memory, heap, trampolines);
    std::string diagnostic;
    check(jni.initialize(&diagnostic), "synthetic JNI and JavaVM tables initialize");
    if (!jni.initialized()) {
        std::cerr << "JNI bridge diagnostic: " << diagnostic << '\n';
        return;
    }

    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U); // svc #0, used as the thunk return sentinel
    check(memory.map_bytes(GuestAddress32{0x8000U}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "JNI thunk return sentinel maps RX");
    std::array<std::byte, 4> guest_code{std::byte{0x00}, std::byte{0x00}, std::byte{0xa0}, std::byte{0xe1}};
    check(memory.map_bytes(GuestAddress32{0x9000U}, guest_code, guest_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "registered guest native method maps RX");
    check(memory.map_zeroed(GuestAddress32{0x10000U}, 0x3000U,
        GuestPermission::Read | GuestPermission::Write), "JNI test strings, table, stack, and output map RW");

    const auto write_guest_string = [&](std::uint32_t address, std::string_view text) {
        std::vector<std::byte> bytes(text.size() + 1U, std::byte{0});
        for (std::size_t index = 0; index < text.size(); ++index) {
            bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(text[index]));
        }
        return memory.write(GuestAddress32{address}, bytes);
    };
    check(write_guest_string(0x10000U, "hello JNI \xe2\x98\x83"), "JNI UTF-8 fixture is staged");
    check(write_guest_string(0x10100U, "com/example/Native"), "JNI class name fixture is staged");
    check(write_guest_string(0x10200U, "nativeCall"), "JNI native method name fixture is staged");
    check(write_guest_string(0x10300U, "([B)I"), "JNI method signature fixture is staged");

    const auto env = jni.jni_env_address().value();
    const auto vm = jni.java_vm_address().value();
    const auto jni_table = memory.read_u32(jni.jni_env_address()).value_or(0);
    const auto vm_table = memory.read_u32(jni.java_vm_address()).value_or(0);
    check(jni_table != 0 && vm_table != 0, "guest JNIEnv and JavaVM objects point at guest function tables");

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "JNI test return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected JNI test SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke_jni = [&](std::size_t index, GuestCpuState32 state) {
        const auto function = memory.read_u32(GuestAddress32{jni_table + static_cast<std::uint32_t>(index * 4U)});
        if (!function.has_value() || *function == 0) {
            check(false, "JNI table entry is populated with a guest thunk");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[14] = 0x8000U;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        return std::pair{state, result};
    };
    const auto invoke_vm = [&](std::size_t index, GuestCpuState32 state) {
        const auto function = memory.read_u32(GuestAddress32{vm_table + static_cast<std::uint32_t>(index * 4U)});
        if (!function.has_value() || *function == 0) {
            check(false, "JavaVM table entry is populated with a guest thunk");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[14] = 0x8000U;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        return std::pair{state, result};
    };

    GuestCpuState32 state{};
    state.r[0] = env;
    auto [version_state, version_execution] = invoke_jni(4, state);
    check(version_execution.status == ExecutionStatus::Completed && version_state.r[0] == 0x00010006U,
        "JNI GetVersion executes through the guest function table");

    state = {};
    state.r[0] = env;
    state.r[1] = 0x10000U;
    auto [string_state, string_execution] = invoke_jni(167, state); // NewStringUTF
    const auto string_handle = string_state.r[0];
    check(string_execution.status == ExecutionStatus::Completed && string_handle != 0,
        "JNI NewStringUTF creates a generation-checked guest handle");
    state = {};
    state.r[0] = env;
    state.r[1] = string_handle;
    auto [length_state, length_execution] = invoke_jni(164, state); // GetStringLength
    check(length_execution.status == ExecutionStatus::Completed && length_state.r[0] == 11U,
        "JNI GetStringLength counts UTF-16 code units");
    state = {};
    state.r[0] = env;
    state.r[1] = string_handle;
    state.r[2] = 0x10400U;
    auto [chars_state, chars_execution] = invoke_jni(169, state); // GetStringUTFChars
    std::array<std::byte, 14> utf8_readback{};
    const std::array<std::byte, 14> expected_utf8{std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'},
        std::byte{' '}, std::byte{'J'}, std::byte{'N'}, std::byte{'I'}, std::byte{' '}, std::byte{0xe2}, std::byte{0x98},
        std::byte{0x83}, std::byte{0}};
    check(chars_execution.status == ExecutionStatus::Completed && chars_state.r[0] != 0
            && memory.read(GuestAddress32{chars_state.r[0]}, utf8_readback) && utf8_readback == expected_utf8,
        "JNI GetStringUTFChars copies guest-visible UTF-8 bytes into the guest heap");
    state = {};
    state.r[0] = env;
    state.r[1] = string_handle;
    state.r[2] = chars_state.r[0];
    auto [release_state, release_execution] = invoke_jni(170, state); // ReleaseStringUTFChars
    check(release_execution.status == ExecutionStatus::Completed && release_state.r[0] == 0,
        "JNI ReleaseStringUTFChars frees its tracked guest buffer");

    state = {};
    state.r[0] = env;
    state.r[1] = string_handle;
    auto [global_state, global_execution] = invoke_jni(21, state); // NewGlobalRef
    const auto global_handle = global_state.r[0];
    state = {};
    state.r[0] = env;
    state.r[1] = global_handle;
    auto [kind_state, kind_execution] = invoke_jni(232, state); // GetObjectRefType
    check(global_execution.status == ExecutionStatus::Completed && kind_execution.status == ExecutionStatus::Completed
            && kind_state.r[0] == 2U,
        "JNI global references remain opaque and report the correct reference kind");
    state = {};
    state.r[0] = env;
    state.r[1] = global_handle;
    (void)invoke_jni(22, state); // DeleteGlobalRef

    state = {};
    state.r[0] = env;
    state.r[1] = 0x10100U;
    auto [class_state, class_execution] = invoke_jni(6, state); // FindClass
    const auto class_handle = class_state.r[0];
    check(class_execution.status == ExecutionStatus::Completed && class_handle != 0,
        "JNI FindClass produces an opaque class reference");
    check(memory.write_u32(GuestAddress32{0x11000U}, 0x10200U)
            && memory.write_u32(GuestAddress32{0x11004U}, 0x10300U)
            && memory.write_u32(GuestAddress32{0x11008U}, 0x9000U),
        "JNI native method descriptor is marshalled in the 32-bit guest ABI");
    state = {};
    state.r[0] = env;
    state.r[1] = class_handle;
    state.r[2] = 0x11000U;
    state.r[3] = 1;
    auto [register_state, register_execution] = invoke_jni(215, state); // RegisterNatives
    check(register_execution.status == ExecutionStatus::Completed && register_state.r[0] == 0
            && jni.registered_native_count() == 1U,
        "JNI RegisterNatives validates guest strings and executable guest function addresses");
    state = {};
    state.r[0] = env;
    state.r[1] = class_handle;
    state.r[2] = 0x10200U;
    state.r[3] = 0x10300U;
    auto [method_state, method_execution] = invoke_jni(113, state); // GetStaticMethodID
    check(method_execution.status == ExecutionStatus::Completed && method_state.r[0] >= 0xf3000000U,
        "JNI method IDs are opaque guest-width identifiers, not host pointers");

    state = {};
    state.r[0] = vm;
    state.r[1] = 0x10500U;
    state.r[2] = 0x00010006U;
    auto [getenv_state, getenv_execution] = invoke_vm(6, state); // GetEnv
    check(getenv_execution.status == ExecutionStatus::Completed && getenv_state.r[0] == 0
            && memory.read_u32(GuestAddress32{0x10500U}).value_or(0U) == env,
        "JavaVM GetEnv returns the synthetic guest JNIEnv pointer");

    state = {};
    state.r[0] = env;
    auto [unsupported_state, unsupported_execution] = invoke_jni(34, state); // CallObjectMethod (unsupported)
    (void)unsupported_state;
    state = {};
    state.r[0] = env;
    auto [exception_state, exception_execution] = invoke_jni(228, state); // ExceptionCheck
    check(unsupported_execution.status == ExecutionStatus::Completed && exception_execution.status == ExecutionStatus::Completed
            && exception_state.r[0] == 1U && !jni.pending_exception().empty(),
        "unsupported JNI calls surface a pending exception rather than fabricating host objects");
    state = {};
    state.r[0] = env;
    (void)invoke_jni(17, state); // ExceptionClear

    jni.shutdown();
    check(!jni.initialized() && !heap.allocation_size(GuestAddress32{jni_table}).has_value(),
        "JNI shutdown unregisters thunks and releases its guest tables");
    heap.shutdown();
}

void test_a32_t32_execution_svc_and_trampolines() {
    using namespace retrobridge::runtime;
    GuestMemory memory(0x10000);
    GuestTrampolineRegistry trampolines;
    auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "fixture exit"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected fixture SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    check(interpreter.available(), "A32/T32 interpreter reports an executable backend");

    std::vector<std::byte> arm_program(16, std::byte{0});
    put_u32(arm_program, 0, 0xe3a00005U);  // mov r0, #5
    put_u32(arm_program, 4, 0xe2800003U);  // add r0, r0, #3
    put_u32(arm_program, 8, 0xe3a07001U);  // mov r7, #1
    put_u32(arm_program, 12, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x1000}, arm_program, arm_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "A32 test code maps RX");
    GuestCpuState32 arm_state{};
    const auto arm_result = interpreter.run(arm_state, GuestAddress32{0x1000}, 32);
    check(arm_result.status == ExecutionStatus::Completed && arm_state.r[0] == 8,
        "A32 data-processing instructions execute until SVC exit");

    std::vector<std::byte> thumb_program(8, std::byte{0});
    put_u16(thumb_program, 0, 0x2007U); // movs r0, #7
    put_u16(thumb_program, 2, 0x3001U); // adds r0, #1
    put_u16(thumb_program, 4, 0x2701U); // movs r7, #1
    put_u16(thumb_program, 6, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2000}, thumb_program, thumb_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "T32 test code maps RX");
    GuestCpuState32 thumb_state{};
    const auto thumb_result = interpreter.run(thumb_state, GuestAddress32{0x2001}, 32);
    check(thumb_result.status == ExecutionStatus::Completed && thumb_state.r[0] == 8,
        "T32 16-bit instructions execute and SVC is dispatched");

    std::vector<std::byte> wide_thumb_program(12, std::byte{0});
    put_u16(wide_thumb_program, 0, 0xf240U); // movw r0, #40
    put_u16(wide_thumb_program, 2, 0x0028U);
    put_u16(wide_thumb_program, 4, 0xf2c0U); // movt r0, #1
    put_u16(wide_thumb_program, 6, 0x0001U);
    put_u16(wide_thumb_program, 8, 0x2701U); // movs r7, #1
    put_u16(wide_thumb_program, 10, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2100}, wide_thumb_program, wide_thumb_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "wide T32 test code maps RX");
    GuestCpuState32 wide_thumb_state{};
    const auto wide_thumb_result = interpreter.run(wide_thumb_state, GuestAddress32{0x2101}, 32);
    check(wide_thumb_result.status == ExecutionStatus::Completed && wide_thumb_state.r[0] == 0x00010028U,
        "T32 32-bit MOVW/MOVT instructions decode and execute");

    std::vector<std::byte> caller_program(16, std::byte{0});
    put_u32(caller_program, 0, 0xe3a00009U);  // mov r0, #9
    put_u32(caller_program, 4, 0xeb000001U);  // bl 0x3010
    put_u32(caller_program, 8, 0xe3a07001U);  // mov r7, #1
    put_u32(caller_program, 12, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3000}, caller_program, caller_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "trampoline caller code maps RX");
    check(trampolines.register_trampoline("fixture_thunk", GuestAddress32{0x3010},
        [](GuestCpuState32& state, GuestMemory&) {
            state.r[0] += 4;
            return GuestHookResult{};
        }), "guest thunk registers by guest symbol name and address");
    check(trampolines.resolve_symbol("fixture_thunk").value_or(0U) == 0x3010U,
        "guest linker can resolve a registered trampoline symbol");
    GuestCpuState32 caller_state{};
    const auto trampoline_result = interpreter.run(caller_state, GuestAddress32{0x3000}, 32);
    check(trampoline_result.status == ExecutionStatus::Completed && caller_state.r[0] == 13,
        "A32 BL calls a host thunk and returns through guest LR");
    check(trampoline_result.guest_instructions == 5,
        "trampoline dispatch consumes one bounded guest instruction step");

    std::vector<std::byte> loop_program(4, std::byte{0});
    put_u32(loop_program, 0, 0xeafffffeU); // b .
    check(memory.map_bytes(GuestAddress32{0x4000}, loop_program, loop_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "bounded-loop test code maps RX");
    GuestCpuState32 loop_state{};
    const auto loop_result = interpreter.run(loop_state, GuestAddress32{0x4000}, 3);
    check(loop_result.status == ExecutionStatus::BudgetExhausted && loop_result.guest_instructions == 3,
        "A32 backward branches cannot exceed the instruction budget");
}

void test_capabilities_and_optional_dbt_placeholder() {
    retrobridge::runtime::UnavailableTranslationEngine engine;
    retrobridge::runtime::GuestCpuState32 state{};
    const auto result = engine.run(state, retrobridge::runtime::GuestAddress32{0x1000}, 100);
    check(!engine.available(), "placeholder translator reports unavailable");
    check(result.status == retrobridge::runtime::ExecutionStatus::BackendUnavailable, "placeholder refuses guest execution");
    check(retrobridge::runtime::current_capabilities().arm32_elf_metadata_validation, "ELF metadata validation is reported available");
    check(retrobridge::runtime::current_capabilities().guest_elf_mapping_and_supported_relocations,
        "guest ELF mapping and relocation support is reported available");
    check(retrobridge::runtime::current_capabilities().guest_heap_allocator,
        "guest heap allocation is reported available");
    check(retrobridge::runtime::current_capabilities().native_guest_vfs,
        "native app-private guest VFS is reported available");
    check(retrobridge::runtime::current_capabilities().arm32_eabi_syscall_subset,
        "the implemented ARM32 EABI syscall subset is reported available");
    check(!retrobridge::runtime::current_capabilities().bionic_and_guest_syscalls,
        "unimplemented Bionic symbols and syscalls are not reported as complete");
    check(retrobridge::runtime::current_capabilities().synthetic_jni_tables_and_handle_subset,
        "synthetic JNI/JavaVM tables and the tested handle subset are reported available");
    check(!retrobridge::runtime::current_capabilities().synthetic_jni,
        "partial JNI support is not reported as a complete virtual Java runtime");
    check(retrobridge::runtime::current_capabilities().arm32_instruction_execution,
        "bounded ARM instruction interpretation is reported available");
    check(!retrobridge::runtime::current_capabilities().arbitrary_guest_execution,
        "arbitrary guest execution remains unavailable pending a full compatibility/security layer");
}

}  // namespace

int main() {
    test_guest_address_boundary();
    test_guest_memory_permissions_and_bounds();
    test_elf32_loader_maps_symbols_relocations_and_constructors();
    test_elf_validation_and_dependencies();
    test_opaque_handles_and_generation();
    test_native_vfs_path_translation();
    test_native_vfs_io_and_descriptors();
    test_guest_heap_allocation_and_coalescing();
    test_arm32_syscall_dispatcher_and_guest_vfs();
    test_synthetic_jni_java_vm_tables_and_handles();
    test_a32_t32_execution_svc_and_trampolines();
    test_capabilities_and_optional_dbt_placeholder();
    if (failures != 0) {
        std::cerr << failures << " native verification check(s) failed\n";
        return 1;
    }
    std::cout << "Native verification checks passed\n";
    return 0;
}
