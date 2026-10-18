#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/elf32_image.h"
#include "retrobridge/elf32_loader.h"
#include "retrobridge/guest_address.h"
#include "retrobridge/guest_memory.h"
#include "retrobridge/guest_lifecycle.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/guest_jni_bridge.h"
#include "retrobridge/guest_bionic_thunks.h"
#include "retrobridge/guest_android_asset_thunks.h"
#include "retrobridge/guest_android_window_thunks.h"
#include "retrobridge/guest_android_input_thunks.h"
#include "retrobridge/guest_headless_gles_egl_thunks.h"
#include "retrobridge/guest_opensl_thunks.h"
#include "retrobridge/native_execution_session.h"
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
    put_u32(bytes, 100, 40);
    put_u32(bytes, 104, 40);
    put_u32(bytes, 108, 4);
    put_u32(bytes, 112, 4);

    put_u32(bytes, 0x100, 5);       // DT_STRTAB
    put_u32(bytes, 0x104, 0x180);
    put_u32(bytes, 0x108, 10);      // DT_STRSZ
    put_u32(bytes, 0x10c, 15);
    put_u32(bytes, 0x110, 1);       // DT_NEEDED
    put_u32(bytes, 0x114, 1);
    put_u32(bytes, 0x118, 14);      // DT_SONAME
    put_u32(bytes, 0x11c, 1);
    put_u32(bytes, 0x120, 0);       // DT_NULL
    put_u32(bytes, 0x124, 0);
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

void test_native_execution_session_runs_mapped_library_lifecycle() {
    using namespace retrobridge::runtime;
    auto bytes = make_loadable_arm_elf();
    // Keep only the two R_ARM_RELATIVE relocations used to initialize constructor/finalizer arrays.
    put_u32(bytes, 0x134, 0x288); // DT_REL
    put_u32(bytes, 0x13c, 16);    // DT_RELSZ

    const auto root = std::filesystem::temp_directory_path()
        / ("retrobridge-native-session-" + std::to_string(static_cast<unsigned long long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "internal/files");
    std::filesystem::create_directories(root / "external/data");
    std::filesystem::create_directories(root / "obb");
    std::filesystem::create_directories(root / "runtime/native");

    {
        NativeExecutionSession session(root, "org.example.nativefixture");
        std::string diagnostic;
        check(session.initialize(&diagnostic), "native execution session installs bounded guest services");
        if (session.initialized()) {
            const auto loaded = session.load_library(bytes, "libsession_fixture.so");
            check(loaded.loaded && loaded.load_address == 0x40000000U,
                "native execution session maps a verified ARM32 ET_DYN image");
            const auto report = session.execute(128);
            check(report.success, "native execution session executes mapped constructors under budget");
            check(report.guest_instructions == 6,
                "native execution report counts real A32/T32 constructor instructions and return thunks");
            check(report.relocation_count == 2,
                "native execution report records applied constructor-array relocations");
            check(report.loaded_libraries.size() == 1 && report.loaded_libraries.front() == "libsession_fixture.so",
                "native execution report names loaded guest libraries");
            session.stop();
        } else {
            std::cerr << "Native session initialization diagnostic: " << diagnostic << '\n';
        }
    }
    std::filesystem::remove_all(root);
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
        check(image->soname().value_or("") == "libfixture.so", "DT_SONAME is extracted for dependency ordering");
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

void test_guest_bionic_libc_libm_and_pthread_thunks() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kGuestData = 0x20000U;

    GuestMemory memory(1024U * 1024U);
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x10000000U}, 64U * 1024U), "Bionic thunk guest heap initializes");
    GuestTrampolineRegistry trampolines;
    const std::array<std::byte, 4> return_code{std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xef}};
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "Bionic thunk return SVC maps executable");
    check(memory.map_zeroed(GuestAddress32{kGuestData}, 0x4000U,
        GuestPermission::Read | GuestPermission::Write), "Bionic thunk test buffers map read/write");

    const auto root = std::filesystem::temp_directory_path()
        / ("retrobridge-native-bionic-" + std::to_string(::getpid()));
    std::error_code filesystem_error;
    std::filesystem::remove_all(root, filesystem_error);
    filesystem_error.clear();
    std::filesystem::create_directories(root / "internal/files", filesystem_error);
    check(!filesystem_error, "Bionic thunk VFS test root is created");
    {
        NativeVfs vfs(root, "org.retrobridge.native");
        check(vfs.available(), "Bionic thunk VFS is available for an isolated app root");
        GuestBionicThunks thunks(memory, heap, trampolines, &vfs);
        std::string diagnostic;
        check(thunks.install(&diagnostic), "Bionic/libc/libm/pthread thunk table installs");
        if (!diagnostic.empty()) std::cerr << "Bionic thunk diagnostic: " << diagnostic << '\n';
        check(thunks.installed(), "Bionic thunk table records its initialized state");
        check(thunks.resolve_symbol("malloc").has_value() && thunks.resolve_symbol("pthread_mutex_lock").has_value()
                && thunks.resolve_symbol("sqrtf").has_value() && thunks.resolve_symbol("mkdir").has_value()
                && thunks.resolve_symbol("rename").has_value() && thunks.resolve_symbol("getdents64").has_value()
                && thunks.resolve_symbol("openat").has_value() && thunks.resolve_symbol("mkdirat").has_value()
                && thunks.resolve_symbol("unlinkat").has_value() && thunks.resolve_symbol("renameat").has_value()
                && thunks.resolve_symbol("faccessat").has_value()
                && thunks.resolve_symbol("__android_log_write").has_value(),
            "Bionic symbol resolver exposes allocator, pthread, libm, file/directory, and logging subsets");
        check(thunks.resolve_guest_symbol("__stack_chk_guard").value_or(0U) == thunks.stack_guard_cell().value()
                && thunks.resolve_data_symbol("errno").value_or(GuestAddress32{0}) == thunks.errno_cell(),
            "guest symbol resolver returns data-cell addresses for stack guard and errno");

        const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
            if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "Bionic thunk return"};
            return GuestHookResult{GuestHookAction::Fault, "unexpected Bionic thunk SVC"};
        };
        Arm32Interpreter interpreter(memory, trampolines, svc);
        const auto invoke = [&](std::string_view name, GuestCpuState32 state) {
            const auto function = thunks.resolve_symbol(name);
            if (!function.has_value()) {
                check(false, "Bionic test symbol resolves to a guest trampoline");
                return std::pair{state, ExecutionResult{}};
            }
            state.r[7] = 1;
            state.r[14] = kReturnAddress;
            auto result = interpreter.run(state, GuestAddress32{*function}, 16);
            check(result.status == ExecutionStatus::Completed, "Bionic thunk returns through guest execution");
            return std::pair{state, result};
        };
        const auto write_guest_string = [&](std::uint32_t address, std::string_view text) {
            std::vector<std::byte> bytes(text.size() + 1U, std::byte{0});
            for (std::size_t index = 0; index < text.size(); ++index) {
                bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(text[index]));
            }
            return memory.write(GuestAddress32{address}, bytes);
        };

        GuestCpuState32 state{};
        state.r[0] = 17;
        auto [malloc_state, malloc_result] = invoke("malloc", state);
        const auto allocated = GuestAddress32{malloc_state.r[0]};
        check(malloc_result.status == ExecutionStatus::Completed && allocated.value() != 0
                && (allocated.value() & 7U) == 0,
            "guest malloc returns a non-null aligned 32-bit allocation");

        state = {};
        state.r[0] = 8;
        state.r[1] = 4;
        auto [calloc_state, calloc_result] = invoke("calloc", state);
        std::array<std::byte, 32> zeroed{};
        check(calloc_result.status == ExecutionStatus::Completed && calloc_state.r[0] != 0
                && memory.read(GuestAddress32{calloc_state.r[0]}, zeroed)
                && std::all_of(zeroed.begin(), zeroed.end(), [](std::byte value) { return value == std::byte{0}; }),
            "guest calloc detects multiplication safely and zeroes guest memory");

        if (allocated.value() != 0) {
            const std::array<std::byte, 4> marker{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
            check(memory.write(allocated, marker), "guest malloc buffer is writable");
            state = {};
            state.r[0] = allocated.value();
            state.r[1] = 128;
            auto [realloc_state, realloc_result] = invoke("realloc", state);
            std::array<std::byte, 4> retained{};
            check(realloc_result.status == ExecutionStatus::Completed && realloc_state.r[0] != 0
                    && memory.read(GuestAddress32{realloc_state.r[0]}, retained) && retained == marker,
                "guest realloc grows an allocation while preserving its bytes");
            state = {};
            state.r[0] = realloc_state.r[0];
            (void)invoke("free", state);
        }
        if (calloc_state.r[0] != 0) {
            state = {};
            state.r[0] = calloc_state.r[0];
            (void)invoke("free", state);
        }

        state = {};
        state.r[0] = 32;
        state.r[1] = 64;
        auto [aligned_state, aligned_result] = invoke("memalign", state);
        check(aligned_result.status == ExecutionStatus::Completed && aligned_state.r[0] != 0
                && (aligned_state.r[0] & 31U) == 0,
            "guest memalign honors a valid power-of-two alignment");
        state = {};
        state.r[0] = kGuestData + 0x100U;
        state.r[1] = 0x5aU;
        state.r[2] = 8;
        auto [memset_state, memset_result] = invoke("memset", state);
        std::array<std::byte, 8> filled{};
        check(memset_result.status == ExecutionStatus::Completed && memset_state.r[0] == kGuestData + 0x100U
                && memory.read(GuestAddress32{kGuestData + 0x100U}, filled)
                && std::all_of(filled.begin(), filled.end(), [](std::byte value) { return value == std::byte{0x5a}; }),
            "libc memset fills guest memory and returns the destination");
        state = {};
        state.r[0] = kGuestData + 0x100U;
        state.r[1] = 8;
        state.r[2] = 0x33U;
        (void)invoke("__aeabi_memset", state);
        check(memory.read(GuestAddress32{kGuestData + 0x100U}, filled)
                && std::all_of(filled.begin(), filled.end(), [](std::byte value) { return value == std::byte{0x33}; }),
            "ARM EABI memset uses its destination, length, value argument order");
        state = {};
        state.r[0] = kGuestData + 0x100U;
        state.r[1] = 8;
        (void)invoke("__aeabi_memclr", state);
        check(memory.read(GuestAddress32{kGuestData + 0x100U}, filled)
                && std::all_of(filled.begin(), filled.end(), [](std::byte value) { return value == std::byte{0}; }),
            "ARM EABI memclr zeroes a guest buffer");

        check(write_guest_string(kGuestData + 0x200U, "guest")
                && write_guest_string(kGuestData + 0x220U, "guest")
                && write_guest_string(kGuestData + 0x240U, "guest!"),
            "Bionic string fixtures are staged in guest memory");
        state = {};
        state.r[0] = kGuestData + 0x200U;
        auto [strlen_state, strlen_result] = invoke("strlen", state);
        check(strlen_result.status == ExecutionStatus::Completed && strlen_state.r[0] == 5U,
            "guest strlen counts bytes up to the terminating NUL");
        state = {};
        state.r[0] = kGuestData + 0x200U;
        state.r[1] = kGuestData + 0x220U;
        auto [strcmp_equal, strcmp_equal_result] = invoke("strcmp", state);
        check(strcmp_equal_result.status == ExecutionStatus::Completed && strcmp_equal.r[0] == 0,
            "guest strcmp reports equal strings");
        state = {};
        state.r[0] = kGuestData + 0x200U;
        state.r[1] = kGuestData + 0x240U;
        state.r[2] = 5;
        auto [strncmp_equal, strncmp_result] = invoke("strncmp", state);
        check(strncmp_result.status == ExecutionStatus::Completed && strncmp_equal.r[0] == 0,
            "guest strncmp compares at most the requested bytes");
        state = {};
        state.r[0] = kGuestData + 0x260U;
        state.r[1] = kGuestData + 0x200U;
        state.r[2] = 4;
        (void)invoke("strncpy", state);
        std::array<std::byte, 4> copied_string{};
        check(memory.read(GuestAddress32{kGuestData + 0x260U}, copied_string)
                && copied_string == std::array<std::byte, 4>{std::byte{'g'}, std::byte{'u'}, std::byte{'e'}, std::byte{'s'}},
            "guest strncpy copies a bounded non-NUL-terminated prefix");
        state = {};
        state.r[0] = kGuestData + 0x200U;
        auto [strdup_state, strdup_result] = invoke("strdup", state);
        std::array<std::byte, 6> duplicated{};
        check(strdup_result.status == ExecutionStatus::Completed && strdup_state.r[0] != 0
                && memory.read(GuestAddress32{strdup_state.r[0]}, duplicated)
                && duplicated == std::array<std::byte, 6>{std::byte{'g'}, std::byte{'u'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'}, std::byte{0}},
            "guest strdup allocates and copies the terminating NUL");
        state = {};
        state.r[0] = strdup_state.r[0];
        (void)invoke("free", state);

        const std::array<std::byte, 5> overlap_source{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}, std::byte{'e'}};
        check(memory.write(GuestAddress32{kGuestData + 0x300U}, overlap_source), "memmove overlap fixture is staged");
        state = {};
        state.r[0] = kGuestData + 0x301U;
        state.r[1] = kGuestData + 0x300U;
        state.r[2] = 4;
        (void)invoke("memmove", state);
        std::array<std::byte, 5> overlap_result{};
        check(memory.read(GuestAddress32{kGuestData + 0x300U}, overlap_result)
                && overlap_result == std::array<std::byte, 5>{std::byte{'a'}, std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}},
            "guest memmove handles overlapping ranges using bounded staging");

        state = {};
        state.r[0] = std::bit_cast<std::uint32_t>(9.0F);
        auto [sqrt_state, sqrt_result] = invoke("sqrtf", state);
        check(sqrt_result.status == ExecutionStatus::Completed
                && std::bit_cast<float>(sqrt_state.r[0]) == 3.0F,
            "libm sqrtf computes using ARM32 single-precision register arguments");
        state = {};
        state.r[0] = std::bit_cast<std::uint32_t>(2.0F);
        state.r[1] = std::bit_cast<std::uint32_t>(3.0F);
        auto [pow_state, pow_result] = invoke("powf", state);
        check(pow_result.status == ExecutionStatus::Completed
                && std::bit_cast<float>(pow_state.r[0]) == 8.0F,
            "libm powf computes from two guest single-precision arguments");
        state = {};
        state.r[0] = 17;
        state.r[1] = 5;
        auto [div_state, div_result] = invoke("__aeabi_idivmod", state);
        check(div_result.status == ExecutionStatus::Completed && div_state.r[0] == 3U && div_state.r[1] == 2U,
            "ARM EABI signed division helper returns quotient and remainder");

        const auto mutex_address = heap.malloc(64);
        check(mutex_address.has_value(), "guest memory for a synthetic pthread mutex allocates");
        if (mutex_address.has_value()) {
            state = {};
            state.r[0] = mutex_address->value();
            auto [mutex_init_state, mutex_init_result] = invoke("pthread_mutex_init", state);
            check(mutex_init_result.status == ExecutionStatus::Completed && mutex_init_state.r[0] == 0,
                "pthread mutex initializer creates a host-backed guest mutex object");
            state = {};
            state.r[0] = mutex_address->value();
            auto [lock_state, lock_result] = invoke("pthread_mutex_lock", state);
            check(lock_result.status == ExecutionStatus::Completed && lock_state.r[0] == 0,
                "pthread mutex lock acquires a free guest mutex");
            state = {};
            state.r[0] = mutex_address->value();
            auto [recursive_lock_state, recursive_lock_result] = invoke("pthread_mutex_lock", state);
            check(recursive_lock_result.status == ExecutionStatus::Completed && recursive_lock_state.r[0] == 35U,
                "pthread mutex lock reports EDEADLK instead of hanging without a guest scheduler");
            state = {};
            state.r[0] = mutex_address->value();
            auto [try_state, try_result] = invoke("pthread_mutex_trylock", state);
            check(try_result.status == ExecutionStatus::Completed && try_state.r[0] == 16U,
                "pthread mutex trylock reports EBUSY for a locked mutex");
            state = {};
            state.r[0] = mutex_address->value();
            auto [unlock_state, unlock_result] = invoke("pthread_mutex_unlock", state);
            check(unlock_result.status == ExecutionStatus::Completed && unlock_state.r[0] == 0,
                "pthread mutex unlock releases the guest mutex");
            state = {};
            state.r[0] = mutex_address->value();
            auto [destroy_state, destroy_result] = invoke("pthread_mutex_destroy", state);
            check(destroy_result.status == ExecutionStatus::Completed && destroy_state.r[0] == 0,
                "pthread mutex destroy drops its host-side state");
            check(heap.free(*mutex_address), "guest pthread mutex backing storage frees");
        }

        state = {};
        state.r[0] = kGuestData + 0x380U;
        auto [key_state, key_result] = invoke("pthread_key_create", state);
        const auto key = memory.read_u32(GuestAddress32{kGuestData + 0x380U}).value_or(0U);
        check(key_result.status == ExecutionStatus::Completed && key_state.r[0] == 0 && key != 0,
            "pthread TLS key creation writes a synthetic guest key");
        state = {};
        state.r[0] = key;
        state.r[1] = 0x12345678U;
        auto [set_state, set_result] = invoke("pthread_setspecific", state);
        state = {};
        state.r[0] = key;
        auto [get_state, get_result] = invoke("pthread_getspecific", state);
        check(set_result.status == ExecutionStatus::Completed && set_state.r[0] == 0
                && get_result.status == ExecutionStatus::Completed && get_state.r[0] == 0x12345678U,
            "pthread TLS stores and retrieves an opaque guest-width value");
        state = {};
        state.r[0] = key;
        auto [delete_key_state, delete_key_result] = invoke("pthread_key_delete", state);
        check(delete_key_result.status == ExecutionStatus::Completed && delete_key_state.r[0] == 0,
            "pthread TLS key deletion clears its synthetic value");
        state = {};
        state.r[0] = 0;
        state.r[1] = 0;
        state.r[2] = 0;
        state.r[3] = 0;
        auto [create_thread_state, create_thread_result] = invoke("pthread_create", state);
        check(create_thread_result.status == ExecutionStatus::Completed && create_thread_state.r[0] == 11U,
            "unsupported pthread_create returns EAGAIN instead of fabricating a guest thread");

        check(write_guest_string(kGuestData + 0x400U, "/data/user/0/org.retrobridge.native/files/guest.bin"),
            "guest VFS file path is staged");
        state = {};
        state.r[0] = kGuestData + 0x400U;
        state.r[1] = static_cast<std::uint32_t>(O_CREAT | O_RDWR | O_TRUNC);
        state.r[2] = 0600;
        auto [open_state, open_result] = invoke("open", state);
        const auto guest_fd = std::bit_cast<std::int32_t>(open_state.r[0]);
        check(open_result.status == ExecutionStatus::Completed && guest_fd >= 3,
            "guest libc open uses the app-private VFS descriptor table");
        if (guest_fd >= 0) {
            const std::array<std::byte, 6> file_bytes{std::byte{'r'}, std::byte{'u'}, std::byte{'n'}, std::byte{'t'}, std::byte{'i'}, std::byte{'m'}};
            check(memory.write(GuestAddress32{kGuestData + 0x500U}, file_bytes), "guest VFS write bytes are staged");
            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            state.r[1] = kGuestData + 0x500U;
            state.r[2] = static_cast<std::uint32_t>(file_bytes.size());
            auto [write_state, write_result] = invoke("write", state);
            check(write_result.status == ExecutionStatus::Completed && write_state.r[0] == file_bytes.size(),
                "guest libc write persists bytes through the VFS");

            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            state.r[1] = 2;
            state.r[2] = 0;
            auto [seek_state, seek_result] = invoke("lseek", state);
            check(seek_result.status == ExecutionStatus::Completed && seek_state.r[0] == 2U,
                "guest 32-bit lseek repositions a VFS descriptor");
            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            state.r[1] = 0;
            state.r[2] = 0;
            state.r[3] = 1;
            state.r[13] = kGuestData + 0x600U;
            check(memory.write_u32(GuestAddress32{kGuestData + 0x600U}, 0), "lseek64 stack whence argument is staged");
            auto [seek64_state, seek64_result] = invoke("lseek64", state);
            check(seek64_result.status == ExecutionStatus::Completed && seek64_state.r[0] == 0U && seek64_state.r[1] == 1U,
                "guest lseek64 marshals an aligned ARM32 64-bit offset and stack whence");
            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            state.r[1] = 0;
            state.r[2] = 0;
            (void)invoke("lseek", state);
            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            state.r[1] = kGuestData + 0x520U;
            state.r[2] = static_cast<std::uint32_t>(file_bytes.size());
            auto [read_state, read_result] = invoke("read", state);
            std::array<std::byte, 6> readback{};
            check(read_result.status == ExecutionStatus::Completed && read_state.r[0] == file_bytes.size()
                    && memory.read(GuestAddress32{kGuestData + 0x520U}, readback) && readback == file_bytes,
                "guest libc read copies descriptor bytes back into guest memory");
            state = {};
            state.r[0] = static_cast<std::uint32_t>(guest_fd);
            auto [close_state, close_result] = invoke("close", state);
            check(close_result.status == ExecutionStatus::Completed && close_state.r[0] == 0,
                "guest libc close releases its virtual descriptor");
        }
        check(write_guest_string(kGuestData + 0x780U, "/data/user/0/org.retrobridge.native/files"),
            "guest directory path is staged");
        state = {};
        state.r[0] = kGuestData + 0x780U;
        state.r[1] = static_cast<std::uint32_t>(O_RDONLY | O_DIRECTORY);
        auto [directory_open_state, directory_open_result] = invoke("open", state);
        const auto directory_fd = std::bit_cast<std::int32_t>(directory_open_state.r[0]);
        check(directory_open_result.status == ExecutionStatus::Completed && directory_fd >= 3,
            "Bionic open returns a virtual descriptor for an app-private directory");
        if (directory_fd >= 3) {
            state = {};
            state.r[0] = static_cast<std::uint32_t>(directory_fd);
            state.r[1] = kGuestData + 0x1000U;
            state.r[2] = 1024U;
            auto [getdents_state, getdents_result] = invoke("getdents64", state);
            const auto returned_bytes = std::min<std::uint32_t>(getdents_state.r[0], 1024U);
            std::array<std::byte, 10> guest_file_name{
                std::byte{'g'}, std::byte{'u'}, std::byte{'e'}, std::byte{'s'}, std::byte{'t'},
                std::byte{'.'}, std::byte{'b'}, std::byte{'i'}, std::byte{'n'}, std::byte{0},
            };
            std::array<std::byte, 1024> directory_bytes{};
            check(getdents_result.status == ExecutionStatus::Completed && returned_bytes > 0
                    && memory.read(GuestAddress32{kGuestData + 0x1000U}, directory_bytes)
                    && std::search(directory_bytes.begin(), directory_bytes.begin() + returned_bytes,
                        guest_file_name.begin(), guest_file_name.end())
                        != directory_bytes.begin() + returned_bytes,
                "Bionic getdents64 copies bounded Linux dirent64 records into guest memory");
            state = {};
            state.r[0] = static_cast<std::uint32_t>(directory_fd);
            auto [directory_close_state, directory_close_result] = invoke("close", state);
            check(directory_close_result.status == ExecutionStatus::Completed && directory_close_state.r[0] == 0,
                "Bionic close releases a guest directory stream");
        }

        check(write_guest_string(kGuestData + 0x780U, "/data/user/0/org.retrobridge.native/files/guest.bin")
                && write_guest_string(kGuestData + 0x820U, "/data/user/0/org.retrobridge.native/files/renamed.bin"),
            "guest rename source and destination paths are staged");
        state = {};
        state.r[0] = kGuestData + 0x780U;
        state.r[1] = kGuestData + 0x820U;
        auto [rename_state, rename_result] = invoke("rename", state);
        check(rename_result.status == ExecutionStatus::Completed && rename_state.r[0] == 0,
            "Bionic rename moves a file only within the app-private VFS");
        state = {};
        state.r[0] = kGuestData + 0x820U;
        state.r[1] = F_OK;
        auto [renamed_access_state, renamed_access_result] = invoke("access", state);
        check(renamed_access_result.status == ExecutionStatus::Completed && renamed_access_state.r[0] == 0,
            "Bionic access finds a renamed guest file");
        state = {};
        state.r[0] = kGuestData + 0x820U;
        auto [unlink_state, unlink_result] = invoke("unlink", state);
        state = {};
        state.r[0] = kGuestData + 0x820U;
        state.r[1] = F_OK;
        auto [removed_access_state, removed_access_result] = invoke("access", state);
        check(unlink_result.status == ExecutionStatus::Completed && unlink_state.r[0] == 0
                && removed_access_result.status == ExecutionStatus::Completed
                && std::bit_cast<std::int32_t>(removed_access_state.r[0]) == -1
                && memory.read_u32(thunks.errno_cell()).value_or(0U) == ENOENT,
            "Bionic unlink removes a guest file and access reports its real ENOENT status");

        check(write_guest_string(kGuestData + 0x880U, "/data/user/0/org.retrobridge.native/files/cache-dir"),
            "guest directory mutation path is staged");
        state = {};
        state.r[0] = kGuestData + 0x880U;
        state.r[1] = 0700U;
        auto [mkdir_state, mkdir_result] = invoke("mkdir", state);
        state = {};
        state.r[0] = kGuestData + 0x880U;
        state.r[1] = F_OK;
        auto [directory_access_state, directory_access_result] = invoke("access", state);
        state = {};
        state.r[0] = kGuestData + 0x880U;
        auto [rmdir_state, rmdir_result] = invoke("rmdir", state);
        check(mkdir_result.status == ExecutionStatus::Completed && mkdir_state.r[0] == 0
                && directory_access_result.status == ExecutionStatus::Completed && directory_access_state.r[0] == 0
                && rmdir_result.status == ExecutionStatus::Completed && rmdir_state.r[0] == 0,
            "Bionic mkdir/access/rmdir operate on app-private directories");

        check(write_guest_string(kGuestData + 0x940U, "/data/user/0/org.retrobridge.native/files/at-dir")
                && write_guest_string(kGuestData + 0x980U, "child.txt")
                && write_guest_string(kGuestData + 0x9a0U, "moved.txt")
                && write_guest_string(kGuestData + 0x9c0U, "nested"),
            "guest *at API paths are staged");
        state = {};
        state.r[0] = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(AT_FDCWD));
        state.r[1] = kGuestData + 0x940U;
        state.r[2] = 0700U;
        auto [mkdirat_state, mkdirat_result] = invoke("mkdirat", state);
        state = {};
        state.r[0] = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(AT_FDCWD));
        state.r[1] = kGuestData + 0x940U;
        state.r[2] = static_cast<std::uint32_t>(O_RDONLY | O_DIRECTORY);
        auto [openat_directory_state, openat_directory_result] = invoke("openat", state);
        const auto openat_directory_fd = std::bit_cast<std::int32_t>(openat_directory_state.r[0]);
        bool at_apis_passed = mkdirat_result.status == ExecutionStatus::Completed && mkdirat_state.r[0] == 0
            && openat_directory_result.status == ExecutionStatus::Completed && openat_directory_fd >= 3;
        if (openat_directory_fd >= 3) {
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x980U;
            state.r[2] = static_cast<std::uint32_t>(O_CREAT | O_RDWR | O_TRUNC);
            state.r[3] = 0600U;
            auto [openat_file_state, openat_file_result] = invoke("openat", state);
            const auto openat_file_fd = std::bit_cast<std::int32_t>(openat_file_state.r[0]);
            at_apis_passed = at_apis_passed && openat_file_result.status == ExecutionStatus::Completed
                && openat_file_fd >= 3;
            if (openat_file_fd >= 3) {
                state = {};
                state.r[0] = static_cast<std::uint32_t>(openat_file_fd);
                auto [close_at_file_state, close_at_file_result] = invoke("close", state);
                at_apis_passed = at_apis_passed && close_at_file_result.status == ExecutionStatus::Completed
                    && close_at_file_state.r[0] == 0;
            }
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x980U;
            state.r[2] = F_OK;
            auto [faccessat_state, faccessat_result] = invoke("faccessat", state);
            at_apis_passed = at_apis_passed && faccessat_result.status == ExecutionStatus::Completed
                && faccessat_state.r[0] == 0;
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x980U;
            state.r[2] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[3] = kGuestData + 0x9a0U;
            auto [renameat_state, renameat_result] = invoke("renameat", state);
            at_apis_passed = at_apis_passed && renameat_result.status == ExecutionStatus::Completed
                && renameat_state.r[0] == 0;
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x9c0U;
            state.r[2] = 0700U;
            auto [relative_mkdirat_state, relative_mkdirat_result] = invoke("mkdirat", state);
            at_apis_passed = at_apis_passed && relative_mkdirat_result.status == ExecutionStatus::Completed
                && relative_mkdirat_state.r[0] == 0;
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x9a0U;
            state.r[2] = 0U;
            auto [unlinkat_file_state, unlinkat_file_result] = invoke("unlinkat", state);
            at_apis_passed = at_apis_passed && unlinkat_file_result.status == ExecutionStatus::Completed
                && unlinkat_file_state.r[0] == 0;
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            state.r[1] = kGuestData + 0x9c0U;
            state.r[2] = static_cast<std::uint32_t>(AT_REMOVEDIR);
            auto [unlinkat_directory_state, unlinkat_directory_result] = invoke("unlinkat", state);
            at_apis_passed = at_apis_passed && unlinkat_directory_result.status == ExecutionStatus::Completed
                && unlinkat_directory_state.r[0] == 0;
            state = {};
            state.r[0] = 99U;
            state.r[1] = kGuestData + 0x9a0U;
            state.r[2] = F_OK;
            auto [bad_faccessat_state, bad_faccessat_result] = invoke("faccessat", state);
            at_apis_passed = at_apis_passed && bad_faccessat_result.status == ExecutionStatus::Completed
                && std::bit_cast<std::int32_t>(bad_faccessat_state.r[0]) == -1
                && memory.read_u32(thunks.errno_cell()).value_or(0U) == EBADF;
            state = {};
            state.r[0] = static_cast<std::uint32_t>(openat_directory_fd);
            auto [close_at_directory_state, close_at_directory_result] = invoke("close", state);
            at_apis_passed = at_apis_passed && close_at_directory_result.status == ExecutionStatus::Completed
                && close_at_directory_state.r[0] == 0;
            state = {};
            state.r[0] = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(AT_FDCWD));
            state.r[1] = kGuestData + 0x940U;
            state.r[2] = static_cast<std::uint32_t>(AT_REMOVEDIR);
            auto [remove_at_root_state, remove_at_root_result] = invoke("unlinkat", state);
            at_apis_passed = at_apis_passed && remove_at_root_result.status == ExecutionStatus::Completed
                && remove_at_root_state.r[0] == 0;
        }
        check(at_apis_passed,
            "Bionic openat/mkdirat/unlinkat/renameat/faccessat honor app-private directory descriptors");

        check(write_guest_string(kGuestData + 0x900U, "RetroBridge")
                && write_guest_string(kGuestData + 0x920U, "Bionic log thunk executed"),
            "guest Android log tag and message are staged");
        state = {};
        state.r[0] = 4U;
        state.r[1] = kGuestData + 0x900U;
        state.r[2] = kGuestData + 0x920U;
        auto [log_state, log_result] = invoke("__android_log_write", state);
        check(log_result.status == ExecutionStatus::Completed && log_state.r[0] == 0,
            "Android log write validates guest strings and emits the requested priority/tag/message");

        check(write_guest_string(kGuestData + 0x700U, "/data/user/0/org.retrobridge.native/files/../../escape"),
            "unsafe guest path fixture is staged");
        state = {};
        state.r[0] = kGuestData + 0x700U;
        state.r[1] = static_cast<std::uint32_t>(O_RDONLY);
        auto [unsafe_open_state, unsafe_open_result] = invoke("open", state);
        (void)unsafe_open_result;
        check(std::bit_cast<std::int32_t>(unsafe_open_state.r[0]) == -1
                && memory.read_u32(thunks.errno_cell()).value_or(0U) != 0,
            "guest libc open rejects traversal and records a guest errno");

        thunks.shutdown();
        check(!thunks.installed() && !thunks.resolve_symbol("malloc").has_value(),
            "Bionic thunk shutdown unregisters functions and clears the symbol resolver");
    }
    heap.shutdown();
    std::filesystem::remove_all(root, filesystem_error);
    check(!filesystem_error, "Bionic thunk VFS test root is cleaned up");
}

void test_guest_android_asset_thunks() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kGuestData = 0x10000U;
    constexpr std::uint32_t kGuestStack = 0x20000U;

    GuestMemory memory(1024U * 1024U);
    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U); // svc #0, used as the thunk return sentinel
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "asset thunk return sentinel maps RX");
    check(memory.map_zeroed(GuestAddress32{kGuestData}, 0x2000U,
        GuestPermission::Read | GuestPermission::Write), "asset test strings and output buffers map RW");
    check(memory.map_zeroed(GuestAddress32{kGuestStack}, 0x1000U,
        GuestPermission::Read | GuestPermission::Write), "asset thunk stack arguments map RW");
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x30000U}, 0x10000U), "asset thunk guest heap initializes");

    GuestTrampolineRegistry trampolines;
    GuestAndroidAssetThunks assets(memory, heap, trampolines);
    const std::array<std::byte, 4> source{
        std::byte{'A'}, std::byte{'B'}, std::byte{'C'}, std::byte{'D'},
    };
    std::string diagnostic;
    check(!assets.register_asset("../outside.bin", source, &diagnostic)
            && !diagnostic.empty(),
        "asset catalog rejects traversal names");
    check(assets.register_asset("textures/hero.bin", source, &diagnostic),
        "bounded immutable asset blob registers");
    check(!assets.register_asset("textures/hero.bin", source, &diagnostic),
        "asset catalog rejects duplicate paths");
    check(assets.install(&diagnostic), "synthetic AAssetManager/AAsset thunk table installs");
    check(assets.installed() && assets.asset_manager_handle() != 0
            && assets.registered_asset_count() == 1,
        "asset bridge exposes an opaque manager handle and a bounded catalog");
    check(assets.resolve_symbol("AAssetManager_open").has_value()
            && assets.resolve_symbol("AAsset_read").has_value()
            && assets.resolve_symbol("AAsset_getBuffer").has_value()
            && assets.resolve_symbol("AAsset_seek64").has_value()
            && assets.resolve_symbol("AAsset_getLength64").has_value(),
        "asset bridge resolves the supported NDK function subset");

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "asset thunk return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected asset thunk SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke = [&](std::string_view name, GuestCpuState32 state) {
        const auto function = assets.resolve_symbol(name);
        if (!function.has_value()) {
            check(false, "asset test symbol resolves to a guest trampoline");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[13] = kGuestStack;
        state.r[14] = kReturnAddress;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        check(result.status == ExecutionStatus::Completed, "asset thunk returns through guest execution");
        return std::pair{state, result};
    };
    const auto write_guest_string = [&](std::uint32_t address, std::string_view text) {
        std::vector<std::byte> bytes(text.size() + 1U, std::byte{0});
        for (std::size_t index = 0; index < text.size(); ++index) {
            bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(text[index]));
        }
        return memory.write(GuestAddress32{address}, bytes);
    };
    check(write_guest_string(kGuestData, "textures/hero.bin")
            && write_guest_string(kGuestData + 0x100U, "../outside.bin"),
        "asset path fixtures are staged in guest memory");

    GuestCpuState32 state{};
    state.r[0] = assets.asset_manager_handle();
    state.r[1] = kGuestData;
    state.r[2] = 3; // AASSET_MODE_BUFFER
    auto [opened_state, opened_result] = invoke("AAssetManager_open", state);
    const auto asset = opened_state.r[0];
    check(opened_result.status == ExecutionStatus::Completed && asset != 0
            && asset != assets.asset_manager_handle()
            && heap.allocation_size(GuestAddress32{asset}).has_value()
            && memory.is_mapped(GuestAddress32{asset}, 2U * sizeof(std::uint32_t)),
        "AAssetManager_open returns a distinct guest-heap object with an opaque generation-checked handle");

    state = {};
    state.r[0] = asset;
    auto [buffer_state, buffer_result] = invoke("AAsset_getBuffer", state);
    std::array<std::byte, 4> buffered_contents{};
    check(buffer_result.status == ExecutionStatus::Completed && buffer_state.r[0] != 0
            && heap.allocation_size(GuestAddress32{buffer_state.r[0]}).value_or(0) >= source.size()
            && memory.read(GuestAddress32{buffer_state.r[0]}, buffered_contents)
            && buffered_contents == source,
        "AAsset_getBuffer materializes immutable bytes in bounded guest heap memory");
    const auto asset_buffer_address = buffer_state.r[0];

    state = {};
    state.r[0] = assets.asset_manager_handle();
    state.r[1] = kGuestData + 0x100U;
    state.r[2] = 0;
    auto [traversal_state, traversal_result] = invoke("AAssetManager_open", state);
    check(traversal_result.status == ExecutionStatus::Completed && traversal_state.r[0] == 0,
        "AAssetManager_open rejects traversal and missing catalog entries");

    state = {};
    state.r[0] = asset;
    auto [length_state, length_result] = invoke("AAsset_getLength64", state);
    check(length_result.status == ExecutionStatus::Completed && length_state.r[0] == 4U
            && length_state.r[1] == 0U,
        "AAsset_getLength64 returns a guest-width 64-bit length");

    state = {};
    state.r[0] = asset;
    state.r[1] = kGuestData + 0x400U;
    state.r[2] = 2;
    auto [read_state, read_result] = invoke("AAsset_read", state);
    std::array<std::byte, 2> first_bytes{};
    check(read_result.status == ExecutionStatus::Completed && read_state.r[0] == 2U
            && memory.read(GuestAddress32{kGuestData + 0x400U}, first_bytes)
            && first_bytes == std::array<std::byte, 2>{std::byte{'A'}, std::byte{'B'}},
        "AAsset_read copies only the requested bounded range into writable guest memory");

    state = {};
    state.r[0] = asset;
    state.r[1] = kReturnAddress; // mapped RX, deliberately not writable
    state.r[2] = 1;
    auto [bad_buffer_state, bad_buffer_result] = invoke("AAsset_read", state);
    check(bad_buffer_result.status == ExecutionStatus::Completed
            && bad_buffer_state.r[0] == std::numeric_limits<std::uint32_t>::max(),
        "AAsset_read reports an invalid guest destination without faulting the interpreter");

    check(memory.write_u32(GuestAddress32{kGuestStack}, 0U), "64-bit asset seek whence argument is staged");
    state = {};
    state.r[0] = asset;
    state.r[2] = 1U; // off64_t in r2/r3 after AAPCS 64-bit alignment
    state.r[3] = 0U;
    auto [seek64_state, seek64_result] = invoke("AAsset_seek64", state);
    check(seek64_result.status == ExecutionStatus::Completed && seek64_state.r[0] == 1U
            && seek64_state.r[1] == 0U,
        "AAsset_seek64 reads aligned 64-bit ARM arguments and reports its new offset");

    state = {};
    state.r[0] = asset;
    state.r[1] = 2U;
    state.r[2] = 0U; // SEEK_SET
    auto [seek_state, seek_result] = invoke("AAsset_seek", state);
    check(seek_result.status == ExecutionStatus::Completed && seek_state.r[0] == 2U,
        "AAsset_seek implements bounded SEEK_SET semantics");

    state = {};
    state.r[0] = asset;
    state.r[1] = kGuestData + 0x500U;
    state.r[2] = 4U;
    auto [read_rest_state, read_rest_result] = invoke("AAsset_read", state);
    std::array<std::byte, 2> remainder{};
    check(read_rest_result.status == ExecutionStatus::Completed && read_rest_state.r[0] == 2U
            && memory.read(GuestAddress32{kGuestData + 0x500U}, remainder)
            && remainder == std::array<std::byte, 2>{std::byte{'C'}, std::byte{'D'}},
        "AAsset_read returns only the remaining bytes at end-of-file");

    state = {};
    state.r[0] = asset;
    auto [remaining_state, remaining_result] = invoke("AAsset_getRemainingLength64", state);
    check(remaining_result.status == ExecutionStatus::Completed && remaining_state.r[0] == 0U
            && remaining_state.r[1] == 0U,
        "AAsset_getRemainingLength64 reports end-of-file");

    state = {};
    state.r[0] = asset;
    (void)invoke("AAsset_close", state);
    check(!heap.allocation_size(GuestAddress32{asset_buffer_address}).has_value(),
        "AAsset_close releases its guest-materialized buffer");
    state = {};
    state.r[0] = asset;
    auto [stale_state, stale_result] = invoke("AAsset_read", state);
    check(stale_result.status == ExecutionStatus::Completed
            && stale_state.r[0] == std::numeric_limits<std::uint32_t>::max(),
        "closing an asset invalidates its generation-checked handle");
}

void test_headless_native_window_buffers_and_lifecycle() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kGuestData = 0x10000U;

    GuestMemory memory(8U * 1024U * 1024U);
    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U);
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "native-window return sentinel maps RX");
    check(memory.map_zeroed(GuestAddress32{kGuestData}, 0x2000U,
        GuestPermission::Read | GuestPermission::Write), "native-window output structures map RW");
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x30000U}, 4U * 1024U * 1024U), "native-window guest heap initializes");

    GuestTrampolineRegistry trampolines;
    GuestAndroidWindowThunks windows(memory, heap, trampolines);
    std::string diagnostic;
    check(windows.install(&diagnostic), "bounded headless ANativeWindow thunk table installs");
    check(windows.resolve_symbol("ANativeWindow_lock").has_value()
            && windows.resolve_symbol("ANativeWindow_unlockAndPost").has_value()
            && windows.resolve_symbol("ANativeWindow_setBuffersGeometry").has_value(),
        "headless window bridge resolves buffer and geometry APIs");
    check(!windows.create_headless_window(0, 4).has_value()
            && !windows.create_headless_window(4, 4, 4).has_value()
            && !windows.create_headless_window(4097, 1).has_value(),
        "headless window factory rejects empty dimensions, unsupported formats, and oversized sides");
    const auto handle = windows.create_headless_window(4, 3, GuestAndroidWindowThunks::kRgba8888, &diagnostic);
    check(handle.has_value() && *handle != 0 && heap.allocation_size(GuestAddress32{*handle}).has_value(),
        "headless window is represented by a guest-heap opaque handle");
    if (!handle.has_value()) return;

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "window thunk return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected window thunk SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke = [&](std::string_view name, GuestCpuState32 state) {
        const auto function = windows.resolve_symbol(name);
        if (!function.has_value()) {
            check(false, "native-window test symbol resolves to a guest trampoline");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[14] = kReturnAddress;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        check(result.status == ExecutionStatus::Completed, "native-window thunk returns through guest execution");
        return std::pair{state, result};
    };

    GuestCpuState32 state{};
    state.r[0] = *handle;
    auto [width_state, width_result] = invoke("ANativeWindow_getWidth", state);
    check(width_result.status == ExecutionStatus::Completed && width_state.r[0] == 4U,
        "ANativeWindow_getWidth reports the current offscreen width");
    state = {};
    state.r[0] = *handle;
    auto [height_state, height_result] = invoke("ANativeWindow_getHeight", state);
    check(height_result.status == ExecutionStatus::Completed && height_state.r[0] == 3U,
        "ANativeWindow_getHeight reports the current offscreen height");

    state = {};
    state.r[0] = *handle;
    state.r[1] = 2;
    state.r[2] = 2;
    state.r[3] = GuestAndroidWindowThunks::kRgba8888;
    auto [geometry_state, geometry_result] = invoke("ANativeWindow_setBuffersGeometry", state);
    check(geometry_result.status == ExecutionStatus::Completed && geometry_state.r[0] == 0,
        "ANativeWindow_setBuffersGeometry reallocates a bounded RGBA buffer");
    const auto pixels = windows.pixel_buffer(*handle);
    check(pixels.has_value() && memory.is_accessible(*pixels, 16U, GuestPermission::Write)
            && !heap.allocation_size(*pixels).has_value() && !heap.free(*pixels),
        "headless surface exposes a bounded guest-mapped pixel buffer outside the general heap");
    if (!pixels.has_value()) return;

    state = {};
    state.r[0] = *handle;
    state.r[1] = 0x10100U; // ANativeWindow_Buffer, 24 bytes in the 32-bit ABI
    state.r[2] = 0x10200U; // ARect dirty bounds
    auto [lock_state, lock_result] = invoke("ANativeWindow_lock", state);
    check(lock_result.status == ExecutionStatus::Completed && lock_state.r[0] == 0,
        "ANativeWindow_lock returns a 32-bit guest buffer descriptor");
    check(memory.read_u32(GuestAddress32{0x10100U}).value_or(0U) == 2U
            && memory.read_u32(GuestAddress32{0x10104U}).value_or(0U) == 2U
            && memory.read_u32(GuestAddress32{0x10108U}).value_or(0U) == 2U
            && memory.read_u32(GuestAddress32{0x1010cU}).value_or(0U) == GuestAndroidWindowThunks::kRgba8888
            && memory.read_u32(GuestAddress32{0x10110U}).value_or(0U) == pixels->value(),
        "ANativeWindow_Buffer fields contain guest width, height, stride, format, and bits pointer");
    check(memory.read_u32(GuestAddress32{0x10208U}).value_or(0U) == 2U
            && memory.read_u32(GuestAddress32{0x1020cU}).value_or(0U) == 2U,
        "ANativeWindow_lock writes the dirty rectangle in guest memory");

    state = {};
    state.r[0] = *handle;
    state.r[1] = 0x10300U;
    auto [double_lock_state, double_lock_result] = invoke("ANativeWindow_lock", state);
    check(double_lock_result.status == ExecutionStatus::Completed
            && double_lock_state.r[0] == static_cast<std::uint32_t>(-EBUSY),
        "headless surface rejects a second lock while the buffer is held");

    const std::array<std::byte, 4> green_pixel{std::byte{0x00}, std::byte{0xff}, std::byte{0x00}, std::byte{0xff}};
    check(memory.write(*pixels, green_pixel), "guest can update its locked RGBA pixel buffer");
    state = {};
    state.r[0] = *handle;
    auto [post_state, post_result] = invoke("ANativeWindow_unlockAndPost", state);
    std::array<std::byte, 4> posted_pixel{};
    check(post_result.status == ExecutionStatus::Completed && post_state.r[0] == 0
            && memory.read(*pixels, posted_pixel) && posted_pixel == green_pixel
            && windows.posted_frame_count(*handle).value_or(0) == 1,
        "ANativeWindow_unlockAndPost completes a headless frame without copying host pointers");

    state = {};
    state.r[0] = *handle;
    state.r[1] = kReturnAddress; // RX-only output memory is not an ANativeWindow_Buffer
    state.r[2] = 0;
    auto [bad_lock_state, bad_lock_result] = invoke("ANativeWindow_lock", state);
    check(bad_lock_result.status == ExecutionStatus::Completed
            && bad_lock_state.r[0] == static_cast<std::uint32_t>(-EINVAL),
        "ANativeWindow_lock rejects non-writable guest descriptors");

    state = {};
    state.r[0] = *handle;
    state.r[1] = 4097;
    state.r[2] = 1024;
    state.r[3] = GuestAndroidWindowThunks::kRgba8888;
    auto [oversize_state, oversize_result] = invoke("ANativeWindow_setBuffersGeometry", state);
    check(oversize_result.status == ExecutionStatus::Completed
            && oversize_state.r[0] == static_cast<std::uint32_t>(-EINVAL),
        "headless surface pixel quota rejects excessive geometry");

    state = {};
    state.r[0] = *handle;
    (void)invoke("ANativeWindow_acquire", state);
    state = {};
    state.r[0] = *handle;
    (void)invoke("ANativeWindow_release", state);
    state = {};
    state.r[0] = *handle;
    auto [still_open_state, still_open_result] = invoke("ANativeWindow_getWidth", state);
    check(still_open_result.status == ExecutionStatus::Completed && still_open_state.r[0] == 2U,
        "ANativeWindow acquire/release keeps a referenced window alive");
    state = {};
    state.r[0] = *handle;
    (void)invoke("ANativeWindow_release", state);
    check(!windows.pixel_buffer(*handle).has_value() && !memory.is_mapped(*pixels),
        "final ANativeWindow release invalidates the handle and unmaps its pixel buffer");
    state = {};
    state.r[0] = *handle;
    auto [stale_state, stale_result] = invoke("ANativeWindow_getWidth", state);
    check(stale_result.status == ExecutionStatus::Completed && stale_state.r[0] == 0U,
        "released native-window handles cannot access a later surface");
}

void test_synthetic_android_input_queue_and_looper() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kGuestData = 0x10000U;

    GuestMemory memory(8U * 1024U * 1024U);
    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U);
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "input bridge return sentinel maps RX");
    check(memory.map_zeroed(GuestAddress32{kGuestData}, 0x3000U,
        GuestPermission::Read | GuestPermission::Write), "input bridge output structures map RW");
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x30000U}, 4U * 1024U * 1024U), "input bridge guest heap initializes");

    GuestTrampolineRegistry trampolines;
    GuestAndroidInputThunks input(memory, heap, trampolines);
    std::string diagnostic;
    check(input.install(&diagnostic), "bounded AInputQueue and ALooper thunk table installs");
    check(input.resolve_symbol("AInputQueue_getEvent").has_value()
            && input.resolve_symbol("AKeyEvent_getKeyCode").has_value()
            && input.resolve_symbol("AMotionEvent_getX").has_value()
            && input.resolve_symbol("ALooper_pollOnce").has_value(),
        "synthetic input bridge resolves queue, event, and looper thunks");
    const auto queue = input.create_input_queue(&diagnostic);
    check(queue.has_value() && heap.allocation_size(GuestAddress32{queue.value_or(0)}).has_value(),
        "host-created input queue is exposed through a guest-heap opaque handle");
    if (!queue.has_value()) return;

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "input thunk return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected input thunk SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke = [&](std::string_view name, GuestCpuState32 state) {
        const auto function = input.resolve_symbol(name);
        if (!function.has_value()) {
            check(false, "input test symbol resolves to a guest trampoline");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[14] = kReturnAddress;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        check(result.status == ExecutionStatus::Completed, "input thunk returns through guest execution");
        return std::pair{state, result};
    };

    GuestCpuState32 state{};
    state.r[0] = *queue;
    auto [empty_state, empty_result] = invoke("AInputQueue_hasEvents", state);
    check(empty_result.status == ExecutionStatus::Completed && empty_state.r[0] == 0U,
        "empty synthetic AInputQueue reports no pending events");
    state = {};
    state.r[0] = *queue;
    state.r[1] = 0x10100U;
    auto [would_block_state, would_block_result] = invoke("AInputQueue_getEvent", state);
    check(would_block_result.status == ExecutionStatus::Completed
            && would_block_state.r[0] == static_cast<std::uint32_t>(-EAGAIN),
        "AInputQueue_getEvent returns EAGAIN when the injected queue is empty");

    GuestInputEvent32 malformed{};
    malformed.type = GuestInputEventType32::Motion;
    malformed.down_time_ns = 1;
    malformed.event_time_ns = 2;
    check(!input.enqueue_input_event(*queue, malformed, &diagnostic),
        "host injection rejects motion records without pointers");

    GuestInputEvent32 key{};
    key.type = GuestInputEventType32::Key;
    key.device_id = -1;
    key.source = 0x101;
    key.action = 0;
    key.key_code = 29;
    key.meta_state = 2;
    key.repeat_count = 1;
    key.down_time_ns = 1'000'000;
    key.event_time_ns = 2'000'000;
    check(input.enqueue_input_event(*queue, key, &diagnostic), "host can enqueue a bounded key event");
    state = {};
    state.r[0] = *queue;
    state.r[1] = kReturnAddress; // RX-only memory is not a writable AInputEvent**.
    auto [bad_output_state, bad_output_result] = invoke("AInputQueue_getEvent", state);
    check(bad_output_result.status == ExecutionStatus::Completed
            && bad_output_state.r[0] == static_cast<std::uint32_t>(-EFAULT),
        "AInputQueue_getEvent rejects a non-writable event output pointer");
    state = {};
    state.r[0] = *queue;
    auto [still_pending_state, still_pending_result] = invoke("AInputQueue_hasEvents", state);
    check(still_pending_result.status == ExecutionStatus::Completed && still_pending_state.r[0] == 1U,
        "invalid output memory does not consume an input event");

    state = {};
    state.r[0] = *queue;
    state.r[1] = 0x10100U;
    auto [get_key_state, get_key_result] = invoke("AInputQueue_getEvent", state);
    const auto key_handle = memory.read_u32(GuestAddress32{0x10100U}).value_or(0U);
    check(get_key_result.status == ExecutionStatus::Completed && get_key_state.r[0] == 0U
            && key_handle != 0 && heap.allocation_size(GuestAddress32{key_handle}).has_value(),
        "AInputQueue_getEvent returns a guest-heap opaque AInputEvent handle");
    if (key_handle == 0) return;
    state = {};
    state.r[0] = *queue;
    auto [empty_after_get_state, empty_after_get_result] = invoke("AInputQueue_hasEvents", state);
    check(empty_after_get_result.status == ExecutionStatus::Completed && empty_after_get_state.r[0] == 0U,
        "dequeued key events leave the pending queue while outstanding");

    state = {};
    state.r[0] = key_handle;
    auto [key_type_state, key_type_result] = invoke("AInputEvent_getType", state);
    check(key_type_result.status == ExecutionStatus::Completed && key_type_state.r[0] == 1U,
        "AInputEvent_getType returns AINPUT_EVENT_TYPE_KEY for a key record");
    state = {};
    state.r[0] = key_handle;
    auto [key_code_state, key_code_result] = invoke("AKeyEvent_getKeyCode", state);
    check(key_code_result.status == ExecutionStatus::Completed && key_code_state.r[0] == 29U,
        "AKeyEvent_getKeyCode marshals the injected key code");
    state = {};
    state.r[0] = key_handle;
    auto [key_source_state, key_source_result] = invoke("AInputEvent_getSource", state);
    check(key_source_result.status == ExecutionStatus::Completed && key_source_state.r[0] == 0x101U,
        "AInputEvent_getSource preserves the Android source mask");
    state = {};
    state.r[0] = key_handle;
    auto [key_time_state, key_time_result] = invoke("AKeyEvent_getEventTime", state);
    check(key_time_result.status == ExecutionStatus::Completed
            && key_time_state.r[0] == 2'000'000U && key_time_state.r[1] == 0U,
        "AKeyEvent_getEventTime returns 64-bit nanoseconds in ARM32 r0/r1");
    state = {};
    state.r[0] = *queue;
    state.r[1] = key_handle;
    auto [pre_dispatch_state, pre_dispatch_result] = invoke("AInputQueue_preDispatchEvent", state);
    check(pre_dispatch_result.status == ExecutionStatus::Completed && pre_dispatch_state.r[0] == 0U,
        "AInputQueue_preDispatchEvent reports no framework or IME interception");
    state.r[0] = *queue;
    state.r[1] = key_handle;
    state.r[2] = 1;
    (void)invoke("AInputQueue_finishEvent", state);
    state = {};
    state.r[0] = key_handle;
    auto [stale_key_state, stale_key_result] = invoke("AInputEvent_getType", state);
    check(stale_key_result.status == ExecutionStatus::Completed && stale_key_state.r[0] == 0U,
        "AInputQueue_finishEvent invalidates the event handle");

    GuestInputEvent32 motion{};
    motion.type = GuestInputEventType32::Motion;
    motion.device_id = 3;
    motion.source = 0x1002;
    motion.action = 2;
    motion.meta_state = 4;
    motion.down_time_ns = 2'500'000;
    motion.event_time_ns = 3'000'000;
    motion.pointers.push_back(GuestMotionPointer32{4, 12.5F, -3.25F, 0.75F});
    check(input.enqueue_input_event(*queue, motion, &diagnostic), "host can enqueue a bounded motion event");
    check(memory.write_u32(GuestAddress32{0x10100U}, 0U), "clear the guest event output before motion dequeue");
    state = {};
    state.r[0] = *queue;
    state.r[1] = 0x10100U;
    auto [get_motion_state, get_motion_result] = invoke("AInputQueue_getEvent", state);
    const auto motion_handle = memory.read_u32(GuestAddress32{0x10100U}).value_or(0U);
    check(get_motion_result.status == ExecutionStatus::Completed && get_motion_state.r[0] == 0U
            && motion_handle != 0,
        "AInputQueue_getEvent returns an opaque handle for motion events");
    if (motion_handle == 0) return;
    state = {};
    state.r[0] = motion_handle;
    auto [motion_count_state, motion_count_result] = invoke("AMotionEvent_getPointerCount", state);
    check(motion_count_result.status == ExecutionStatus::Completed && motion_count_state.r[0] == 1U,
        "AMotionEvent_getPointerCount reports the bounded pointer list");
    state = {};
    state.r[0] = motion_handle;
    state.r[1] = 0;
    auto [pointer_id_state, pointer_id_result] = invoke("AMotionEvent_getPointerId", state);
    check(pointer_id_result.status == ExecutionStatus::Completed && pointer_id_state.r[0] == 4U,
        "AMotionEvent_getPointerId marshals a pointer identifier");
    state = {};
    state.r[0] = motion_handle;
    state.r[1] = 0;
    auto [motion_x_state, motion_x_result] = invoke("AMotionEvent_getX", state);
    check(motion_x_result.status == ExecutionStatus::Completed
            && motion_x_state.r[0] == std::bit_cast<std::uint32_t>(12.5F),
        "AMotionEvent_getX returns a float in the ARM32 core register");
    state = {};
    state.r[0] = motion_handle;
    state.r[1] = 0;
    auto [motion_y_state, motion_y_result] = invoke("AMotionEvent_getY", state);
    check(motion_y_result.status == ExecutionStatus::Completed
            && motion_y_state.r[0] == std::bit_cast<std::uint32_t>(-3.25F),
        "AMotionEvent_getY preserves a signed guest float");
    state = {};
    state.r[0] = motion_handle;
    auto [motion_history_state, motion_history_result] = invoke("AMotionEvent_getHistorySize", state);
    check(motion_history_result.status == ExecutionStatus::Completed && motion_history_state.r[0] == 0U,
        "AMotionEvent_getHistorySize reports no unsupported historical samples");
    state = {};
    state.r[0] = *queue;
    state.r[1] = motion_handle;
    state.r[2] = 0;
    (void)invoke("AInputQueue_finishEvent", state);

    state = {};
    auto [no_looper_state, no_looper_result] = invoke("ALooper_forThread", state);
    check(no_looper_result.status == ExecutionStatus::Completed && no_looper_state.r[0] == 0U,
        "ALooper_forThread returns null before a looper is prepared");
    state = {};
    state.r[0] = 0;
    auto [prepare_state, prepare_result] = invoke("ALooper_prepare", state);
    const auto looper = prepare_state.r[0];
    check(prepare_result.status == ExecutionStatus::Completed && looper != 0
            && heap.allocation_size(GuestAddress32{looper}).has_value(),
        "ALooper_prepare returns a guest-heap opaque runtime looper");
    if (looper == 0) return;
    state = {};
    auto [for_thread_state, for_thread_result] = invoke("ALooper_forThread", state);
    check(for_thread_result.status == ExecutionStatus::Completed && for_thread_state.r[0] == looper,
        "ALooper_forThread returns the prepared runtime looper");

    state = {};
    state.r[0] = 0;
    state.r[1] = 0x10200U;
    state.r[2] = 0x10204U;
    state.r[3] = 0x10208U;
    auto [timeout_state, timeout_result] = invoke("ALooper_pollOnce", state);
    check(timeout_result.status == ExecutionStatus::Completed
            && timeout_state.r[0] == static_cast<std::uint32_t>(-3)
            && memory.read_u32(GuestAddress32{0x10200U}).value_or(0U) == std::numeric_limits<std::uint32_t>::max()
            && memory.read_u32(GuestAddress32{0x10204U}).value_or(1U) == 0U
            && memory.read_u32(GuestAddress32{0x10208U}).value_or(1U) == 0U,
        "ALooper_pollOnce performs a nonblocking timeout and clears optional outputs");
    state = {};
    state.r[0] = looper;
    (void)invoke("ALooper_wake", state);
    state = {};
    state.r[0] = 0;
    state.r[1] = 0x10200U;
    state.r[2] = 0x10204U;
    state.r[3] = 0x10208U;
    auto [wake_state, wake_result] = invoke("ALooper_pollOnce", state);
    check(wake_result.status == ExecutionStatus::Completed
            && wake_state.r[0] == static_cast<std::uint32_t>(-1),
        "ALooper_wake causes one ALOOPER_POLL_WAKE result");
    state = {};
    state.r[0] = looper;
    (void)invoke("ALooper_acquire", state);
    state = {};
    state.r[0] = looper;
    (void)invoke("ALooper_release", state);
    state = {};
    state.r[0] = looper;
    (void)invoke("ALooper_wake", state);
    state = {};
    state.r[0] = 0;
    state.r[1] = kReturnAddress;
    state.r[2] = 0;
    state.r[3] = 0;
    auto [bad_poll_state, bad_poll_result] = invoke("ALooper_pollOnce", state);
    check(bad_poll_result.status == ExecutionStatus::Completed
            && bad_poll_state.r[0] == static_cast<std::uint32_t>(-4),
        "ALooper_pollOnce rejects invalid output pointers and does not expose host memory");
    state = {};
    state.r[0] = 0;
    state.r[1] = 0x10200U;
    state.r[2] = 0x10204U;
    state.r[3] = 0x10208U;
    auto [wake_after_error_state, wake_after_error_result] = invoke("ALooper_pollOnce", state);
    check(wake_after_error_result.status == ExecutionStatus::Completed
            && wake_after_error_state.r[0] == static_cast<std::uint32_t>(-1),
        "invalid poll outputs do not consume a pending looper wake");
    state = {};
    state.r[0] = looper;
    state.r[1] = 7;
    state.r[2] = 1;
    state.r[3] = 1;
    auto [add_fd_state, add_fd_result] = invoke("ALooper_addFd", state);
    check(add_fd_result.status == ExecutionStatus::Completed
            && add_fd_state.r[0] == std::numeric_limits<std::uint32_t>::max(),
        "ALooper_addFd explicitly rejects unsupported host file-descriptor polling");
}

void test_headless_egl_gles_clear_subset() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kGuestData = 0x10000U;

    GuestMemory memory(12U * 1024U * 1024U);
    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U);
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "headless EGL return sentinel maps RX");
    check(memory.map_zeroed(GuestAddress32{kGuestData}, 0x4000U,
        GuestPermission::Read | GuestPermission::Write), "headless EGL attribute/output memory maps RW");
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x30000U}, 4U * 1024U * 1024U), "headless EGL guest heap initializes");

    GuestTrampolineRegistry trampolines;
    GuestAndroidWindowThunks windows(memory, heap, trampolines);
    GuestHeadlessGlesEglThunks gles(memory, heap, trampolines, windows);
    std::string diagnostic;
    check(windows.install(&diagnostic), "headless EGL test installs native-window thunks");
    const auto window = windows.create_headless_window(4, 3, GuestAndroidWindowThunks::kRgba8888, &diagnostic);
    check(window.has_value(), "headless EGL test creates an offscreen RGBA window");
    if (!window.has_value()) return;
    const auto gles_installed = gles.install(&diagnostic);
    check(gles_installed, "bounded EGL/GLES clear-only thunk table installs");
    if (!gles_installed) return;
    check(gles.resolve_symbol("eglChooseConfig").has_value()
            && gles.resolve_symbol("eglCreateWindowSurface").has_value()
            && gles.resolve_symbol("glClear").has_value()
            && gles.resolve_symbol("glScissor").has_value(),
        "headless renderer resolves EGL, clear, and scissor APIs");

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "EGL thunk return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected EGL thunk SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke = [&](std::string_view name, GuestCpuState32 state) {
        const auto function = gles.resolve_symbol(name);
        if (!function.has_value()) {
            check(false, "EGL/GLES test symbol resolves to a guest trampoline");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[7] = 1;
        state.r[14] = kReturnAddress;
        auto result = interpreter.run(state, GuestAddress32{*function}, 16);
        check(result.status == ExecutionStatus::Completed, "EGL/GLES thunk returns through guest execution");
        return std::pair{state, result};
    };

    GuestCpuState32 state{};
    state.r[0] = 0; // EGL_DEFAULT_DISPLAY
    auto [display_state, display_result] = invoke("eglGetDisplay", state);
    const auto display = display_state.r[0];
    check(display_result.status == ExecutionStatus::Completed && display != 0,
        "eglGetDisplay returns a synthetic guest display handle");
    state = {};
    state.r[0] = display;
    state.r[1] = 0x10100U;
    state.r[2] = 0x10104U;
    auto [initialize_state, initialize_result] = invoke("eglInitialize", state);
    check(initialize_result.status == ExecutionStatus::Completed && initialize_state.r[0] == 1U
            && memory.read_u32(GuestAddress32{0x10100U}).value_or(0U) == 1U
            && memory.read_u32(GuestAddress32{0x10104U}).value_or(0U) == 4U,
        "eglInitialize reports a bounded EGL 1.4 display");

    const std::array<std::uint32_t, 5> config_attributes{
        0x3033U, 0x0004U, // EGL_SURFACE_TYPE = EGL_WINDOW_BIT
        0x3040U, 0x0004U, // EGL_RENDERABLE_TYPE = EGL_OPENGL_ES2_BIT
        GuestHeadlessGlesEglThunks::kEglNone,
    };
    for (std::size_t index = 0; index < config_attributes.size(); ++index) {
        check(memory.write_u32(GuestAddress32{0x10200U + static_cast<std::uint32_t>(index * 4U)}, config_attributes[index]),
            "write bounded EGL config attributes");
    }
    check(memory.write_u32(GuestAddress32{0x10300U}, 0x10244U), "write EGL choose-config stack argument");
    state = {};
    state.r[0] = display;
    state.r[1] = 0x10200U;
    state.r[2] = 0x10240U;
    state.r[3] = 1U;
    state.r[13] = 0x10300U;
    auto [choose_state, choose_result] = invoke("eglChooseConfig", state);
    const auto config = memory.read_u32(GuestAddress32{0x10240U}).value_or(0U);
    check(choose_result.status == ExecutionStatus::Completed && choose_state.r[0] == 1U
            && config != 0 && memory.read_u32(GuestAddress32{0x10244U}).value_or(0U) == 1U,
        "eglChooseConfig validates window/ES2 attributes and returns one synthetic config");
    state = {};
    state.r[0] = display;
    state.r[1] = config;
    state.r[2] = 0x3024U; // EGL_RED_SIZE
    state.r[3] = 0x10248U;
    auto [config_attrib_state, config_attrib_result] = invoke("eglGetConfigAttrib", state);
    check(config_attrib_result.status == ExecutionStatus::Completed && config_attrib_state.r[0] == 1U
            && memory.read_u32(GuestAddress32{0x10248U}).value_or(0U) == 8U,
        "eglGetConfigAttrib reports an RGBA8888 config");

    state = {};
    state.r[0] = display;
    state.r[1] = config;
    state.r[2] = *window;
    auto [surface_state, surface_result] = invoke("eglCreateWindowSurface", state);
    const auto surface = surface_state.r[0];
    check(surface_result.status == ExecutionStatus::Completed && surface != 0,
        "eglCreateWindowSurface retains the headless ANativeWindow through an opaque surface handle");
    state = {};
    state.r[0] = GuestHeadlessGlesEglThunks::kEglOpenGlesApi;
    auto [bind_api_state, bind_api_result] = invoke("eglBindAPI", state);
    check(bind_api_result.status == ExecutionStatus::Completed && bind_api_state.r[0] == 1U,
        "eglBindAPI selects OpenGL ES");

    const std::array<std::uint32_t, 3> context_attributes{
        0x3098U, 2U, GuestHeadlessGlesEglThunks::kEglNone,
    };
    for (std::size_t index = 0; index < context_attributes.size(); ++index) {
        check(memory.write_u32(GuestAddress32{0x10280U + static_cast<std::uint32_t>(index * 4U)}, context_attributes[index]),
            "write bounded EGL context attributes");
    }
    state = {};
    state.r[0] = display;
    state.r[1] = config;
    state.r[2] = 0;
    state.r[3] = 0x10280U;
    auto [context_state, context_result] = invoke("eglCreateContext", state);
    const auto context = context_state.r[0];
    check(context_result.status == ExecutionStatus::Completed && context != 0,
        "eglCreateContext creates a synthetic OpenGL ES 2 context");
    state = {};
    state.r[0] = display;
    state.r[1] = surface;
    state.r[2] = surface;
    state.r[3] = context;
    auto [make_current_state, make_current_result] = invoke("eglMakeCurrent", state);
    check(make_current_result.status == ExecutionStatus::Completed && make_current_state.r[0] == 1U,
        "eglMakeCurrent binds one window surface for draw and read");

    state = {};
    state.r[0] = std::bit_cast<std::uint32_t>(1.0F);
    state.r[1] = std::bit_cast<std::uint32_t>(0.0F);
    state.r[2] = std::bit_cast<std::uint32_t>(0.0F);
    state.r[3] = std::bit_cast<std::uint32_t>(1.0F);
    (void)invoke("glClearColor", state);
    state = {};
    state.r[0] = GuestHeadlessGlesEglThunks::kGlColorBufferBit;
    (void)invoke("glClear", state);
    const auto pixels = windows.pixel_buffer(*window);
    check(pixels.has_value(), "headless EGL surface retains a guest-mapped color buffer");
    if (!pixels.has_value()) return;
    std::array<std::byte, 4> first_pixel{};
    check(memory.read(*pixels, first_pixel)
            && first_pixel == std::array<std::byte, 4>{std::byte{0xff}, std::byte{0}, std::byte{0}, std::byte{0xff}},
        "glClear writes a red RGBA8888 color across the software surface");

    state = {};
    state.r[0] = GuestHeadlessGlesEglThunks::kGlScissorTest;
    (void)invoke("glEnable", state);
    state = {};
    state.r[0] = 1;
    state.r[1] = 1;
    state.r[2] = 1;
    state.r[3] = 1;
    (void)invoke("glScissor", state);
    state = {};
    state.r[0] = std::bit_cast<std::uint32_t>(0.0F);
    state.r[1] = std::bit_cast<std::uint32_t>(1.0F);
    state.r[2] = std::bit_cast<std::uint32_t>(0.0F);
    state.r[3] = std::bit_cast<std::uint32_t>(1.0F);
    (void)invoke("glClearColor", state);
    state = {};
    state.r[0] = GuestHeadlessGlesEglThunks::kGlColorBufferBit;
    (void)invoke("glClear", state);
    const auto scissored_pixel_address = pixels->checked_add(20U);
    std::array<std::byte, 4> scissored_pixel{};
    check(scissored_pixel_address.has_value() && memory.read(*scissored_pixel_address, scissored_pixel)
            && scissored_pixel == std::array<std::byte, 4>{std::byte{0}, std::byte{0xff}, std::byte{0}, std::byte{0xff}}
            && memory.read(*pixels, first_pixel)
            && first_pixel == std::array<std::byte, 4>{std::byte{0xff}, std::byte{0}, std::byte{0}, std::byte{0xff}},
        "scissored glClear updates only the selected bottom-left-origin rectangle");

    state = {};
    state.r[0] = 0x1f02U; // GL_VERSION
    auto [version_state, version_result] = invoke("glGetString", state);
    check(version_result.status == ExecutionStatus::Completed && version_state.r[0] != 0
            && memory.read_u8(GuestAddress32{version_state.r[0]}).value_or(0U) == static_cast<std::uint8_t>('O'),
        "glGetString returns a guest-memory GLES version string");
    state = {};
    state.r[0] = 0xdeadU;
    (void)invoke("glEnable", state);
    state = {};
    auto [gl_error_state, gl_error_result] = invoke("glGetError", state);
    check(gl_error_result.status == ExecutionStatus::Completed && gl_error_state.r[0] == 0x0500U,
        "GLES subset records and clears GL_INVALID_ENUM");

    state = {};
    state.r[0] = display;
    state.r[1] = surface;
    auto [swap_state, swap_result] = invoke("eglSwapBuffers", state);
    check(swap_result.status == ExecutionStatus::Completed && swap_state.r[0] == 1U
            && windows.posted_frame_count(*window).value_or(0) == 1U,
        "eglSwapBuffers posts a rendered headless frame");
    state = {};
    state.r[0] = display;
    state.r[1] = surface;
    (void)invoke("eglDestroySurface", state);
    state = {};
    state.r[0] = display;
    state.r[1] = context;
    (void)invoke("eglDestroyContext", state);
    state = {};
    state.r[0] = display;
    auto [terminate_state, terminate_result] = invoke("eglTerminate", state);
    check(terminate_result.status == ExecutionStatus::Completed && terminate_state.r[0] == 1U,
        "eglTerminate tears down the synthetic display state");
    windows.release_headless_window(*window);
    check(!windows.pixel_buffer(*window).has_value(),
        "EGL surface destruction releases its native-window reference");
}

void test_opensl_pcm_buffer_queue_subset() {
    using namespace retrobridge::runtime;
    constexpr std::uint32_t kReturnAddress = 0x8000U;
    constexpr std::uint32_t kData = 0x10000U;

    GuestMemory memory(12U * 1024U * 1024U);
    std::vector<std::byte> return_code(4, std::byte{0});
    put_u32(return_code, 0, 0xef000000U);
    check(memory.map_bytes(GuestAddress32{kReturnAddress}, return_code, return_code.size(),
        GuestPermission::Read | GuestPermission::Execute), "OpenSL return sentinel maps RX");
    check(memory.map_zeroed(GuestAddress32{kData}, 0x20000U,
        GuestPermission::Read | GuestPermission::Write), "OpenSL object and PCM fixture memory maps RW");
    GuestHeap32 heap(memory);
    check(heap.initialize(GuestAddress32{0x40000U}, 4U * 1024U * 1024U), "OpenSL guest heap initializes");

    GuestTrampolineRegistry trampolines;
    GuestOpenSlThunks opensl(memory, heap, trampolines);
    std::string diagnostic;
    check(opensl.install(&diagnostic), "bounded OpenSL ES object and queue thunks install");
    if (!opensl.installed()) return;
    check(opensl.resolve_symbol("slCreateEngine").has_value()
            && opensl.resolve_symbol("slQueryNumSupportedEngineInterfaces").has_value()
            && opensl.resolve_symbol("slQuerySupportedEngineInterfaces").has_value()
            && opensl.resolve_symbol("SL_IID_ENGINE").has_value()
            && opensl.resolve_symbol("SL_IID_BUFFERQUEUE").has_value()
            && opensl.resolve_symbol("SL_IID_ANDROIDSIMPLEBUFFERQUEUE").has_value(),
        "OpenSL ES entrypoints and selected interface-ID data symbols resolve");

    const auto svc = [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
        if (immediate == 0 && state.r[7] == 1) return GuestHookResult{GuestHookAction::Stop, "OpenSL thunk return"};
        return GuestHookResult{GuestHookAction::Fault, "unexpected OpenSL thunk SVC"};
    };
    Arm32Interpreter interpreter(memory, trampolines, svc);
    const auto invoke = [&](std::uint32_t function, GuestCpuState32 state) {
        state.r[7] = 1;
        state.r[14] = kReturnAddress;
        auto result = interpreter.run(state, GuestAddress32{function}, 16);
        check(result.status == ExecutionStatus::Completed, "OpenSL ES method returns through guest execution");
        return std::pair{state, result};
    };
    const auto invoke_symbol = [&](std::string_view name, GuestCpuState32 state) {
        const auto function = opensl.resolve_symbol(name);
        if (!function.has_value()) {
            check(false, "OpenSL ES symbol resolves to a guest entrypoint");
            return std::pair{state, ExecutionResult{}};
        }
        return invoke(*function, state);
    };
    const auto invoke_interface = [&](std::uint32_t self, std::size_t index, GuestCpuState32 state) {
        const auto vtable = memory.read_u32(GuestAddress32{self});
        if (!vtable.has_value()) {
            check(false, "OpenSL interface handle points at a guest vtable");
            return std::pair{state, ExecutionResult{}};
        }
        const auto slot = static_cast<std::uint64_t>(*vtable) + index * sizeof(std::uint32_t);
        if (slot > std::numeric_limits<std::uint32_t>::max()) {
            check(false, "OpenSL vtable method slot stays in the 32-bit guest address space");
            return std::pair{state, ExecutionResult{}};
        }
        const auto function = memory.read_u32(GuestAddress32{static_cast<std::uint32_t>(slot)});
        if (!function.has_value() || *function == 0) {
            check(false, "OpenSL vtable method slot contains a guest thunk");
            return std::pair{state, ExecutionResult{}};
        }
        state.r[0] = self;
        return invoke(*function, state);
    };

    constexpr std::uint32_t kInterfaceIds = 0x11500U;
    constexpr std::uint32_t kRequired = 0x11520U;
    constexpr std::uint32_t kPlayerOutput = 0x11540U;
    constexpr std::uint32_t kStack = 0x11600U;
    constexpr std::uint32_t kEngineOptions = 0x11780U;
    const auto optional_iid_variable = opensl.resolve_symbol("SL_IID_VOLUME");
    const auto optional_iid = optional_iid_variable.has_value()
        ? memory.read_u32(GuestAddress32{*optional_iid_variable}).value_or(0U) : 0U;
    const std::array<std::uint32_t, 4> engine_options{1U, 1U, 2U, 0U};
    bool engine_setup_ok = optional_iid != 0
        && memory.write_u32(GuestAddress32{kInterfaceIds}, optional_iid)
        && memory.write(GuestAddress32{kRequired}, std::array<std::byte, 1>{std::byte{0}})
        && memory.write_u32(GuestAddress32{kStack}, kInterfaceIds)
        && memory.write_u32(GuestAddress32{kStack + 4U}, kRequired);
    for (std::size_t index = 0; index < engine_options.size(); ++index) {
        engine_setup_ok = memory.write_u32(
            GuestAddress32{kEngineOptions + static_cast<std::uint32_t>(index * sizeof(std::uint32_t))},
            engine_options[index]) && engine_setup_ok;
    }
    check(engine_setup_ok, "OpenSL engine options and optional interface arrays are staged");
    if (!engine_setup_ok) return;

    GuestCpuState32 state{};
    state.r[0] = 0x10028U;
    auto [interface_count_state, interface_count_result] = invoke_symbol("slQueryNumSupportedEngineInterfaces", state);
    check(interface_count_result.status == ExecutionStatus::Completed
            && interface_count_state.r[0] == 0U
            && memory.read_u32(GuestAddress32{0x10028U}).value_or(0U) == 1U,
        "slQueryNumSupportedEngineInterfaces enumerates the supported engine interface subset");
    state = {};
    state.r[0] = 0U; // first supported interface
    state.r[1] = 0x1002cU;
    auto [queried_interface_state, queried_interface_result] = invoke_symbol("slQuerySupportedEngineInterfaces", state);
    const auto queried_interface_iid = memory.read_u32(GuestAddress32{0x1002cU}).value_or(0U);
    const auto engine_iid_variable_for_query = opensl.resolve_symbol("SL_IID_ENGINE");
    const auto engine_iid_for_query = engine_iid_variable_for_query.has_value()
        ? memory.read_u32(GuestAddress32{*engine_iid_variable_for_query}).value_or(0U) : 0U;
    check(queried_interface_result.status == ExecutionStatus::Completed
            && queried_interface_state.r[0] == 0U && queried_interface_iid == engine_iid_for_query,
        "slQuerySupportedEngineInterfaces returns the guest SL_IID_ENGINE pointer");
    state = {};
    state.r[0] = 1U; // out-of-range interface index
    state.r[1] = 0x1002cU;
    auto [bad_interface_index_state, bad_interface_index_result] = invoke_symbol("slQuerySupportedEngineInterfaces", state);
    check(bad_interface_index_result.status == ExecutionStatus::Completed
            && bad_interface_index_state.r[0] == 2U
            && memory.read_u32(GuestAddress32{0x1002cU}).value_or(1U) == 0U,
        "slQuerySupportedEngineInterfaces clears output and rejects an invalid index");
    state = {};
    auto [null_count_output_state, null_count_output_result] = invoke_symbol("slQueryNumSupportedEngineInterfaces", state);
    check(null_count_output_result.status == ExecutionStatus::Completed && null_count_output_state.r[0] == 2U,
        "slQueryNumSupportedEngineInterfaces rejects a null output pointer");

    state = {};
    check(memory.write_u32(GuestAddress32{0x1001cU}, 0xabcdef01U),
        "stage sentinel output before invalid OpenSL input checks");
    state.r[0] = 0x1001cU;
    state.r[1] = 1U;
    state.r[2] = 0xdeadbeefU; // invalid pEngineOptions with a nonzero count
    auto [bad_options_pointer_state, bad_options_pointer_result] = invoke_symbol("slCreateEngine", state);
    check(bad_options_pointer_result.status == ExecutionStatus::Completed
            && bad_options_pointer_state.r[0] == 2U
            && memory.read_u32(GuestAddress32{0x1001cU}).value_or(1U) == 0U,
        "slCreateEngine rejects an inaccessible options array without publishing an object");

    check(memory.write_u32(GuestAddress32{kEngineOptions}, 99U)
            && memory.write_u32(GuestAddress32{kEngineOptions + 4U}, 0U)
            && memory.write_u32(GuestAddress32{0x1001cU}, 0xabcdef01U),
        "stage an unsupported OpenSL engine option and a non-null output sentinel");
    state = {};
    state.r[0] = 0x1001cU;
    state.r[1] = 1U;
    state.r[2] = kEngineOptions;
    auto [unknown_option_state, unknown_option_result] = invoke_symbol("slCreateEngine", state);
    check(unknown_option_result.status == ExecutionStatus::Completed
            && unknown_option_state.r[0] == 2U
            && memory.read_u32(GuestAddress32{0x1001cU}).value_or(1U) == 0U,
        "slCreateEngine reports parameter-invalid for unknown engine option features");
    check(memory.write_u32(GuestAddress32{kEngineOptions}, engine_options[0])
            && memory.write_u32(GuestAddress32{kEngineOptions + 4U}, engine_options[1]),
        "restore the recognized thread-safety engine option and its data");

    state = {};
    state.r[0] = 0x10000U;
    state.r[1] = 2U; // numOptions
    state.r[2] = kEngineOptions; // two {feature, data} pairs
    state.r[3] = 1U; // numInterfaces; both trailing interface pointers are on the guest stack
    state.r[13] = kStack;
    auto [engine_create_state, engine_create_result] = invoke_symbol("slCreateEngine", state);
    const auto engine = memory.read_u32(GuestAddress32{0x10000U}).value_or(0U);
    check(engine_create_result.status == ExecutionStatus::Completed
            && engine_create_state.r[0] == 0U && engine != 0,
        "slCreateEngine accepts Android-compatible options and stack interfaces, then returns a guest object vtable");
    if (engine == 0) return;

    state = {};
    state.r[0] = 0x10020U;
    state.r[2] = 0xdeadbeefU;
    auto [duplicate_engine_state, duplicate_engine_result] = invoke_symbol("slCreateEngine", state);
    const auto duplicate_engine = memory.read_u32(GuestAddress32{0x10020U}).value_or(0U);
    check(duplicate_engine_result.status == ExecutionStatus::Completed
            && duplicate_engine_state.r[0] == 0U && duplicate_engine == engine,
        "repeated slCreateEngine shares Android's one engine object and increments its reference count");
    if (duplicate_engine != 0) {
        state = {};
        (void)invoke_interface(duplicate_engine, 6, state); // release only the second engine reference
    }

    state = {};
    state.r[1] = 0; // synchronous Realize
    auto [engine_realize_state, engine_realize_result] = invoke_interface(engine, 0, state);
    check(engine_realize_result.status == ExecutionStatus::Completed && engine_realize_state.r[0] == 0U,
        "SLObjectItf.Realize transitions the engine to realized state");

    const auto engine_iid_variable = opensl.resolve_symbol("SL_IID_ENGINE");
    const auto engine_iid = engine_iid_variable.has_value()
        ? memory.read_u32(GuestAddress32{*engine_iid_variable}).value_or(0U) : 0U;
    check(engine_iid != 0
            && memory.read_u32(GuestAddress32{engine_iid}).value_or(0U) == 0x8d97c260U
            && memory.read_u16(GuestAddress32{engine_iid + 4U}).value_or(0U) == 0xddd4U
            && memory.read_u16(GuestAddress32{engine_iid + 6U}).value_or(0U) == 0x11dbU,
        "SL_IID_ENGINE exports the Android NDK OpenSL ES 1.0.1 UUID");
    const auto standard_queue_iid_variable = opensl.resolve_symbol("SL_IID_BUFFERQUEUE");
    const auto standard_queue_iid = standard_queue_iid_variable.has_value()
        ? memory.read_u32(GuestAddress32{*standard_queue_iid_variable}).value_or(0U) : 0U;
    check(standard_queue_iid != 0
            && memory.read_u32(GuestAddress32{standard_queue_iid}).value_or(0U) == 0x2bc99cc0U
            && memory.read_u16(GuestAddress32{standard_queue_iid + 4U}).value_or(0U) == 0xddd4U,
        "SL_IID_BUFFERQUEUE exports the Android NDK OpenSL ES 1.0.1 UUID, not the 1.1 identifier");
    state = {};
    state.r[1] = engine_iid;
    state.r[2] = 0x10004U;
    auto [engine_interface_state, engine_interface_result] = invoke_interface(engine, 3, state);
    const auto engine_interface = memory.read_u32(GuestAddress32{0x10004U}).value_or(0U);
    check(engine_interface_result.status == ExecutionStatus::Completed
            && engine_interface_state.r[0] == 0U && engine_interface != 0,
        "SLObjectItf.GetInterface returns a distinct guest SLEngineItf");
    if (engine_interface == 0) return;

    check(memory.write_u32(GuestAddress32{kStack}, kRequired),
        "stage the single CreateOutputMix stack pointer");
    state = {};
    state.r[1] = 0x10008U;
    state.r[2] = 1U; // one optional interface
    state.r[3] = kInterfaceIds;
    state.r[13] = kStack; // pInterfaceRequired is the first stack argument
    auto [mix_create_state, mix_create_result] = invoke_interface(engine_interface, 7, state);
    const auto output_mix = memory.read_u32(GuestAddress32{0x10008U}).value_or(0U);
    check(mix_create_result.status == ExecutionStatus::Completed
            && mix_create_state.r[0] == 0U && output_mix != 0,
        "SLEngineItf.CreateOutputMix creates a guest output-mix object");
    if (output_mix == 0) return;
    state = {};
    state.r[1] = 0;
    auto [mix_realize_state, mix_realize_result] = invoke_interface(output_mix, 0, state);
    check(mix_realize_result.status == ExecutionStatus::Completed && mix_realize_state.r[0] == 0U,
        "output-mix object realizes synchronously");

    constexpr std::uint32_t kSource = 0x11000U;
    constexpr std::uint32_t kSourceLocator = 0x11100U;
    constexpr std::uint32_t kPcmFormat = 0x11200U;
    constexpr std::uint32_t kSink = 0x11300U;
    constexpr std::uint32_t kSinkLocator = 0x11400U;
    check(memory.write_u32(GuestAddress32{kSource}, kSourceLocator)
            && memory.write_u32(GuestAddress32{kSource + 4U}, kPcmFormat)
            && memory.write_u32(GuestAddress32{kSourceLocator}, 0x800007bdU)
            && memory.write_u32(GuestAddress32{kSourceLocator + 4U}, 2U),
        "Android simple-buffer-queue PCM source is staged");
    const std::array<std::uint32_t, 7> pcm_format{1U, 2U, 44'100'000U, 16U, 16U, 3U, 2U};
    for (std::size_t index = 0; index < pcm_format.size(); ++index) {
        check(memory.write_u32(GuestAddress32{kPcmFormat + static_cast<std::uint32_t>(index * 4U)}, pcm_format[index]),
            "write bounded stereo PCM format fields");
    }
    const auto output_mix_locator_type = 4U; // SL_DATALOCATOR_OUTPUTMIX
    check(memory.write_u32(GuestAddress32{kSink}, kSinkLocator)
            && memory.write_u32(GuestAddress32{kSink + 4U}, 0U)
            && memory.write_u32(GuestAddress32{kSinkLocator}, output_mix_locator_type)
            && memory.write_u32(GuestAddress32{kSinkLocator + 4U}, output_mix),
        "OpenSL audio sink references the realized output mix");
    const auto queue_iid_variable = opensl.resolve_symbol("SL_IID_ANDROIDSIMPLEBUFFERQUEUE");
    const auto queue_iid = queue_iid_variable.has_value()
        ? memory.read_u32(GuestAddress32{*queue_iid_variable}).value_or(0U) : 0U;
    check(queue_iid != 0
            && memory.read_u32(GuestAddress32{queue_iid}).value_or(0U) == 0x89f6a7e0U
            && memory.read_u16(GuestAddress32{queue_iid + 4U}).value_or(0U) == 0xbeacU
            && memory.read_u16(GuestAddress32{queue_iid + 6U}).value_or(0U) == 0x11dfU,
        "SL_IID_ANDROIDSIMPLEBUFFERQUEUE exports the Android API-level-9 extension UUID");
    if (queue_iid == 0) return;

    check(memory.write_u32(GuestAddress32{kStack}, 0U)
            && memory.write_u32(GuestAddress32{kStack + 4U}, 0U)
            && memory.write_u32(GuestAddress32{kStack + 8U}, 0U),
        "stage empty CreateAudioPlayer interface arrays");
    state = {};
    state.r[1] = 0x11560U;
    state.r[2] = kSource;
    state.r[3] = kSink;
    state.r[13] = kStack;
    auto [unrequested_player_state, unrequested_player_result] = invoke_interface(engine_interface, 2, state);
    const auto unrequested_player = memory.read_u32(GuestAddress32{0x11560U}).value_or(0U);
    check(unrequested_player_result.status == ExecutionStatus::Completed
            && unrequested_player_state.r[0] == 0U && unrequested_player != 0,
        "CreateAudioPlayer accepts no explicit queue interface while retaining the implicit play interface");
    if (unrequested_player == 0) return;
    state = {};
    state.r[1] = 0;
    auto [unrequested_realize_state, unrequested_realize_result] = invoke_interface(unrequested_player, 0, state);
    check(unrequested_realize_result.status == ExecutionStatus::Completed && unrequested_realize_state.r[0] == 0U,
        "player without an explicit buffer-queue interface can realize");
    state = {};
    state.r[1] = queue_iid;
    state.r[2] = 0x11564U;
    auto [unrequested_queue_state, unrequested_queue_result] = invoke_interface(unrequested_player, 3, state);
    check(unrequested_queue_result.status == ExecutionStatus::Completed && unrequested_queue_state.r[0] == 12U,
        "GetInterface does not expose an unrequested explicit buffer queue");
    state = {};
    (void)invoke_interface(unrequested_player, 6, state);

    check(memory.write_u32(GuestAddress32{kInterfaceIds}, queue_iid)
            && memory.write(GuestAddress32{kRequired}, std::array<std::byte, 1>{std::byte{1}}),
        "required Android simple-buffer-queue IID is staged");
    check(memory.write_u32(GuestAddress32{kStack}, 1U)
            && memory.write_u32(GuestAddress32{kStack + 4U}, kInterfaceIds)
            && memory.write_u32(GuestAddress32{kStack + 8U}, kRequired),
        "CreateAudioPlayer stack arguments are staged");
    state = {};
    state.r[1] = kPlayerOutput;
    state.r[2] = kSource;
    state.r[3] = kSink;
    state.r[13] = kStack;
    auto [player_create_state, player_create_result] = invoke_interface(engine_interface, 2, state);
    const auto player = memory.read_u32(GuestAddress32{kPlayerOutput}).value_or(0U);
    check(player_create_result.status == ExecutionStatus::Completed
            && player_create_state.r[0] == 0U && player != 0,
        "CreateAudioPlayer validates PCM layouts and creates a bounded queue player");
    if (player == 0) return;

    state = {};
    state.r[1] = 0;
    auto [player_realize_state, player_realize_result] = invoke_interface(player, 0, state);
    check(player_realize_result.status == ExecutionStatus::Completed && player_realize_state.r[0] == 0U,
        "audio player object realizes after its engine and output mix");

    const auto play_iid_variable = opensl.resolve_symbol("SL_IID_PLAY");
    const auto play_iid = play_iid_variable.has_value()
        ? memory.read_u32(GuestAddress32{*play_iid_variable}).value_or(0U) : 0U;
    state = {};
    state.r[1] = play_iid;
    state.r[2] = 0x11544U;
    auto [play_interface_state, play_interface_result] = invoke_interface(player, 3, state);
    const auto play_interface = memory.read_u32(GuestAddress32{0x11544U}).value_or(0U);
    check(play_interface_result.status == ExecutionStatus::Completed
            && play_interface_state.r[0] == 0U && play_interface != 0,
        "audio player GetInterface returns a guest SLPlayItf");
    if (play_interface == 0) return;
    state = {};
    state.r[1] = queue_iid;
    state.r[2] = 0x11548U;
    auto [queue_interface_state, queue_interface_result] = invoke_interface(player, 3, state);
    const auto queue_interface = memory.read_u32(GuestAddress32{0x11548U}).value_or(0U);
    check(queue_interface_result.status == ExecutionStatus::Completed
            && queue_interface_state.r[0] == 0U && queue_interface != 0,
        "audio player GetInterface returns a guest Android simple buffer queue");
    if (queue_interface == 0) return;

    state = {};
    state.r[1] = 3U; // SL_PLAYSTATE_PLAYING
    auto [play_state_set, play_state_result] = invoke_interface(play_interface, 0, state);
    check(play_state_result.status == ExecutionStatus::Completed && play_state_set.r[0] == 0U,
        "SLPlayItf.SetPlayState transitions the synthetic player to playing");
    state = {};
    state.r[1] = 0x1154cU;
    auto [play_state_get, play_state_get_result] = invoke_interface(play_interface, 1, state);
    check(play_state_get_result.status == ExecutionStatus::Completed && play_state_get.r[0] == 0U
            && memory.read_u32(GuestAddress32{0x1154cU}).value_or(0U) == 3U,
        "SLPlayItf.GetPlayState reports the guest playback state");

    const std::array<std::byte, 8> pcm_bytes{
        std::byte{0x10}, std::byte{0x00}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x30}, std::byte{0x00}, std::byte{0x40}, std::byte{0x00},
    };
    check(memory.write(GuestAddress32{0x12000U}, pcm_bytes), "stage a bounded stereo PCM buffer");
    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = static_cast<std::uint32_t>(pcm_bytes.size());
    auto [enqueue_state, enqueue_result] = invoke_interface(queue_interface, 0, state);
    check(enqueue_result.status == ExecutionStatus::Completed && enqueue_state.r[0] == 0U,
        "Android simple-buffer-queue Enqueue copies guest PCM into bounded host-owned storage");
    state = {};
    state.r[1] = 0x11550U;
    auto [queue_state, queue_state_result] = invoke_interface(queue_interface, 2, state);
    check(queue_state_result.status == ExecutionStatus::Completed && queue_state.r[0] == 0U
            && memory.read_u32(GuestAddress32{0x11550U}).value_or(0U) == 1U
            && memory.read_u32(GuestAddress32{0x11554U}).value_or(1U) == 0U,
        "buffer queue GetState reports one pending buffer and its current index");
    const auto consumed = opensl.consume_next_playback_buffer(player);
    check(consumed.has_value() && consumed->sample_rate_millihz == 44'100'000U
            && consumed->channels == 2U && consumed->bits_per_sample == 16U
            && consumed->samples == std::vector<std::byte>(pcm_bytes.begin(), pcm_bytes.end()),
        "host drain obtains the queued PCM payload without exposing a guest pointer");
    state = {};
    state.r[1] = 0x11550U;
    auto [drained_state, drained_state_result] = invoke_interface(queue_interface, 2, state);
    check(drained_state_result.status == ExecutionStatus::Completed && drained_state.r[0] == 0U
            && memory.read_u32(GuestAddress32{0x11550U}).value_or(1U) == 0U
            && memory.read_u32(GuestAddress32{0x11554U}).value_or(0U) == 1U,
        "buffer queue state advances after a host-side drain");

    state = {};
    state.r[1] = 2U; // SL_PLAYSTATE_PAUSED
    auto [pause_state, pause_result] = invoke_interface(play_interface, 0, state);
    check(pause_result.status == ExecutionStatus::Completed && pause_state.r[0] == 0U,
        "SLPlayItf can pause the synthetic queue player");
    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = static_cast<std::uint32_t>(pcm_bytes.size());
    auto [paused_enqueue_state, paused_enqueue_result] = invoke_interface(queue_interface, 0, state);
    check(paused_enqueue_result.status == ExecutionStatus::Completed && paused_enqueue_state.r[0] == 0U
            && !opensl.consume_next_playback_buffer(player).has_value(),
        "queued PCM is retained but not host-drained while playback is paused");
    state = {};
    state.r[1] = 3U;
    auto [resume_state, resume_result] = invoke_interface(play_interface, 0, state);
    const auto resumed_buffer = opensl.consume_next_playback_buffer(player);
    check(resume_result.status == ExecutionStatus::Completed && resume_state.r[0] == 0U
            && resumed_buffer.has_value(),
        "resuming playback makes the retained PCM buffer available to the host drain");

    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = 3U; // not an integral PCM frame
    auto [invalid_enqueue_state, invalid_enqueue_result] = invoke_interface(queue_interface, 0, state);
    check(invalid_enqueue_result.status == ExecutionStatus::Completed
            && invalid_enqueue_state.r[0] == 2U,
        "buffer queue rejects partial PCM frames");

    state = {};
    state.r[1] = 0x9000U; // callbacks are not dispatched by this runtime
    auto [callback_state, callback_result] = invoke_interface(queue_interface, 3, state);
    check(callback_result.status == ExecutionStatus::Completed
            && callback_state.r[0] == 12U,
        "buffer queue explicitly rejects callback dispatch without a guest scheduler");

    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = static_cast<std::uint32_t>(pcm_bytes.size());
    auto [second_enqueue_state, second_enqueue_result] = invoke_interface(queue_interface, 0, state);
    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = static_cast<std::uint32_t>(pcm_bytes.size());
    auto [queue_full_state, queue_full_result] = invoke_interface(queue_interface, 0, state);
    state = {};
    state.r[1] = 0x12000U;
    state.r[2] = static_cast<std::uint32_t>(pcm_bytes.size());
    auto [queue_overflow_state, queue_overflow_result] = invoke_interface(queue_interface, 0, state);
    state = {};
    auto [clear_state, clear_result] = invoke_interface(queue_interface, 1, state);
    state = {};
    state.r[1] = 0x11550U;
    auto [clear_get_state, clear_get_result] = invoke_interface(queue_interface, 2, state);
    check(second_enqueue_result.status == ExecutionStatus::Completed && second_enqueue_state.r[0] == 0U
            && queue_full_result.status == ExecutionStatus::Completed && queue_full_state.r[0] == 0U
            && queue_overflow_result.status == ExecutionStatus::Completed && queue_overflow_state.r[0] == 7U
            && clear_result.status == ExecutionStatus::Completed && clear_state.r[0] == 0U
            && clear_get_result.status == ExecutionStatus::Completed && clear_get_state.r[0] == 0U
            && memory.read_u32(GuestAddress32{0x11550U}).value_or(1U) == 0U
            && memory.read_u32(GuestAddress32{0x11554U}).value_or(1U) == 0U
            && !opensl.consume_next_playback_buffer(player).has_value(),
        "buffer queue Clear releases queued PCM, resets the index, and restores bounded queue accounting");

    state = {};
    auto [destroy_player_state, destroy_player_result] = invoke_interface(player, 6, state);
    check(destroy_player_result.status == ExecutionStatus::Completed
            && !opensl.consume_next_playback_buffer(player).has_value(),
        "SLObjectItf.Destroy invalidates player and queue handles");
    (void)destroy_player_state;
    state = {};
    (void)invoke_interface(output_mix, 6, state);
    state = {};
    (void)invoke_interface(engine, 6, state);

    state = {};
    state.r[0] = 0x10024U;
    state.r[2] = 0xdeadbeefU; // ignored when numOptions in r1 is zero
    auto [zero_option_state, zero_option_result] = invoke_symbol("slCreateEngine", state);
    const auto zero_option_engine = memory.read_u32(GuestAddress32{0x10024U}).value_or(0U);
    check(zero_option_result.status == ExecutionStatus::Completed
            && zero_option_state.r[0] == 0U && zero_option_engine != 0,
        "slCreateEngine ignores the options pointer when numOptions is zero and permits recreation after Destroy");
    if (zero_option_engine != 0) {
        state = {};
        (void)invoke_interface(zero_option_engine, 6, state);
    }
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

    check(memory.map_zeroed(GuestAddress32{0x8000}, 0x1000,
            GuestPermission::Read | GuestPermission::Write),
        "A32 block-transfer stack maps read/write");
    std::vector<std::byte> arm_multiple_program(32, std::byte{0});
    put_u32(arm_multiple_program, 0, 0xe3a00011U);  // mov r0, #0x11
    put_u32(arm_multiple_program, 4, 0xe3a01022U);  // mov r1, #0x22
    put_u32(arm_multiple_program, 8, 0xe92d0003U);  // stmdb sp!, {r0, r1}
    put_u32(arm_multiple_program, 12, 0xe3a00000U); // mov r0, #0
    put_u32(arm_multiple_program, 16, 0xe3a01000U); // mov r1, #0
    put_u32(arm_multiple_program, 20, 0xe8bd0003U); // ldmia sp!, {r0, r1}
    put_u32(arm_multiple_program, 24, 0xe3a07001U); // mov r7, #1
    put_u32(arm_multiple_program, 28, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x5000}, arm_multiple_program, arm_multiple_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "A32 LDM/STM test code maps RX");
    GuestCpuState32 arm_multiple_state{};
    arm_multiple_state.r[13] = 0x9000U;
    const auto arm_multiple_result = interpreter.run(arm_multiple_state, GuestAddress32{0x5000}, 32);
    check(arm_multiple_result.status == ExecutionStatus::Completed
            && arm_multiple_state.r[0] == 0x11U && arm_multiple_state.r[1] == 0x22U
            && arm_multiple_state.r[13] == 0x9000U,
        "A32 STM/LDM transfer registers in order and apply stack-pointer writeback");

    check(memory.map_zeroed(GuestAddress32{0xb000U}, 0x100U,
            GuestPermission::Read | GuestPermission::Write)
            && memory.write_u16(GuestAddress32{0xb00cU}, 0x5aa5U),
        "A32 halfword-transfer data maps read/write and stages a register-offset value");
    std::vector<std::byte> arm_halfword_program(36, std::byte{0});
    put_u32(arm_halfword_program, 0, 0xe1e100b4U);  // strh r0, [r1, #4]!
    put_u32(arm_halfword_program, 4, 0xe1d120b0U);  // ldrh r2, [r1]
    put_u32(arm_halfword_program, 8, 0xe19190b8U);  // ldrh r9, [r1, r8]
    put_u32(arm_halfword_program, 12, 0xe1d130d0U); // ldrsb r3, [r1]
    put_u32(arm_halfword_program, 16, 0xe1d140f0U); // ldrsh r4, [r1]
    put_u32(arm_halfword_program, 20, 0xe0d150b2U); // ldrh r5, [r1], #2
    put_u32(arm_halfword_program, 24, 0xe0c160b2U); // strh r6, [r1], #2
    put_u32(arm_halfword_program, 28, 0xe3a07001U); // mov r7, #1
    put_u32(arm_halfword_program, 32, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x5100U}, arm_halfword_program, arm_halfword_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "A32 halfword-transfer test code maps RX");
    GuestCpuState32 arm_halfword_state{};
    arm_halfword_state.r[0] = 0x80ffU;
    arm_halfword_state.r[1] = 0xb000U;
    arm_halfword_state.r[6] = 0x1234U;
    arm_halfword_state.r[8] = 8U;
    const auto arm_halfword_result = interpreter.run(arm_halfword_state, GuestAddress32{0x5100U}, 32);
    check(arm_halfword_result.status == ExecutionStatus::Completed
            && arm_halfword_state.r[1] == 0xb008U
            && arm_halfword_state.r[2] == 0x000080ffU
            && arm_halfword_state.r[3] == 0xffffffffU
            && arm_halfword_state.r[4] == 0xffff80ffU
            && arm_halfword_state.r[5] == 0x000080ffU
            && arm_halfword_state.r[9] == 0x00005aa5U
            && memory.read_u32(GuestAddress32{0xb006U}).value_or(0U) == 0x00001234U,
        "A32 STRH/LDRH/LDRSB/LDRSH cover register/immediate offsets, sign extension, and pre/post-index writeback");

    check(memory.map_zeroed(GuestAddress32{0xc000U}, 0x100U,
            GuestPermission::Read | GuestPermission::Write),
        "A32 doubleword-transfer data maps read/write");
    std::vector<std::byte> arm_doubleword_program(16, std::byte{0});
    put_u32(arm_doubleword_program, 0, 0xe1e120f8U); // strd r2, r3, [r1, #8]!
    put_u32(arm_doubleword_program, 4, 0xe0c140d8U); // ldrd r4, r5, [r1], #8
    put_u32(arm_doubleword_program, 8, 0xe3a07001U); // mov r7, #1
    put_u32(arm_doubleword_program, 12, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x5200U}, arm_doubleword_program, arm_doubleword_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "A32 doubleword-transfer test code maps RX");
    GuestCpuState32 arm_doubleword_state{};
    arm_doubleword_state.r[1] = 0xc000U;
    arm_doubleword_state.r[2] = 0x11223344U;
    arm_doubleword_state.r[3] = 0x55667788U;
    const auto arm_doubleword_result = interpreter.run(arm_doubleword_state, GuestAddress32{0x5200U}, 16);
    check(arm_doubleword_result.status == ExecutionStatus::Completed
            && arm_doubleword_state.r[1] == 0xc010U
            && arm_doubleword_state.r[4] == 0x11223344U
            && arm_doubleword_state.r[5] == 0x55667788U
            && memory.read_u32(GuestAddress32{0xc008U}).value_or(0U) == 0x11223344U
            && memory.read_u32(GuestAddress32{0xc00cU}).value_or(0U) == 0x55667788U,
        "A32 STRD/LDRD transfer register pairs in order and apply immediate address writeback");

    std::vector<std::byte> arm_long_multiply_program(24, std::byte{0});
    put_u32(arm_long_multiply_program, 0, 0xe0c32190U); // smull r2, r3, r0, r1
    put_u32(arm_long_multiply_program, 4, 0xe0854190U); // umull r4, r5, r0, r1
    put_u32(arm_long_multiply_program, 8, 0xe0f98190U); // smlals r8, r9, r0, r1
    put_u32(arm_long_multiply_program, 12, 0xe0aba190U); // umlal r10, r11, r0, r1
    put_u32(arm_long_multiply_program, 16, 0xe3a07001U); // mov r7, #1
    put_u32(arm_long_multiply_program, 20, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x5300U}, arm_long_multiply_program,
            arm_long_multiply_program.size(), GuestPermission::Read | GuestPermission::Execute),
        "A32 long-multiply test code maps RX");
    GuestCpuState32 arm_long_multiply_state{};
    arm_long_multiply_state.r[0] = 0xfffffff9U; // -7 signed, 4294967289 unsigned
    arm_long_multiply_state.r[1] = 9U;
    arm_long_multiply_state.r[8] = 100U;
    arm_long_multiply_state.r[10] = 5U;
    arm_long_multiply_state.r[11] = 1U;
    arm_long_multiply_state.cpsr |= 0x30000000U; // preserve C and V across SMLALS
    const auto arm_long_multiply_result = interpreter.run(
        arm_long_multiply_state, GuestAddress32{0x5300U}, 32);
    check(arm_long_multiply_result.status == ExecutionStatus::Completed
            && arm_long_multiply_state.r[2] == 0xffffffc1U && arm_long_multiply_state.r[3] == 0xffffffffU
            && arm_long_multiply_state.r[4] == 0xffffffc1U && arm_long_multiply_state.r[5] == 8U
            && arm_long_multiply_state.r[8] == 37U && arm_long_multiply_state.r[9] == 0U
            && arm_long_multiply_state.r[10] == 0xffffffc6U && arm_long_multiply_state.r[11] == 9U
            && (arm_long_multiply_state.cpsr & 0xf0000000U) == 0x30000000U,
        "A32 SMULL/UMULL/SMLAL/UMLAL compute full 64-bit results and preserve unaffected flags");

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

    std::vector<std::byte> arm_divide_program(24, std::byte{0});
    put_u32(arm_divide_program, 0, 0xe712f110U);  // sdiv r2, r0, r1
    put_u32(arm_divide_program, 4, 0xe733f110U);  // udiv r3, r0, r1
    put_u32(arm_divide_program, 8, 0xe714f510U);  // sdiv r4, r0, r5
    put_u32(arm_divide_program, 12, 0xe736f510U); // udiv r6, r0, r5
    put_u32(arm_divide_program, 16, 0xe3a07001U); // mov r7, #1
    put_u32(arm_divide_program, 20, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2600}, arm_divide_program, arm_divide_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "A32 integer-division test code maps RX");
    GuestCpuState32 arm_divide_state{};
    arm_divide_state.r[0] = std::bit_cast<std::uint32_t>(std::int32_t{-41});
    arm_divide_state.r[1] = 5;
    arm_divide_state.r[5] = 0;
    const auto arm_divide_result = interpreter.run(arm_divide_state, GuestAddress32{0x2600}, 32);
    check(arm_divide_result.status == ExecutionStatus::Completed
            && arm_divide_state.r[2] == std::bit_cast<std::uint32_t>(std::int32_t{-8})
            && arm_divide_state.r[3] == (0xffffffffU - 40U) / 5U
            && arm_divide_state.r[4] == 0 && arm_divide_state.r[6] == 0,
        "A32 SDIV/UDIV truncate signed quotients toward zero and handle zero divisors deterministically");

    std::vector<std::byte> thumb_divide_program(20, std::byte{0});
    put_u16(thumb_divide_program, 0, 0xfb90U); // sdiv r2, r0, r1
    put_u16(thumb_divide_program, 2, 0xf2f1U);
    put_u16(thumb_divide_program, 4, 0xfbb0U); // udiv r3, r0, r1
    put_u16(thumb_divide_program, 6, 0xf3f1U);
    put_u16(thumb_divide_program, 8, 0xfb90U); // sdiv r4, r0, r5
    put_u16(thumb_divide_program, 10, 0xf4f5U);
    put_u16(thumb_divide_program, 12, 0xfbb0U); // udiv r6, r0, r5
    put_u16(thumb_divide_program, 14, 0xf6f5U);
    put_u16(thumb_divide_program, 16, 0x2701U); // movs r7, #1
    put_u16(thumb_divide_program, 18, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2700}, thumb_divide_program, thumb_divide_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 integer-division test code maps RX");
    GuestCpuState32 thumb_divide_state{};
    thumb_divide_state.r[0] = std::bit_cast<std::uint32_t>(std::int32_t{-41});
    thumb_divide_state.r[1] = 5;
    thumb_divide_state.r[5] = 0;
    const auto thumb_divide_result = interpreter.run(thumb_divide_state, GuestAddress32{0x2701}, 32);
    check(thumb_divide_result.status == ExecutionStatus::Completed
            && thumb_divide_state.r[2] == std::bit_cast<std::uint32_t>(std::int32_t{-8})
            && thumb_divide_state.r[3] == (0xffffffffU - 40U) / 5U
            && thumb_divide_state.r[4] == 0 && thumb_divide_state.r[6] == 0,
        "T32 SDIV/UDIV share bounded signed and unsigned divide semantics");

    std::vector<std::byte> thumb_reverse_program(10, std::byte{0});
    put_u16(thumb_reverse_program, 0, 0xba02U); // rev r2, r0
    put_u16(thumb_reverse_program, 2, 0xba43U); // rev16 r3, r0
    put_u16(thumb_reverse_program, 4, 0xba84U); // rbit r4, r0
    put_u16(thumb_reverse_program, 6, 0xbac5U); // revsh r5, r0
    put_u16(thumb_reverse_program, 8, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2500}, thumb_reverse_program, thumb_reverse_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T16 byte-reversal test code maps RX");
    GuestCpuState32 thumb_reverse_state{};
    thumb_reverse_state.r[0] = 0x80ff1234U;
    thumb_reverse_state.r[7] = 1;
    thumb_reverse_state.cpsr |= 0xa0000000U;
    std::uint32_t expected_rbit = 0;
    for (unsigned bit = 0; bit < 32; ++bit) {
        expected_rbit |= ((thumb_reverse_state.r[0] >> bit) & 1U) << (31U - bit);
    }
    const auto reverse_flags = thumb_reverse_state.cpsr & 0xf0000000U;
    const auto thumb_reverse_result = interpreter.run(thumb_reverse_state, GuestAddress32{0x2501}, 16);
    check(thumb_reverse_result.status == ExecutionStatus::Completed
            && thumb_reverse_state.r[2] == 0x3412ff80U
            && thumb_reverse_state.r[3] == 0xff803412U
            && thumb_reverse_state.r[4] == expected_rbit
            && thumb_reverse_state.r[5] == 0x00003412U
            && (thumb_reverse_state.cpsr & 0xf0000000U) == reverse_flags,
        "T16 REV/REV16/RBIT/REVSH operate on bytes without changing condition flags");

    std::vector<std::byte> thumb_bitfield_program(18, std::byte{0});
    put_u16(thumb_bitfield_program, 0, 0xf3c0U); // ubfx r2, r0, #8, #8
    put_u16(thumb_bitfield_program, 2, 0x2207U);
    put_u16(thumb_bitfield_program, 4, 0xf340U); // sbfx r3, r0, #8, #8
    put_u16(thumb_bitfield_program, 6, 0x2307U);
    put_u16(thumb_bitfield_program, 8, 0xf361U); // bfi r4, r1, #8, #8
    put_u16(thumb_bitfield_program, 10, 0x240fU);
    put_u16(thumb_bitfield_program, 12, 0xf36fU); // bfc r5, #4, #8
    put_u16(thumb_bitfield_program, 14, 0x150bU);
    put_u16(thumb_bitfield_program, 16, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2800}, thumb_bitfield_program, thumb_bitfield_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 bitfield test code maps RX");
    GuestCpuState32 thumb_bitfield_state{};
    thumb_bitfield_state.r[0] = 0x1234ff80U;
    thumb_bitfield_state.r[1] = 0xa5U;
    thumb_bitfield_state.r[4] = 0xdeadbeefU;
    thumb_bitfield_state.r[5] = 0xffffffffU;
    thumb_bitfield_state.r[7] = 1;
    const auto thumb_bitfield_result = interpreter.run(thumb_bitfield_state, GuestAddress32{0x2801}, 16);
    check(thumb_bitfield_result.status == ExecutionStatus::Completed
            && thumb_bitfield_state.r[2] == 0xffU && thumb_bitfield_state.r[3] == 0xffffffffU
            && thumb_bitfield_state.r[4] == 0xdeada5efU && thumb_bitfield_state.r[5] == 0xfffff00fU,
        "T32 UBFX/SBFX sign-extend fields and BFI/BFC update only the selected bits");

    std::vector<std::byte> thumb_cb_program(14, std::byte{0});
    put_u16(thumb_cb_program, 0, 0xb110U); // cbz r0, target
    put_u16(thumb_cb_program, 2, 0x4611U); // mov r1, r2 (fall-through)
    put_u16(thumb_cb_program, 4, 0xe002U); // b after the conditional slot
    put_u16(thumb_cb_program, 8, 0x4619U); // mov r1, r3 (CBZ/CBNZ target)
    put_u16(thumb_cb_program, 10, 0xbf00U); // nop
    put_u16(thumb_cb_program, 12, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2d00}, thumb_cb_program, thumb_cb_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T16 CBZ/CBNZ test code maps RX");
    const auto make_cb_state = [](std::uint32_t r0) {
        GuestCpuState32 state{};
        state.r[0] = r0;
        state.r[2] = 1U;
        state.r[3] = 2U;
        state.r[7] = 1U;
        state.cpsr |= 0xa0000000U;
        return state;
    };
    auto cbz_taken_state = make_cb_state(0U);
    const auto cbz_taken_flags = cbz_taken_state.cpsr & 0xf0000000U;
    const auto cbz_taken_result = interpreter.run(cbz_taken_state, GuestAddress32{0x2d01}, 16);
    auto cbz_not_taken_state = make_cb_state(1U);
    const auto cbz_not_taken_result = interpreter.run(cbz_not_taken_state, GuestAddress32{0x2d01}, 16);
    put_u16(thumb_cb_program, 0, 0xb910U); // cbnz r0, target
    check(memory.map_bytes(GuestAddress32{0x2d20}, thumb_cb_program, thumb_cb_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T16 CBNZ encoding maps RX");
    auto cbnz_taken_state = make_cb_state(1U);
    const auto cbnz_taken_result = interpreter.run(cbnz_taken_state, GuestAddress32{0x2d21}, 16);
    auto cbnz_not_taken_state = make_cb_state(0U);
    const auto cbnz_not_taken_result = interpreter.run(cbnz_not_taken_state, GuestAddress32{0x2d21}, 16);
    check(cbz_taken_result.status == ExecutionStatus::Completed && cbz_taken_state.r[1] == 2U
            && cbz_not_taken_result.status == ExecutionStatus::Completed && cbz_not_taken_state.r[1] == 1U
            && cbnz_taken_result.status == ExecutionStatus::Completed && cbnz_taken_state.r[1] == 2U
            && cbnz_not_taken_result.status == ExecutionStatus::Completed && cbnz_not_taken_state.r[1] == 1U
            && (cbz_taken_state.cpsr & 0xf0000000U) == cbz_taken_flags,
        "T16 CBZ/CBNZ branch forward on register value without consuming or changing APSR flags");

    std::vector<std::byte> thumb_add_sub_w_program(12, std::byte{0});
    put_u16(thumb_add_sub_w_program, 0, 0xf200U); // addw r2, r0, #0x345
    put_u16(thumb_add_sub_w_program, 2, 0x3245U);
    put_u16(thumb_add_sub_w_program, 4, 0xf2a2U); // subw r3, r2, #0x45
    put_u16(thumb_add_sub_w_program, 6, 0x0345U);
    put_u16(thumb_add_sub_w_program, 8, 0x2701U); // movs r7, #1
    put_u16(thumb_add_sub_w_program, 10, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2e00}, thumb_add_sub_w_program, thumb_add_sub_w_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 ADDW/SUBW test code maps RX");
    GuestCpuState32 add_sub_w_state{};
    add_sub_w_state.r[0] = 0x1000U;
    const auto add_sub_w_result = interpreter.run(add_sub_w_state, GuestAddress32{0x2e01}, 16);
    check(add_sub_w_result.status == ExecutionStatus::Completed
            && add_sub_w_state.r[2] == 0x1345U && add_sub_w_state.r[3] == 0x1300U,
        "T32 ADDW/SUBW combine split immediates without modifying flags");

    std::vector<std::byte> thumb_cond_branch_program(14, std::byte{0});
    put_u16(thumb_cond_branch_program, 0, 0xf040U); // bne.w +4
    put_u16(thumb_cond_branch_program, 2, 0x8002U);
    put_u16(thumb_cond_branch_program, 4, 0x2001U); // movs r0, #1 (Z path)
    put_u16(thumb_cond_branch_program, 6, 0xe000U); // b.n +0, skip the NE target
    put_u16(thumb_cond_branch_program, 8, 0x2002U); // movs r0, #2 (NE target)
    put_u16(thumb_cond_branch_program, 10, 0x2701U); // movs r7, #1
    put_u16(thumb_cond_branch_program, 12, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2f00}, thumb_cond_branch_program, thumb_cond_branch_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 conditional branch test code maps RX");
    GuestCpuState32 branch_ne_state{};
    const auto branch_ne_result = interpreter.run(branch_ne_state, GuestAddress32{0x2f01}, 16);
    GuestCpuState32 branch_eq_state{};
    branch_eq_state.cpsr |= 1U << 30U;
    const auto branch_eq_result = interpreter.run(branch_eq_state, GuestAddress32{0x2f01}, 16);
    check(branch_ne_result.status == ExecutionStatus::Completed && branch_ne_state.r[0] == 2U
            && branch_eq_result.status == ExecutionStatus::Completed && branch_eq_state.r[0] == 1U,
        "T32 conditional B.W follows APSR conditions and sign-extended displacement");

    check(memory.map_zeroed(GuestAddress32{0x3200}, 0x100,
            GuestPermission::Read | GuestPermission::Write),
        "T32 indexed memory test data maps read/write");
    std::vector<std::byte> thumb_indexed_memory_program(28, std::byte{0});
    put_u16(thumb_indexed_memory_program, 0, 0xf841U); // str r0, [r1, #4]!
    put_u16(thumb_indexed_memory_program, 2, 0x0f04U);
    put_u16(thumb_indexed_memory_program, 4, 0xf851U); // ldr r2, [r1], #4
    put_u16(thumb_indexed_memory_program, 6, 0x2b04U);
    put_u16(thumb_indexed_memory_program, 8, 0xf801U); // strb r3, [r1, #-1]!
    put_u16(thumb_indexed_memory_program, 10, 0x3d01U);
    put_u16(thumb_indexed_memory_program, 12, 0xf991U); // ldrsb r4, [r1]
    put_u16(thumb_indexed_memory_program, 14, 0x4000U);
    put_u16(thumb_indexed_memory_program, 16, 0xf821U); // strh r5, [r1, #1]!
    put_u16(thumb_indexed_memory_program, 18, 0x5f01U);
    put_u16(thumb_indexed_memory_program, 20, 0xf8b1U); // ldrh r6, [r1]
    put_u16(thumb_indexed_memory_program, 22, 0x6000U);
    put_u16(thumb_indexed_memory_program, 24, 0x2701U); // movs r7, #1
    put_u16(thumb_indexed_memory_program, 26, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3100}, thumb_indexed_memory_program,
            thumb_indexed_memory_program.size(), GuestPermission::Read | GuestPermission::Execute),
        "T32 indexed memory test code maps RX");
    GuestCpuState32 thumb_indexed_memory_state{};
    thumb_indexed_memory_state.r[0] = 0xaabbccddU;
    thumb_indexed_memory_state.r[1] = 0x3200U;
    thumb_indexed_memory_state.r[3] = 0x80U;
    thumb_indexed_memory_state.r[5] = 0x1234U;
    const auto thumb_indexed_memory_result = interpreter.run(
        thumb_indexed_memory_state, GuestAddress32{0x3101}, 24);
    const auto stored_byte = memory.read_u8(GuestAddress32{0x3207});
    const auto stored_halfword = memory.read_u16(GuestAddress32{0x3208});
    check(thumb_indexed_memory_result.status == ExecutionStatus::Completed
            && thumb_indexed_memory_state.r[1] == 0x3208U
            && thumb_indexed_memory_state.r[2] == 0xaabbccddU
            && thumb_indexed_memory_state.r[4] == 0xffffff80U
            && thumb_indexed_memory_state.r[6] == 0x1234U
            && stored_byte.has_value() && *stored_byte == 0x80U
            && stored_halfword.has_value() && *stored_halfword == 0x1234U,
        "T32 pre/post-indexed word, halfword, and signed-byte transfers apply writeback and bounds checks");

    check(memory.map_zeroed(GuestAddress32{0x3800}, 0x100,
            GuestPermission::Read | GuestPermission::Write),
        "T32 register-offset test data maps read/write");
    const std::array<std::byte, 1> register_offset_byte{std::byte{0x44}};
    check(memory.write(GuestAddress32{0x3804}, register_offset_byte)
            && memory.write_u16(GuestAddress32{0x3806}, 0x8001U),
        "T32 byte and signed-halfword sources are staged");
    std::vector<std::byte> thumb_register_offset_program(30, std::byte{0});
    put_u16(thumb_register_offset_program, 0, 0xf841U); // str r0, [r1, r2, lsl #2]
    put_u16(thumb_register_offset_program, 2, 0x0022U);
    put_u16(thumb_register_offset_program, 4, 0xf851U); // ldr r3, [r1, r2, lsl #2]
    put_u16(thumb_register_offset_program, 6, 0x3022U);
    put_u16(thumb_register_offset_program, 8, 0xf811U); // ldrb r4, [r1, r5]
    put_u16(thumb_register_offset_program, 10, 0x4005U);
    put_u16(thumb_register_offset_program, 12, 0xf931U); // ldrsh r6, [r1, r7, lsl #1]
    put_u16(thumb_register_offset_program, 14, 0x6017U);
    put_u16(thumb_register_offset_program, 16, 0xf801U); // strb r8, [r1, r5]
    put_u16(thumb_register_offset_program, 18, 0x8005U);
    put_u16(thumb_register_offset_program, 20, 0xf811U); // ldrb r9, [r1, r5]
    put_u16(thumb_register_offset_program, 22, 0x9005U);
    put_u16(thumb_register_offset_program, 24, 0x2701U); // movs r7, #1
    put_u16(thumb_register_offset_program, 26, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3400}, thumb_register_offset_program,
            thumb_register_offset_program.size(), GuestPermission::Read | GuestPermission::Execute),
        "T32 register-offset load/store test code maps RX");
    GuestCpuState32 thumb_register_offset_state{};
    thumb_register_offset_state.r[0] = 0x11223344U;
    thumb_register_offset_state.r[1] = 0x3800U;
    thumb_register_offset_state.r[2] = 2U;
    thumb_register_offset_state.r[5] = 4U;
    thumb_register_offset_state.r[7] = 3U;
    thumb_register_offset_state.r[8] = 0x5aU;
    const auto thumb_register_offset_result = interpreter.run(
        thumb_register_offset_state, GuestAddress32{0x3401}, 16);
    const auto register_offset_word = memory.read_u32(GuestAddress32{0x3808}).value_or(0);
    const bool register_offset_passed = thumb_register_offset_result.status == ExecutionStatus::Completed
        && thumb_register_offset_state.r[3] == 0x11223344U
        && thumb_register_offset_state.r[4] == 0x44U
        && thumb_register_offset_state.r[6] == 0xffff8001U
        && thumb_register_offset_state.r[9] == 0x5aU
        && register_offset_word == 0x11223344U;
    if (!register_offset_passed) {
        std::cerr << "T32 register-offset diagnostics: status=" << static_cast<int>(thumb_register_offset_result.status)
            << " diagnostic=\"" << thumb_register_offset_result.diagnostic << '\"'
            << " r3=0x" << std::hex << thumb_register_offset_state.r[3]
            << " r4=0x" << thumb_register_offset_state.r[4]
            << " r6=0x" << thumb_register_offset_state.r[6]
            << " r9=0x" << thumb_register_offset_state.r[9]
            << " mem=0x" << register_offset_word << std::dec << '\n';
    }
    check(register_offset_passed,
        "T32 register-offset word/byte transfers apply scaled indices and signed halfword loads");

    check(memory.map_zeroed(GuestAddress32{0xa000}, 0x1000,
            GuestPermission::Read | GuestPermission::Write),
        "T32 multiple-transfer stack region maps read/write");
    std::vector<std::byte> thumb_stmdb_program(8, std::byte{0});
    put_u16(thumb_stmdb_program, 0, 0xe92dU); // stmdb sp!, {r4, r8, lr}
    put_u16(thumb_stmdb_program, 2, 0x4110U);
    put_u16(thumb_stmdb_program, 4, 0x2701U); // movs r7, #1
    put_u16(thumb_stmdb_program, 6, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3300}, thumb_stmdb_program, thumb_stmdb_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 STMDB test code maps RX");
    GuestCpuState32 thumb_stmdb_state{};
    thumb_stmdb_state.r[13] = 0xa100U;
    thumb_stmdb_state.r[4] = 0x44444444U;
    thumb_stmdb_state.r[8] = 0x88888888U;
    thumb_stmdb_state.r[14] = 0xeeeeeeeeU;
    const auto thumb_stmdb_result = interpreter.run(thumb_stmdb_state, GuestAddress32{0x3301}, 8);
    check(thumb_stmdb_result.status == ExecutionStatus::Completed && thumb_stmdb_state.r[13] == 0xa0f4U
            && memory.read_u32(GuestAddress32{0xa0f4}).value_or(0) == 0x44444444U
            && memory.read_u32(GuestAddress32{0xa0f8}).value_or(0) == 0x88888888U
            && memory.read_u32(GuestAddress32{0xa0fc}).value_or(0) == 0xeeeeeeeeU,
        "T32 STMDB stores high registers in ascending register order and writes back the stack pointer");

    std::vector<std::byte> thumb_ldmia_program(8, std::byte{0});
    put_u16(thumb_ldmia_program, 0, 0xe8bdU); // ldmia sp!, {r4, r8, lr}
    put_u16(thumb_ldmia_program, 2, 0x4110U);
    put_u16(thumb_ldmia_program, 4, 0x2701U); // movs r7, #1
    put_u16(thumb_ldmia_program, 6, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3340}, thumb_ldmia_program, thumb_ldmia_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 LDMIA test code maps RX");
    GuestCpuState32 thumb_ldmia_state{};
    thumb_ldmia_state.r[13] = 0xa0f4U;
    const auto thumb_ldmia_result = interpreter.run(thumb_ldmia_state, GuestAddress32{0x3341}, 8);
    check(thumb_ldmia_result.status == ExecutionStatus::Completed && thumb_ldmia_state.r[13] == 0xa100U
            && thumb_ldmia_state.r[4] == 0x44444444U && thumb_ldmia_state.r[8] == 0x88888888U
            && thumb_ldmia_state.r[14] == 0xeeeeeeeeU,
        "T32 LDMIA restores high registers and applies writeback");

    std::vector<std::byte> thumb_pop_pc_program(8, std::byte{0});
    put_u16(thumb_pop_pc_program, 0, 0xe8bdU); // ldmia sp!, {r4, r8, pc}
    put_u16(thumb_pop_pc_program, 2, 0x8110U);
    put_u16(thumb_pop_pc_program, 4, 0x2701U); // movs r7, #1 -- loaded PC target
    put_u16(thumb_pop_pc_program, 6, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x3380}, thumb_pop_pc_program, thumb_pop_pc_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "T32 LDMIA-to-PC test code maps RX");
    check(memory.write_u32(GuestAddress32{0xa080}, 0x44444444U)
            && memory.write_u32(GuestAddress32{0xa084}, 0x88888888U)
            && memory.write_u32(GuestAddress32{0xa088}, 0x3385U),
        "T32 LDMIA-to-PC stack frame is staged");
    GuestCpuState32 thumb_pop_pc_state{};
    thumb_pop_pc_state.r[13] = 0xa080U;
    const auto thumb_pop_pc_result = interpreter.run(thumb_pop_pc_state, GuestAddress32{0x3381}, 8);
    check(thumb_pop_pc_result.status == ExecutionStatus::Completed && thumb_pop_pc_state.r[13] == 0xa08cU
            && thumb_pop_pc_state.r[4] == 0x44444444U && thumb_pop_pc_state.r[8] == 0x88888888U,
        "T32 LDMIA loading PC returns through the Thumb target after restoring high registers");

    std::vector<std::byte> thumb_table(8, std::byte{0});
    thumb_table[1] = static_cast<std::byte>(6U);
    put_u16(thumb_table, 4, 6U);
    check(memory.map_bytes(GuestAddress32{0x2a00}, thumb_table, thumb_table.size(), GuestPermission::Read),
        "TBB/TBH lookup table maps read-only");
    std::vector<std::byte> tbb_program(22, std::byte{0});
    put_u16(tbb_program, 0, 0xe8d0U); // tbb [r0, r1]
    put_u16(tbb_program, 2, 0xf001U);
    put_u16(tbb_program, 16, 0x2007U); // movs r0, #7 -- table branch target
    put_u16(tbb_program, 18, 0x2701U); // movs r7, #1
    put_u16(tbb_program, 20, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2900}, tbb_program, tbb_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "TBB control-flow test code maps RX");
    GuestCpuState32 tbb_state{};
    tbb_state.r[0] = 0x2a00U;
    tbb_state.r[1] = 1U;
    const auto tbb_result = interpreter.run(tbb_state, GuestAddress32{0x2901}, 16);
    check(tbb_result.status == ExecutionStatus::Completed && tbb_state.r[0] == 7U,
        "TBB uses byte-indexed offsets relative to the following Thumb instruction");

    std::vector<std::byte> tbh_program(22, std::byte{0});
    put_u16(tbh_program, 0, 0xe8d0U); // tbh [r0, r1]
    put_u16(tbh_program, 2, 0xf011U);
    put_u16(tbh_program, 16, 0x2009U); // movs r0, #9 -- table branch target
    put_u16(tbh_program, 18, 0x2701U); // movs r7, #1
    put_u16(tbh_program, 20, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2b00}, tbh_program, tbh_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "TBH control-flow test code maps RX");
    GuestCpuState32 tbh_state{};
    tbh_state.r[0] = 0x2a00U;
    tbh_state.r[1] = 2U;
    const auto tbh_result = interpreter.run(tbh_state, GuestAddress32{0x2b01}, 16);
    check(tbh_result.status == ExecutionStatus::Completed && tbh_state.r[0] == 9U,
        "TBH scales its register index by two and branches using the halfword table offset");

    std::vector<std::byte> it_program(10, std::byte{0});
    put_u16(it_program, 0, 0xbf0cU); // ite eq
    put_u16(it_program, 2, 0x4608U); // mov r0, r1 (then)
    put_u16(it_program, 4, 0x461aU); // mov r2, r3 (else)
    put_u16(it_program, 6, 0x2701U); // movs r7, #1
    put_u16(it_program, 8, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2c00}, it_program, it_program.size(),
            GuestPermission::Read | GuestPermission::Execute),
        "Thumb IT-block test code maps RX");
    GuestCpuState32 it_equal_state{};
    it_equal_state.cpsr |= 1U << 30U;
    it_equal_state.r[1] = 11U;
    it_equal_state.r[2] = 99U;
    it_equal_state.r[3] = 22U;
    auto it_equal_result = interpreter.run(it_equal_state, GuestAddress32{0x2c01}, 16);
    GuestCpuState32 it_not_equal_state{};
    it_not_equal_state.r[0] = 55U;
    it_not_equal_state.r[1] = 11U;
    it_not_equal_state.r[2] = 99U;
    it_not_equal_state.r[3] = 22U;
    auto it_not_equal_result = interpreter.run(it_not_equal_state, GuestAddress32{0x2c01}, 16);
    check(it_equal_result.status == ExecutionStatus::Completed && it_equal_state.r[0] == 11U
            && it_equal_state.r[2] == 99U
            && it_not_equal_result.status == ExecutionStatus::Completed && it_not_equal_state.r[0] == 55U
            && it_not_equal_state.r[2] == 22U,
        "Thumb ITE conditions execute the matching slot and skip the inverse-condition slot");

    std::vector<std::byte> vfp_a32_program(32, std::byte{0});
    put_u32(vfp_a32_program, 0, 0xee000a10U);  // vmov s0, r0
    put_u32(vfp_a32_program, 4, 0xee001a90U);  // vmov s1, r1
    put_u32(vfp_a32_program, 8, 0xee301a20U);  // vadd.f32 s2, s0, s1
    put_u32(vfp_a32_program, 12, 0xee701a60U); // vsub.f32 s3, s0, s1
    put_u32(vfp_a32_program, 16, 0xee202a20U); // vmul.f32 s4, s0, s1
    put_u32(vfp_a32_program, 20, 0xeec02a20U); // vdiv.f32 s5, s0, s1
    put_u32(vfp_a32_program, 24, 0xe3a07001U); // mov r7, #1
    put_u32(vfp_a32_program, 28, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2200}, vfp_a32_program, vfp_a32_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "A32 VFP test code maps RX");
    GuestCpuState32 vfp_a32_state{};
    vfp_a32_state.r[0] = std::bit_cast<std::uint32_t>(40.0F);
    vfp_a32_state.r[1] = std::bit_cast<std::uint32_t>(2.0F);
    const auto vfp_a32_result = interpreter.run(vfp_a32_state, GuestAddress32{0x2200}, 32);
    const auto read_single_bits = [](const GuestCpuState32& state, unsigned index) {
        const auto& q = state.q[index / 4U];
        const auto offset = (index % 4U) * 4U;
        std::uint32_t value = 0;
        for (unsigned byte = 0; byte < 4; ++byte) {
            value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(q[offset + byte])) << (byte * 8U);
        }
        return value;
    };
    check(vfp_a32_result.status == ExecutionStatus::Completed
            && read_single_bits(vfp_a32_state, 2) == std::bit_cast<std::uint32_t>(42.0F)
            && read_single_bits(vfp_a32_state, 3) == std::bit_cast<std::uint32_t>(38.0F)
            && read_single_bits(vfp_a32_state, 4) == std::bit_cast<std::uint32_t>(80.0F)
            && read_single_bits(vfp_a32_state, 5) == std::bit_cast<std::uint32_t>(20.0F),
        "A32 VFP scalar add/subtract/multiply/divide target even and odd S registers correctly");

    std::vector<std::byte> vfp_double_program(20, std::byte{0});
    put_u32(vfp_double_program, 0, 0xee302b01U);  // vadd.f64 d2, d0, d1
    put_u32(vfp_double_program, 4, 0xee303b41U);  // vsub.f64 d3, d0, d1
    put_u32(vfp_double_program, 8, 0xee204b01U);  // vmul.f64 d4, d0, d1
    put_u32(vfp_double_program, 12, 0xee805b01U); // vdiv.f64 d5, d0, d1
    put_u32(vfp_double_program, 16, 0xef000000U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2300}, vfp_double_program, vfp_double_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "A32 VFP double-precision test code maps RX");
    GuestCpuState32 vfp_double_state{};
    const auto forty_double = std::bit_cast<std::uint64_t>(40.0);
    const auto two_double = std::bit_cast<std::uint64_t>(2.0);
    for (unsigned byte = 0; byte < 8; ++byte) {
        vfp_double_state.q[0][byte] = static_cast<std::byte>((forty_double >> (byte * 8U)) & 0xffU);
        vfp_double_state.q[0][8U + byte] = static_cast<std::byte>((two_double >> (byte * 8U)) & 0xffU);
    }
    vfp_double_state.r[7] = 1;
    const auto vfp_double_result = interpreter.run(vfp_double_state, GuestAddress32{0x2300}, 16);
    const auto read_double_bits = [](const GuestCpuState32& state, unsigned index) {
        const auto& q = state.q[index / 2U];
        const auto offset = (index % 2U) * 8U;
        std::uint64_t value = 0;
        for (unsigned byte = 0; byte < 8; ++byte) {
            value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(q[offset + byte])) << (byte * 8U);
        }
        return value;
    };
    check(vfp_double_result.status == ExecutionStatus::Completed
            && read_double_bits(vfp_double_state, 2) == std::bit_cast<std::uint64_t>(42.0)
            && read_double_bits(vfp_double_state, 3) == std::bit_cast<std::uint64_t>(38.0)
            && read_double_bits(vfp_double_state, 4) == std::bit_cast<std::uint64_t>(80.0)
            && read_double_bits(vfp_double_state, 5) == std::bit_cast<std::uint64_t>(20.0),
        "A32 VFP double add/subtract/multiply/divide update consecutive D registers");

    std::vector<std::byte> vfp_t32_program(28, std::byte{0});
    put_u16(vfp_t32_program, 0, 0xee00U);
    put_u16(vfp_t32_program, 2, 0x0a10U); // Thumb-2 vmov s0, r0
    put_u16(vfp_t32_program, 4, 0xee00U);
    put_u16(vfp_t32_program, 6, 0x1a90U); // Thumb-2 vmov s1, r1
    put_u16(vfp_t32_program, 8, 0xee30U);
    put_u16(vfp_t32_program, 10, 0x1a20U); // vadd.f32 s2, s0, s1
    put_u16(vfp_t32_program, 12, 0xee70U);
    put_u16(vfp_t32_program, 14, 0x1a60U); // vsub.f32 s3, s0, s1
    put_u16(vfp_t32_program, 16, 0xee20U);
    put_u16(vfp_t32_program, 18, 0x2a20U); // vmul.f32 s4, s0, s1
    put_u16(vfp_t32_program, 20, 0xeec0U);
    put_u16(vfp_t32_program, 22, 0x2a20U); // vdiv.f32 s5, s0, s1
    put_u16(vfp_t32_program, 24, 0x2701U); // movs r7, #1
    put_u16(vfp_t32_program, 26, 0xdf00U); // svc #0
    check(memory.map_bytes(GuestAddress32{0x2400}, vfp_t32_program, vfp_t32_program.size(),
        GuestPermission::Read | GuestPermission::Execute), "T32 VFP test code maps RX");
    GuestCpuState32 vfp_t32_state{};
    vfp_t32_state.r[0] = std::bit_cast<std::uint32_t>(40.0F);
    vfp_t32_state.r[1] = std::bit_cast<std::uint32_t>(2.0F);
    const auto vfp_t32_result = interpreter.run(vfp_t32_state, GuestAddress32{0x2401}, 32);
    check(vfp_t32_result.status == ExecutionStatus::Completed
            && read_single_bits(vfp_t32_state, 2) == std::bit_cast<std::uint32_t>(42.0F)
            && read_single_bits(vfp_t32_state, 3) == std::bit_cast<std::uint32_t>(38.0F)
            && read_single_bits(vfp_t32_state, 4) == std::bit_cast<std::uint32_t>(80.0F)
            && read_single_bits(vfp_t32_state, 5) == std::bit_cast<std::uint32_t>(20.0F),
        "T32 VFP scalar arithmetic covers add/subtract/multiply/divide and odd S registers");

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
    check(retrobridge::runtime::current_capabilities().guest_bionic_libc_libm_pthread_thunks,
        "the explicitly partial Bionic/libc/libm/pthread thunk subset is reported available");
    check(!retrobridge::runtime::current_capabilities().bionic_and_guest_syscalls,
        "the partial thunk/syscall coverage is not reported as complete Bionic support");
    check(retrobridge::runtime::current_capabilities().synthetic_jni_tables_and_handle_subset,
        "synthetic JNI/JavaVM tables and the tested handle subset are reported available");
    check(!retrobridge::runtime::current_capabilities().synthetic_jni,
        "partial JNI support is not reported as a complete virtual Java runtime");
    check(retrobridge::runtime::current_capabilities().android_asset_manager_thunks,
        "the registered-blob AAsset subset is reported available");
    check(retrobridge::runtime::current_capabilities().headless_native_window_buffers,
        "bounded headless native-window buffers are reported as a narrow capability");
    check(retrobridge::runtime::current_capabilities().synthetic_android_input_queue_looper_subset,
        "the synthetic host-injected AInputQueue/ALooper subset is reported as available");
    check(retrobridge::runtime::current_capabilities().headless_gles_egl_clear_subset,
        "the explicit headless EGL/GLES clear-only subset is reported available");
    check(retrobridge::runtime::current_capabilities().opensl_es_pcm_buffer_queue_subset,
        "bounded synthetic OpenSL ES PCM queue primitives are reported as a partial capability");
    check(retrobridge::runtime::current_capabilities().arm32_instruction_execution,
        "bounded ARM instruction interpretation is reported available");
    check(retrobridge::runtime::current_capabilities().arm32_shared_library_session
            && retrobridge::runtime::current_capabilities().bounded_native_entrypoint_execution,
        "bounded APK native-library sessions and selected entrypoint execution are reported available");
    check(!retrobridge::runtime::current_capabilities().arbitrary_guest_execution,
        "arbitrary guest execution remains unavailable pending a full compatibility/security layer");
}

}  // namespace

int main() {
    test_guest_address_boundary();
    test_guest_memory_permissions_and_bounds();
    test_elf32_loader_maps_symbols_relocations_and_constructors();
    test_native_execution_session_runs_mapped_library_lifecycle();
    test_elf_validation_and_dependencies();
    test_opaque_handles_and_generation();
    test_native_vfs_path_translation();
    test_native_vfs_io_and_descriptors();
    test_guest_heap_allocation_and_coalescing();
    test_arm32_syscall_dispatcher_and_guest_vfs();
    test_guest_bionic_libc_libm_and_pthread_thunks();
    test_guest_android_asset_thunks();
    test_headless_native_window_buffers_and_lifecycle();
    test_synthetic_android_input_queue_and_looper();
    test_headless_egl_gles_clear_subset();
    test_opensl_pcm_buffer_queue_subset();
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
