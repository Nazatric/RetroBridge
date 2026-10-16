#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/elf32_loader.h"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace retrobridge::runtime;

int fail(const std::string& message) {
    std::cerr << "ARM32 fixture execution failed: " << message << '\n';
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace retrobridge::runtime;
    if (argc != 2) return fail("usage: retrobridge_arm32_fixture_runner <guest-elf>");

    std::ifstream input(argv[1], std::ios::binary | std::ios::ate);
    if (!input) return fail("could not open fixture ELF");
    const auto end = input.tellg();
    if (end <= 0) return fail("fixture ELF is empty or unreadable");
    std::vector<std::byte> file(static_cast<std::size_t>(end));
    input.seekg(0);
    input.read(reinterpret_cast<char*>(file.data()), static_cast<std::streamsize>(file.size()));
    if (!input) return fail("could not read fixture ELF");

    GuestMemory memory(32U * 1024U * 1024U);
    GuestTrampolineRegistry trampolines;
    const auto loaded = Elf32Loader::load(file, memory, {}, argv[1], "org.retrobridge.ci.guest");
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&loaded)) return fail(diagnostic->format());
    const auto& image = std::get<Elf32LoadedImage>(loaded);
    const auto relocation_diagnostic = Elf32Loader::relocate(image, memory,
        [&trampolines](std::string_view name) { return trampolines.resolve_symbol(name); });
    if (relocation_diagnostic.has_value()) return fail(relocation_diagnostic->format());

    constexpr std::uint32_t stack_base = 0x7ff00000U;
    constexpr std::uint32_t stack_size = 0x00010000U;
    if (!memory.map_zeroed(GuestAddress32{stack_base}, stack_size,
            GuestPermission::Read | GuestPermission::Write)) {
        return fail("could not map initial guest stack");
    }

    Arm32Interpreter interpreter(memory, trampolines,
        [](GuestCpuState32& state, std::uint32_t immediate, GuestMemory&) {
            if (immediate != 0 || state.r[7] != 1) {
                return GuestHookResult{GuestHookAction::Fault, "fixture issued an unexpected SVC"};
            }
            if (state.r[0] != 42) {
                return GuestHookResult{GuestHookAction::Fault,
                    "fixture exit status was " + std::to_string(state.r[0]) + ", expected 42"};
            }
            return GuestHookResult{GuestHookAction::Stop, "fixture exited with status 42"};
        });
    GuestCpuState32 state{};
    state.r[13] = stack_base + stack_size - 16U;
    const auto result = interpreter.run(state, image.entry_point, 10'000);
    if (result.status != ExecutionStatus::Completed) {
        return fail(result.diagnostic.empty() ? "guest interpreter did not complete" : result.diagnostic);
    }
    if (state.r[0] != 42 || result.guest_instructions < 4) {
        return fail("guest exit result or executed instruction count did not match the fixture contract");
    }

    std::cout << "ARM32 ELF load, relocation, and A32/T32 execution passed: "
              << result.guest_instructions << " instructions, exit status " << state.r[0] << '\n';
    return 0;
}
