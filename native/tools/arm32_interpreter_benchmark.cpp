#include "retrobridge/arm32_interpreter.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

using namespace retrobridge::runtime;

constexpr std::uint32_t kCodeAddress = 0x1000U;
constexpr std::uint64_t kDefaultGuestInstructions = 2'000'000;
constexpr std::uint64_t kMinGuestInstructions = 10'000;
constexpr std::uint64_t kMaxGuestInstructions = 50'000'000;
constexpr std::size_t kSamples = 5;

int fail(std::string_view message) {
    std::cerr << "ARM32 interpreter benchmark failed: " << message << '\n';
    return 1;
}

bool parse_instructions(int argc, char** argv, std::uint64_t& instructions) {
    if (argc == 1) {
        instructions = kDefaultGuestInstructions;
        return true;
    }
    if (argc != 2) return false;
    const std::string_view text{argv[1]};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), instructions);
    return error == std::errc{} && end == text.data() + text.size()
        && instructions >= kMinGuestInstructions && instructions <= kMaxGuestInstructions;
}

}  // namespace

int main(int argc, char** argv) {
    std::uint64_t guest_instructions = 0;
    if (!parse_instructions(argc, argv, guest_instructions)) {
        return fail("usage: retrobridge_arm32_benchmark [guest-instructions: 10000..50000000]");
    }

    // A32 ADD r0,r0,#1; B back to ADD. Measures only this synthetic interpreter loop.
    constexpr std::array<std::byte, 8> code{
        std::byte{0x01}, std::byte{0x00}, std::byte{0x80}, std::byte{0xe2},
        std::byte{0xfd}, std::byte{0xff}, std::byte{0xff}, std::byte{0xea},
    };
    GuestMemory memory(64U * 1024U);
    std::string map_diagnostic;
    if (!memory.map_bytes(
            GuestAddress32{kCodeAddress}, code, code.size(), GuestPermission::Read | GuestPermission::Execute,
            &map_diagnostic)) {
        return fail(map_diagnostic);
    }
    GuestTrampolineRegistry trampolines;
    Arm32Interpreter interpreter(memory, trampolines, {});

    GuestCpuState32 warmup_state{};
    const auto warmup = interpreter.run(warmup_state, GuestAddress32{kCodeAddress}, 100'000);
    if (warmup.status != ExecutionStatus::BudgetExhausted || warmup.guest_instructions != 100'000
        || warmup_state.r[0] != 50'000) {
        return fail("warm-up loop failed its instruction-budget/result check");
    }

    std::array<std::uint64_t, kSamples> elapsed_nanoseconds{};
    for (auto& elapsed : elapsed_nanoseconds) {
        GuestCpuState32 state{};
        const auto start = std::chrono::steady_clock::now();
        const auto result = interpreter.run(state, GuestAddress32{kCodeAddress}, guest_instructions);
        const auto finish = std::chrono::steady_clock::now();
        if (result.status != ExecutionStatus::BudgetExhausted || result.guest_instructions != guest_instructions) {
            return fail("benchmark execution did not stop at the requested instruction budget");
        }
        const auto expected_adds = (guest_instructions + 1U) / 2U;
        if (state.r[0] != expected_adds) return fail("synthetic A32 loop produced an incorrect result");
        elapsed = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count());
        if (elapsed == 0) return fail("steady-clock measurement returned zero nanoseconds");
    }

    std::sort(elapsed_nanoseconds.begin(), elapsed_nanoseconds.end());
    const auto median_nanoseconds = elapsed_nanoseconds[kSamples / 2U];
    const double ns_per_instruction = static_cast<double>(median_nanoseconds)
        / static_cast<double>(guest_instructions);
    const double instructions_per_second = static_cast<double>(guest_instructions) * 1'000'000'000.0
        / static_cast<double>(median_nanoseconds);

    std::cout << "{\"benchmark\":\"retrobridge_arm32_interpreter_a32_add_branch\","
              << "\"scope\":\"synthetic host-side A32 ADD/branch loop; not APK or device performance\","
              << "\"guest_instructions_per_sample\":" << guest_instructions << ','
              << "\"samples\":" << kSamples << ','
              << "\"median_elapsed_ns\":" << median_nanoseconds << ','
              << "\"median_ns_per_guest_instruction\":" << ns_per_instruction << ','
              << "\"median_guest_instructions_per_second\":" << instructions_per_second << "}\n";
    return 0;
}
