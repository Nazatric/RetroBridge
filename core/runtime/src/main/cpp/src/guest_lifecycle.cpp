#include "retrobridge/guest_lifecycle.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace retrobridge::runtime {
namespace {

constexpr const char* kReturnThunkDiagnostic = "__retrobridge_lifecycle_return__";

struct RegisteredReturnThunk final {
    GuestTrampolineRegistry& registry;
    GuestAddress32 address;

    ~RegisteredReturnThunk() {
        (void)registry.unregister_trampoline(address);
    }
};

}  // namespace

GuestLifecycleExecutor::GuestLifecycleExecutor(
    GuestMemory& memory,
    TranslationEngine& engine,
    GuestTrampolineRegistry& trampolines) noexcept
    : memory_(memory), engine_(engine), trampolines_(trampolines) {}

ExecutionResult GuestLifecycleExecutor::run_constructors(
    const Elf32LoadedImage& image,
    GuestCpuState32& state,
    std::uint64_t instruction_budget) {
    return run_functions(image.constructor_addresses(memory_), state, instruction_budget);
}

ExecutionResult GuestLifecycleExecutor::run_destructors(
    const Elf32LoadedImage& image,
    GuestCpuState32& state,
    std::uint64_t instruction_budget) {
    return run_functions(image.destructor_addresses(memory_), state, instruction_budget);
}

ExecutionResult GuestLifecycleExecutor::run_functions(
    std::variant<std::vector<GuestAddress32>, ElfDiagnostic> functions_result,
    GuestCpuState32& state,
    std::uint64_t instruction_budget) {
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&functions_result)) {
        return {ExecutionStatus::GuestFault, 0, diagnostic->format()};
    }
    const auto& functions = std::get<std::vector<GuestAddress32>>(functions_result);
    if (functions.empty()) return {ExecutionStatus::Completed, 0, "no guest lifecycle functions"};

    std::optional<GuestAddress32> return_address;
    for (std::uint32_t index = 0; index < 256; ++index) {
        const auto normalized = 0xfffffff0U - index * 16U;
        const GuestAddress32 candidate{normalized | 1U};
        if (memory_.is_mapped(GuestAddress32{normalized}, 1)) continue;
        const auto name = "__retrobridge.lifecycle.return." + std::to_string(index);
        if (trampolines_.register_trampoline(name, candidate,
                [](GuestCpuState32&, GuestMemory&) {
                    return GuestHookResult{GuestHookAction::Stop, kReturnThunkDiagnostic};
                })) {
            return_address = candidate;
            break;
        }
    }
    if (!return_address.has_value()) {
        return {ExecutionStatus::BackendUnavailable, 0,
            "no free guest address is available for the lifecycle return thunk"};
    }
    const RegisteredReturnThunk return_thunk{trampolines_, *return_address};

    std::uint64_t executed = 0;
    for (const auto function : functions) {
        if (executed >= instruction_budget) {
            return {ExecutionStatus::BudgetExhausted, executed, "guest lifecycle instruction budget exhausted"};
        }
        state.r[14] = return_address->value();
        const auto result = engine_.run(state, function, instruction_budget - executed);
        executed += result.guest_instructions;
        if (result.status != ExecutionStatus::Completed) {
            return {result.status, executed, result.diagnostic};
        }
        if (result.diagnostic != kReturnThunkDiagnostic) {
            return {ExecutionStatus::GuestFault, executed,
                result.diagnostic.empty()
                    ? "guest lifecycle function stopped before returning"
                    : "guest lifecycle function stopped before returning: " + result.diagnostic};
        }
    }
    return {ExecutionStatus::Completed, executed, "guest lifecycle functions returned normally"};
}

}  // namespace retrobridge::runtime
