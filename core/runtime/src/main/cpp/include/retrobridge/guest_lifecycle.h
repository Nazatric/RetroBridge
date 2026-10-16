#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/elf32_loader.h"

namespace retrobridge::runtime {

/** Calls DT_INIT/DT_INIT_ARRAY and DT_FINI_ARRAY/DT_FINI through a temporary guest return thunk. */
class GuestLifecycleExecutor final {
public:
    GuestLifecycleExecutor(
        GuestMemory& memory,
        TranslationEngine& engine,
        GuestTrampolineRegistry& trampolines) noexcept;

    [[nodiscard]] ExecutionResult run_constructors(
        const Elf32LoadedImage& image,
        GuestCpuState32& state,
        std::uint64_t instruction_budget);
    [[nodiscard]] ExecutionResult run_destructors(
        const Elf32LoadedImage& image,
        GuestCpuState32& state,
        std::uint64_t instruction_budget);

private:
    [[nodiscard]] ExecutionResult run_functions(
        std::variant<std::vector<GuestAddress32>, ElfDiagnostic> functions,
        GuestCpuState32& state,
        std::uint64_t instruction_budget);

    GuestMemory& memory_;
    TranslationEngine& engine_;
    GuestTrampolineRegistry& trampolines_;
};

}  // namespace retrobridge::runtime
