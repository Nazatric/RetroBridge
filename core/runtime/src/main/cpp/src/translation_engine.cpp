#include "retrobridge/translation_engine.h"

namespace retrobridge::runtime {

const char* UnavailableTranslationEngine::backend_name() const noexcept {
    return "unavailable (Dynarmic backend not integrated)";
}

bool UnavailableTranslationEngine::available() const noexcept {
    return false;
}

ExecutionResult UnavailableTranslationEngine::run(
    GuestCpuState32& state,
    GuestAddress32 entry,
    std::uint64_t instruction_budget) {
    (void)state;
    (void)entry;
    (void)instruction_budget;
    return {
        .status = ExecutionStatus::BackendUnavailable,
        .guest_instructions = 0,
        .diagnostic = "Guest execution is disabled: no reviewed ARM32 translation backend is integrated.",
    };
}

void UnavailableTranslationEngine::invalidate(GuestRange32 guest_code) noexcept {
    (void)guest_code;
}

}  // namespace retrobridge::runtime
