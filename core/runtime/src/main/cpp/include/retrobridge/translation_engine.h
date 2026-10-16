#pragma once

#include "retrobridge/guest_address.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace retrobridge::runtime {

/** A32 architectural state. Q0-Q15 carry the VFP/NEON register bank. */
struct GuestCpuState32 final {
    std::array<std::uint32_t, 16> r{};  // R0-R15 (R15 is guest PC)
    std::uint32_t cpsr = 0;
    std::uint32_t fpscr = 0;
    std::array<std::array<std::byte, 16>, 16> q{};
    std::uint32_t thread_local_storage = 0;
    std::uint8_t thumb_it_state = 0;
};

enum class ExecutionStatus {
    Completed,
    BudgetExhausted,
    GuestFault,
    BackendUnavailable,
};

struct ExecutionResult final {
    ExecutionStatus status = ExecutionStatus::BackendUnavailable;
    std::uint64_t guest_instructions = 0;
    std::string diagnostic;
};

/**
 * Guest-code execution boundary. Implementations receive guest addresses, not host pointers.
 * Guest memory access and host-call thunks must remain explicitly marshalled. Despite the
 * historical class name, implementations may interpret or translate instructions.
 */
class TranslationEngine {
public:
    virtual ~TranslationEngine() = default;

    [[nodiscard]] virtual const char* backend_name() const noexcept = 0;
    [[nodiscard]] virtual bool available() const noexcept = 0;
    virtual ExecutionResult run(
        GuestCpuState32& state,
        GuestAddress32 entry,
        std::uint64_t instruction_budget) = 0;
    virtual void invalidate(GuestRange32 guest_code) noexcept = 0;
};

/** Safe placeholder for configurations where no execution backend is integrated. */
class UnavailableTranslationEngine final : public TranslationEngine {
public:
    [[nodiscard]] const char* backend_name() const noexcept override;
    [[nodiscard]] bool available() const noexcept override;
    ExecutionResult run(
        GuestCpuState32& state,
        GuestAddress32 entry,
        std::uint64_t instruction_budget) override;
    void invalidate(GuestRange32 guest_code) noexcept override;
};

}  // namespace retrobridge::runtime
