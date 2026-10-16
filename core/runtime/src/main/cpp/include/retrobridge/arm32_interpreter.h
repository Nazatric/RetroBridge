#pragma once

#include "retrobridge/guest_memory.h"
#include "retrobridge/translation_engine.h"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace retrobridge::runtime {

enum class GuestHookAction {
    Continue,
    Stop,
    Fault,
};

struct GuestHookResult final {
    GuestHookAction action = GuestHookAction::Continue;
    std::string diagnostic;
};

using GuestSvcHandler = std::function<GuestHookResult(GuestCpuState32&, std::uint32_t, GuestMemory&)>;
using GuestTrampolineFunction = std::function<GuestHookResult(GuestCpuState32&, GuestMemory&)>;

/** Name- and address-indexed host thunks. Guest code only sees 32-bit guest addresses. */
class GuestTrampolineRegistry final {
public:
    [[nodiscard]] bool register_trampoline(
        std::string name,
        GuestAddress32 guest_address,
        GuestTrampolineFunction function,
        std::string* diagnostic = nullptr);
    [[nodiscard]] bool unregister_trampoline(GuestAddress32 guest_address) noexcept;
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;

private:
    struct Entry final {
        std::string name;
        std::uint32_t guest_address;
        GuestTrampolineFunction function;
    };

    std::map<std::uint32_t, Entry> entries_by_address_;
    std::map<std::string, std::uint32_t, std::less<>> addresses_by_name_;

    friend class Arm32Interpreter;
};

/**
 * Bounds-checked A32/T32 interpreter for a deliberately explicit ARMv7 instruction subset.
 * It is a real execution backend, but not a complete ARM CPU or Android compatibility layer.
 */
class Arm32Interpreter final : public TranslationEngine {
public:
    Arm32Interpreter(GuestMemory& memory, GuestTrampolineRegistry& trampolines, GuestSvcHandler svc_handler);

    [[nodiscard]] const char* backend_name() const noexcept override;
    [[nodiscard]] bool available() const noexcept override;
    ExecutionResult run(
        GuestCpuState32& state,
        GuestAddress32 entry,
        std::uint64_t instruction_budget) override;
    void invalidate(GuestRange32 guest_code) noexcept override;

private:
    GuestMemory& memory_;
    GuestTrampolineRegistry& trampolines_;
    GuestSvcHandler svc_handler_;
};

}  // namespace retrobridge::runtime
