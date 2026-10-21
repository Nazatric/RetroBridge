#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** A bounded dlfcn subset for symbols already present in this guest session. */
class GuestDlfcnThunks final {
public:
    using OpenResolver = std::function<std::optional<std::string>(std::string_view)>;
    using SymbolResolver = std::function<std::optional<std::uint32_t>(std::string_view, std::string_view)>;

    GuestDlfcnThunks(
        GuestMemory& memory,
        GuestHeap32& heap,
        GuestTrampolineRegistry& trampolines,
        OpenResolver open_resolver,
        SymbolResolver symbol_resolver);
    ~GuestDlfcnThunks();

    GuestDlfcnThunks(const GuestDlfcnThunks&) = delete;
    GuestDlfcnThunks& operator=(const GuestDlfcnThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;

private:
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::string> read_c_string(std::uint32_t address, std::size_t maximum) const;
    [[nodiscard]] GuestHookResult open(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult lookup(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult close(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult error(GuestCpuState32& state);
    void set_error(std::string message);

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    OpenResolver open_resolver_;
    SymbolResolver symbol_resolver_;
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf9000000U;
    GuestAddress32 error_buffer_{0};
    std::map<std::uint32_t, std::string> handles_;
    std::vector<GuestAddress32> trampoline_allocations_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::string pending_error_;

    static constexpr std::size_t kMaximumPathBytes = 4096U;
    static constexpr std::size_t kMaximumSymbolBytes = 4096U;
    static constexpr std::size_t kMaximumErrorBytes = 4096U;
    static constexpr std::size_t kMaximumHandles = 256U;
    static constexpr std::uint32_t kHandleMagic = 0x5242444cU;
    static constexpr std::uint32_t kRtldLazy = 0x00001U;
    static constexpr std::uint32_t kRtldNow = 0x00002U;
    static constexpr std::uint32_t kRtldNoLoad = 0x00004U;
    static constexpr std::uint32_t kRtldGlobal = 0x00100U;
    static constexpr std::uint32_t kRtldNodelete = 0x01000U;
    static constexpr std::uint32_t kRtldAllowedFlags =
        kRtldLazy | kRtldNow | kRtldNoLoad | kRtldGlobal | kRtldNodelete;
    static constexpr std::uint32_t kRtldNext = 0xffffffffU;
};

}  // namespace retrobridge::runtime
