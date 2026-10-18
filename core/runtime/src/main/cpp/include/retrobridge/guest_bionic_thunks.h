#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "native_vfs.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/** Explicitly partial ARM32 libc/libm/Bionic/pthread thunk table backed by guest memory. */
class GuestBionicThunks final {
public:
    GuestBionicThunks(
        GuestMemory& memory,
        GuestHeap32& heap,
        GuestTrampolineRegistry& trampolines,
        NativeVfs* vfs = nullptr);
    ~GuestBionicThunks();

    GuestBionicThunks(const GuestBionicThunks&) = delete;
    GuestBionicThunks& operator=(const GuestBionicThunks&) = delete;

    [[nodiscard]] bool install(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> resolve_guest_symbol(std::string_view name) const noexcept;
    [[nodiscard]] std::optional<GuestAddress32> resolve_data_symbol(std::string_view name) const noexcept;
    [[nodiscard]] GuestAddress32 errno_cell() const noexcept { return errno_cell_; }
    [[nodiscard]] GuestAddress32 stack_guard_cell() const noexcept { return stack_guard_cell_; }

private:
    using Callback = GuestTrampolineFunction;
    struct GuestMutex final {
        bool locked = false;
    };

    [[nodiscard]] std::optional<std::uint32_t> add_thunk(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::string> read_c_string(std::uint32_t address, std::size_t maximum = 1U << 20U) const;
    [[nodiscard]] std::optional<std::uint32_t> stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept;
    [[nodiscard]] bool read_bytes(std::uint32_t address, std::size_t size, std::vector<std::byte>& output) const;
    [[nodiscard]] bool write_bytes(std::uint32_t address, std::span<const std::byte> input) const noexcept;
    void set_errno(int value) noexcept;
    [[nodiscard]] std::shared_ptr<GuestMutex> find_or_create_mutex(std::uint32_t address, bool create);
    [[nodiscard]] GuestHookResult copy_memory(GuestCpuState32& state, bool move);
    [[nodiscard]] GuestHookResult set_memory(GuestCpuState32& state, bool aeabi_order, bool clear);
    [[nodiscard]] GuestHookResult compare_memory(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult string_length(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult string_compare(GuestCpuState32& state, bool bounded);
    [[nodiscard]] GuestHookResult string_copy(GuestCpuState32& state, bool bounded);
    [[nodiscard]] GuestHookResult string_duplicate(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_open(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_close(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_read(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_write(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_seek(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_seek64(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_stat64(GuestCpuState32& state, bool no_follow);
    [[nodiscard]] GuestHookResult file_fstat64(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_statat64(GuestCpuState32& state);
    [[nodiscard]] GuestHookResult file_getdents64(GuestCpuState32& state);
    [[nodiscard]] static std::uint64_t read_u64(std::uint32_t low, std::uint32_t high) noexcept;
    static void write_double_result(GuestCpuState32& state, double value) noexcept;

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    NativeVfs* vfs_ = nullptr;
    bool installed_ = false;
    std::uint32_t next_trampoline_address_ = 0xf2000000U;
    GuestAddress32 errno_cell_{0};
    GuestAddress32 stack_guard_cell_{0};
    std::vector<GuestAddress32> data_allocations_;
    std::vector<GuestAddress32> trampoline_allocations_;
    std::map<std::string, std::uint32_t, std::less<>> symbols_;
    std::map<std::string, GuestAddress32, std::less<>> data_symbols_;
    mutable std::mutex pthread_table_mutex_;
    std::map<std::uint32_t, std::shared_ptr<GuestMutex>> pthread_mutexes_;
    std::map<std::uint32_t, std::uint32_t> pthread_values_;
    std::map<std::uint32_t, bool> pthread_keys_;
    std::uint32_t next_pthread_key_ = 1;
    static constexpr std::uint32_t kSyntheticThreadId = 10001U;
};

}  // namespace retrobridge::runtime
