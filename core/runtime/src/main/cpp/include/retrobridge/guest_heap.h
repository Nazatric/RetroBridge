#pragma once

#include "retrobridge/guest_memory.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace retrobridge::runtime {

/** Coalescing host-managed free-list allocator whose allocations are guest 32-bit addresses. */
class GuestHeap32 final {
public:
    explicit GuestHeap32(GuestMemory& memory) noexcept;
    ~GuestHeap32();

    GuestHeap32(const GuestHeap32&) = delete;
    GuestHeap32& operator=(const GuestHeap32&) = delete;

    [[nodiscard]] bool initialize(
        GuestAddress32 base = GuestAddress32{0x10000000U},
        std::size_t size = 16U * 1024U * 1024U,
        std::string* diagnostic = nullptr);
    void shutdown() noexcept;

    [[nodiscard]] std::optional<GuestAddress32> malloc(std::size_t size) noexcept;
    [[nodiscard]] std::optional<GuestAddress32> calloc(std::size_t count, std::size_t size) noexcept;
    [[nodiscard]] std::optional<GuestAddress32> realloc(GuestAddress32 address, std::size_t size) noexcept;
    [[nodiscard]] bool free(GuestAddress32 address) noexcept;
    [[nodiscard]] std::optional<GuestAddress32> memalign(std::size_t alignment, std::size_t size) noexcept;
    [[nodiscard]] int posix_memalign(GuestAddress32* output, std::size_t alignment, std::size_t size) noexcept;
    [[nodiscard]] std::optional<std::size_t> allocation_size(GuestAddress32 address) const noexcept;

    [[nodiscard]] bool initialized() const noexcept;
    [[nodiscard]] GuestAddress32 base() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept;

private:
    [[nodiscard]] std::optional<GuestAddress32> allocate_locked(
        std::size_t size,
        std::size_t alignment,
        bool clear);
    [[nodiscard]] bool free_locked(GuestAddress32 address);
    [[nodiscard]] bool clear_range(GuestAddress32 address, std::size_t size) noexcept;
    [[nodiscard]] static bool valid_alignment(std::size_t alignment) noexcept;

    GuestMemory& memory_;
    mutable std::mutex mutex_;
    GuestAddress32 base_{0};
    std::size_t size_ = 0;
    std::map<std::size_t, std::size_t> free_blocks_;
    std::map<std::uint32_t, std::size_t> allocations_;
    bool initialized_ = false;
};

}  // namespace retrobridge::runtime
