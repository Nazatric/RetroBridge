#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

namespace retrobridge::runtime {

using GuestHandle32 = std::uint32_t;

enum class ReferenceKind : std::uint8_t {
    Local,
    Global,
    WeakGlobal,
};

/**
 * Maps opaque 32-bit guest handles to opaque 64-bit host reference tokens. Tokens are never
 * encoded into a guest handle or returned as a guest pointer. JNI ownership remains a future layer.
 */
class HandleTable final {
public:
    explicit HandleTable(std::size_t capacity = 4096);

    [[nodiscard]] std::optional<GuestHandle32> insert(std::uint64_t host_reference_token, ReferenceKind kind);
    [[nodiscard]] std::optional<std::uint64_t> resolve(GuestHandle32 guest_handle) const;
    [[nodiscard]] std::optional<ReferenceKind> kind_of(GuestHandle32 guest_handle) const;
    [[nodiscard]] bool release(GuestHandle32 guest_handle);
    void clear(ReferenceKind kind);
    [[nodiscard]] std::size_t live_count() const;

private:
    struct Slot final {
        std::uint16_t generation = 1;
        std::uint64_t host_reference_token = 0;
        ReferenceKind kind = ReferenceKind::Local;
        bool occupied = false;
    };

    [[nodiscard]] static GuestHandle32 encode(std::size_t index, std::uint16_t generation) noexcept;
    [[nodiscard]] const Slot* find(GuestHandle32 guest_handle) const noexcept;
    [[nodiscard]] Slot* find(GuestHandle32 guest_handle) noexcept;
    void retire(Slot& slot) noexcept;

    mutable std::mutex mutex_;
    std::vector<Slot> slots_;
};

}  // namespace retrobridge::runtime
