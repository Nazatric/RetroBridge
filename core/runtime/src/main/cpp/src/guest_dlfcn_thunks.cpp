#include "retrobridge/guest_dlfcn_thunks.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

namespace retrobridge::runtime {

GuestDlfcnThunks::GuestDlfcnThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines,
    OpenResolver open_resolver,
    SymbolResolver symbol_resolver)
    : memory_(memory),
      heap_(heap),
      trampolines_(trampolines),
      open_resolver_(std::move(open_resolver)),
      symbol_resolver_(std::move(symbol_resolver)) {}

GuestDlfcnThunks::~GuestDlfcnThunks() {
    shutdown();
}

bool GuestDlfcnThunks::install(std::string* diagnostic) {
    const auto fail = [&](std::string message) {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        shutdown();
        return false;
    };
    if (diagnostic != nullptr) diagnostic->clear();
    if (installed_) return true;
    if (!heap_.initialized()) return fail("dlfcn thunks require an initialized guest heap");
    if (!open_resolver_ || !symbol_resolver_) return fail("dlfcn thunks require guest-library resolver callbacks");

    try {
        trampoline_allocations_.reserve(4);
        const auto buffer = heap_.malloc(kMaximumErrorBytes);
        if (!buffer.has_value()) return fail("guest heap cannot reserve the dlfcn error buffer");
        error_buffer_ = *buffer;

        const auto bind = [this](std::string name, Callback callback) {
            return add_thunk(std::move(name), std::move(callback)).has_value();
        };
        if (!bind("dlopen", [this](GuestCpuState32& state, GuestMemory& memory) {
                if (&memory != &memory_) {
                    return GuestHookResult{GuestHookAction::Fault, "dlfcn thunk received unrelated guest memory"};
                }
                try {
                    return open(state);
                } catch (...) {
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
            })
            || !bind("dlsym", [this](GuestCpuState32& state, GuestMemory& memory) {
                if (&memory != &memory_) {
                    return GuestHookResult{GuestHookAction::Fault, "dlfcn thunk received unrelated guest memory"};
                }
                try {
                    return lookup(state);
                } catch (...) {
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
            })
            || !bind("dlclose", [this](GuestCpuState32& state, GuestMemory& memory) {
                if (&memory != &memory_) {
                    return GuestHookResult{GuestHookAction::Fault, "dlfcn thunk received unrelated guest memory"};
                }
                try {
                    return close(state);
                } catch (...) {
                    state.r[0] = 0xffffffffU;
                    return GuestHookResult{};
                }
            })
            || !bind("dlerror", [this](GuestCpuState32& state, GuestMemory& memory) {
                if (&memory != &memory_) {
                    return GuestHookResult{GuestHookAction::Fault, "dlfcn thunk received unrelated guest memory"};
                }
                try {
                    return error(state);
                } catch (...) {
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
            })) {
            return fail("unable to register the bounded dlfcn thunk subset");
        }
        installed_ = true;
        return true;
    } catch (...) {
        return fail("host resource failure while installing dlfcn thunks");
    }
}

void GuestDlfcnThunks::shutdown() noexcept {
    for (const auto address : trampoline_allocations_) {
        (void)trampolines_.unregister_trampoline(address);
    }
    trampoline_allocations_.clear();
    symbols_.clear();
    for (const auto& [handle, library] : handles_) {
        (void)library;
        (void)heap_.free(GuestAddress32{handle});
    }
    handles_.clear();
    if (error_buffer_.value() != 0) (void)heap_.free(error_buffer_);
    error_buffer_ = GuestAddress32{0};
    pending_error_.clear();
    installed_ = false;
}

std::optional<std::uint32_t> GuestDlfcnThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    return found == symbols_.end() ? std::nullopt : std::optional<std::uint32_t>{found->second};
}

std::optional<std::uint32_t> GuestDlfcnThunks::add_thunk(std::string name, Callback callback) {
    while (next_trampoline_address_ < 0xfa000000U
        && memory_.is_mapped(GuestAddress32{next_trampoline_address_}, 4)) next_trampoline_address_ += 4U;
    if (next_trampoline_address_ >= 0xfa000000U || symbols_.contains(name)) return std::nullopt;

    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    const auto symbol_name = name;
    if (!trampolines_.register_trampoline(std::move(name), GuestAddress32{address}, std::move(callback))) return std::nullopt;
    try {
        const auto [entry, inserted] = symbols_.emplace(symbol_name, address);
        (void)entry;
        if (!inserted) {
            (void)trampolines_.unregister_trampoline(GuestAddress32{address});
            return std::nullopt;
        }
        trampoline_allocations_.push_back(GuestAddress32{address});
    } catch (...) {
        symbols_.erase(symbol_name);
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<std::string> GuestDlfcnThunks::read_c_string(std::uint32_t address, std::size_t maximum) const {
    std::string result;
    result.reserve(std::min<std::size_t>(maximum, 256U));
    for (std::size_t index = 0; index < maximum; ++index) {
        const auto current = static_cast<std::uint64_t>(address) + index;
        if (current > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        const auto value = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(current)});
        if (!value.has_value()) return std::nullopt;
        if (*value == 0) return result;
        result.push_back(static_cast<char>(*value));
    }
    return std::nullopt;
}

GuestHookResult GuestDlfcnThunks::open(GuestCpuState32& state) {
    const auto flags = state.r[1];
    const auto binding_mode = flags & (kRtldLazy | kRtldNow);
    if ((flags & ~kRtldAllowedFlags) != 0 || binding_mode == (kRtldLazy | kRtldNow)) {
        set_error("dlopen received unsupported flags");
        state.r[0] = 0;
        return {};
    }

    std::string requested_name;
    if (state.r[0] != 0) {
        const auto name = read_c_string(state.r[0], kMaximumPathBytes);
        if (!name.has_value() || name->empty()) {
            set_error("dlopen received an invalid or empty library name");
            state.r[0] = 0;
            return {};
        }
        requested_name = *name;
    }

    if (handles_.size() >= kMaximumHandles) {
        set_error("dlopen guest handle limit reached");
        state.r[0] = 0;
        return {};
    }
    const auto canonical_name = open_resolver_(requested_name);
    if (!canonical_name.has_value()) {
        set_error(requested_name.empty()
                ? "dlopen(NULL) has no main guest executable in this native-only session"
                : "dlopen could not find an already-loaded guest library or supported virtual library: " + requested_name);
        state.r[0] = 0;
        return {};
    }

    const auto handle = heap_.malloc(sizeof(std::uint32_t));
    if (!handle.has_value() || !memory_.write_u32(handle.value_or(GuestAddress32{0}), kHandleMagic)) {
        if (handle.has_value()) (void)heap_.free(*handle);
        set_error("dlopen could not allocate an opaque guest handle");
        state.r[0] = 0;
        return {};
    }
    try {
        const auto [entry, inserted] = handles_.emplace(handle->value(), *canonical_name);
        (void)entry;
        if (!inserted) {
            (void)heap_.free(*handle);
            set_error("dlopen generated a duplicate guest handle");
            state.r[0] = 0;
            return {};
        }
    } catch (...) {
        (void)heap_.free(*handle);
        throw;
    }
    state.r[0] = handle->value();
    return {};
}

GuestHookResult GuestDlfcnThunks::lookup(GuestCpuState32& state) {
    const auto symbol = read_c_string(state.r[1], kMaximumSymbolBytes);
    if (!symbol.has_value() || symbol->empty()) {
        set_error("dlsym received an invalid or empty symbol name");
        state.r[0] = 0;
        return {};
    }

    std::string_view library;
    if (state.r[0] == kRtldNext) {
        set_error("dlsym with RTLD_NEXT is unsupported without guest caller-scope tracking");
        state.r[0] = 0;
        return {};
    }
    if (state.r[0] != 0) {
        const auto found = handles_.find(state.r[0]);
        const GuestAddress32 handle{state.r[0]};
        const auto cookie = memory_.read_u32(handle);
        if (found == handles_.end() || !heap_.allocation_size(handle).has_value()
            || !cookie.has_value() || *cookie != kHandleMagic) {
            set_error("dlsym received an invalid or closed guest library handle");
            state.r[0] = 0;
            return {};
        }
        library = found->second;
    }

    const auto address = symbol_resolver_(library, *symbol);
    if (!address.has_value()) {
        set_error("dlsym could not resolve guest symbol " + *symbol
            + (library.empty() ? " in the global guest scope" : " from " + std::string(library)));
        state.r[0] = 0;
        return {};
    }
    state.r[0] = *address;
    return {};
}

GuestHookResult GuestDlfcnThunks::close(GuestCpuState32& state) {
    const auto found = handles_.find(state.r[0]);
    const GuestAddress32 handle{state.r[0]};
    const auto cookie = memory_.read_u32(handle);
    if (state.r[0] == 0 || state.r[0] == kRtldNext || found == handles_.end()
        || !heap_.allocation_size(handle).has_value() || !cookie.has_value() || *cookie != kHandleMagic) {
        set_error("dlclose received an invalid or already-closed guest library handle");
        state.r[0] = 0xffffffffU;
        return {};
    }
    if (!heap_.free(GuestAddress32{state.r[0]})) {
        set_error("dlclose could not release its guest handle");
        state.r[0] = 0xffffffffU;
        return {};
    }
    handles_.erase(found);
    // Images remain mapped until session teardown; this close releases only the lookup handle.
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestDlfcnThunks::error(GuestCpuState32& state) {
    if (pending_error_.empty()) {
        state.r[0] = 0;
        return {};
    }
    const auto length = std::min(pending_error_.size(), kMaximumErrorBytes - 1U);
    std::vector<std::byte> encoded(length + 1U, std::byte{0});
    for (std::size_t index = 0; index < length; ++index) {
        encoded[index] = static_cast<std::byte>(static_cast<unsigned char>(pending_error_[index]));
    }
    if (error_buffer_.value() == 0 || !memory_.write(error_buffer_, encoded)) {
        state.r[0] = 0;
        pending_error_.clear();
        return {};
    }
    state.r[0] = error_buffer_.value();
    pending_error_.clear();
    return {};
}

void GuestDlfcnThunks::set_error(std::string message) {
    if (message.size() >= kMaximumErrorBytes) message.resize(kMaximumErrorBytes - 1U);
    pending_error_ = std::move(message);
}

}  // namespace retrobridge::runtime
