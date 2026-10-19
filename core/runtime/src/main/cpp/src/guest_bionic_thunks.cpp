#include "retrobridge/guest_bionic_thunks.h"
#include "retrobridge/arm32_stat_layout.h"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <sys/stat.h>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::size_t kMaxMemoryOperation = 16U * 1024U * 1024U;
constexpr std::size_t kMaxStringOperation = 1U << 20U;
constexpr std::uint32_t kPthreadInvalid = 22U;
constexpr std::uint32_t kPthreadBusy = 16U;
constexpr std::uint32_t kPthreadDeadlock = 35U;
constexpr std::uint32_t kPthreadAgain = 11U;
constexpr int kAtFdcwd = -100;
constexpr int kAtRemoveDir = 0x200;

[[nodiscard]] std::uint32_t as_u32(std::int32_t value) noexcept {
    return std::bit_cast<std::uint32_t>(value);
}

[[nodiscard]] std::int32_t as_i32(std::uint32_t value) noexcept {
    return std::bit_cast<std::int32_t>(value);
}

[[nodiscard]] int compare_bytes(std::string_view left, std::string_view right) noexcept {
    const auto count = std::min(left.size(), right.size());
    for (std::size_t index = 0; index < count; ++index) {
        const auto a = static_cast<unsigned char>(left[index]);
        const auto b = static_cast<unsigned char>(right[index]);
        if (a != b) return static_cast<int>(a) - static_cast<int>(b);
    }
    if (left.size() == right.size()) return 0;
    return left.size() < right.size() ? -static_cast<int>(static_cast<unsigned char>(right[count]))
                                      : static_cast<int>(static_cast<unsigned char>(left[count]));
}

}  // namespace

GuestBionicThunks::GuestBionicThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines,
    NativeVfs* vfs)
    : memory_(memory), heap_(heap), trampolines_(trampolines), vfs_(vfs) {}

GuestBionicThunks::~GuestBionicThunks() {
    shutdown();
}

bool GuestBionicThunks::install(std::string* diagnostic) {
    const auto fail = [&](const std::string& message) {
        if (diagnostic != nullptr) *diagnostic = message;
        shutdown();
        return false;
    };
    if (installed_) return true;
    if (!heap_.initialized()) return fail("Bionic thunks require an initialized guest heap");
    try {
        data_allocations_.reserve(2);
        const auto errno_address = heap_.malloc(sizeof(std::uint32_t));
        const auto guard_address = heap_.malloc(sizeof(std::uint32_t));
        if (!errno_address.has_value() || !guard_address.has_value()) {
            if (errno_address.has_value()) (void)heap_.free(*errno_address);
            if (guard_address.has_value()) (void)heap_.free(*guard_address);
            return fail("guest heap cannot reserve the Bionic errno and stack guard cells");
        }
        errno_cell_ = *errno_address;
        stack_guard_cell_ = *guard_address;
        data_allocations_.push_back(errno_cell_);
        data_allocations_.push_back(stack_guard_cell_);
        std::random_device random;
        auto stack_guard = random() & 0xffffff00U;
        if (stack_guard == 0) stack_guard = 0x6d3a2f00U;
        if (!memory_.write_u32(errno_cell_, 0) || !memory_.write_u32(stack_guard_cell_, stack_guard)) {
            return fail("unable to initialize Bionic guest data cells");
        }
        data_symbols_.emplace("__stack_chk_guard", stack_guard_cell_);
        data_symbols_.emplace("errno", errno_cell_);

        const auto bind = [&](std::string name, Callback callback) {
            const auto address = add_thunk(name, std::move(callback));
            return address.has_value();
        };
        const auto zero_result = [](GuestCpuState32& state) {
            state.r[0] = 0;
            return GuestHookResult{};
        };
        const auto fault_thunk = [](GuestCpuState32&, GuestMemory&) {
            return GuestHookResult{GuestHookAction::Fault, "guest called a terminating Bionic thunk"};
        };

        if (!bind("malloc", [this](GuestCpuState32& state, GuestMemory&) {
                const auto address = heap_.malloc(state.r[0]);
                if (!address.has_value()) set_errno(ENOMEM);
                state.r[0] = address.has_value() ? address->value() : 0U;
                return GuestHookResult{};
            })
            || !bind("calloc", [this](GuestCpuState32& state, GuestMemory&) {
                const auto address = heap_.calloc(state.r[0], state.r[1]);
                if (!address.has_value()) set_errno(ENOMEM);
                state.r[0] = address.has_value() ? address->value() : 0U;
                return GuestHookResult{};
            })
            || !bind("realloc", [this](GuestCpuState32& state, GuestMemory&) {
                const auto address = heap_.realloc(GuestAddress32{state.r[0]}, state.r[1]);
                if (!address.has_value() && state.r[1] != 0) set_errno(ENOMEM);
                state.r[0] = address.has_value() ? address->value() : 0U;
                return GuestHookResult{};
            })
            || !bind("free", [this, zero_result](GuestCpuState32& state, GuestMemory&) {
                if (state.r[0] != 0 && !heap_.free(GuestAddress32{state.r[0]})) set_errno(EINVAL);
                return zero_result(state);
            })
            || !bind("memalign", [this](GuestCpuState32& state, GuestMemory&) {
                const auto address = heap_.memalign(state.r[0], state.r[1]);
                if (!address.has_value()) set_errno(EINVAL);
                state.r[0] = address.has_value() ? address->value() : 0U;
                return GuestHookResult{};
            })
            || !bind("posix_memalign", [this](GuestCpuState32& state, GuestMemory&) {
                const auto output = GuestAddress32{state.r[0]};
                GuestAddress32 address{0};
                const auto status = heap_.posix_memalign(&address, state.r[1], state.r[2]);
                if (status == 0 && !memory_.write_u32(output, address.value())) {
                    (void)heap_.free(address);
                    state.r[0] = as_u32(EFAULT);
                } else {
                    state.r[0] = as_u32(status);
                }
                return GuestHookResult{};
            })
            || !bind("aligned_alloc", [this](GuestCpuState32& state, GuestMemory&) {
                if (state.r[0] == 0 || state.r[1] % state.r[0] != 0) {
                    set_errno(EINVAL);
                    state.r[0] = 0;
                } else {
                    const auto address = heap_.memalign(state.r[0], state.r[1]);
                    if (!address.has_value()) set_errno(ENOMEM);
                    state.r[0] = address.has_value() ? address->value() : 0U;
                }
                return GuestHookResult{};
            })
            || !bind("memcpy", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, false); })
            || !bind("memmove", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, true); })
            || !bind("__aeabi_memcpy", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, false); })
            || !bind("__aeabi_memcpy4", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, false); })
            || !bind("__aeabi_memcpy8", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, false); })
            || !bind("__aeabi_memmove", [this](GuestCpuState32& state, GuestMemory&) { return copy_memory(state, true); })
            || !bind("memset", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, false, false); })
            || !bind("__aeabi_memset", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, false); })
            || !bind("__aeabi_memset4", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, false); })
            || !bind("__aeabi_memset8", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, false); })
            || !bind("__aeabi_memclr", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, true); })
            || !bind("__aeabi_memclr4", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, true); })
            || !bind("__aeabi_memclr8", [this](GuestCpuState32& state, GuestMemory&) { return set_memory(state, true, true); })
            || !bind("memcmp", [this](GuestCpuState32& state, GuestMemory&) { return compare_memory(state); })
            || !bind("memchr", [this](GuestCpuState32& state, GuestMemory&) { return find_memory_character(state, false); })
            || !bind("memrchr", [this](GuestCpuState32& state, GuestMemory&) { return find_memory_character(state, true); })
            || !bind("strlen", [this](GuestCpuState32& state, GuestMemory&) { return string_length(state); })
            || !bind("strnlen", [this](GuestCpuState32& state, GuestMemory&) { return bounded_string_length(state); })
            || !bind("strchr", [this](GuestCpuState32& state, GuestMemory&) { return find_string_character(state, false); })
            || !bind("strrchr", [this](GuestCpuState32& state, GuestMemory&) { return find_string_character(state, true); })
            || !bind("strstr", [this](GuestCpuState32& state, GuestMemory&) { return find_string_substring(state, false); })
            || !bind("strpbrk", [this](GuestCpuState32& state, GuestMemory&) { return find_string_substring(state, true); })
            || !bind("strspn", [this](GuestCpuState32& state, GuestMemory&) { return string_span(state, false); })
            || !bind("strcspn", [this](GuestCpuState32& state, GuestMemory&) { return string_span(state, true); })
            || !bind("strcmp", [this](GuestCpuState32& state, GuestMemory&) { return string_compare(state, false); })
            || !bind("strncmp", [this](GuestCpuState32& state, GuestMemory&) { return string_compare(state, true); })
            || !bind("strcpy", [this](GuestCpuState32& state, GuestMemory&) { return string_copy(state, false); })
            || !bind("strncpy", [this](GuestCpuState32& state, GuestMemory&) { return string_copy(state, true); })
            || !bind("strdup", [this](GuestCpuState32& state, GuestMemory&) { return string_duplicate(state); })
            || !bind("__errno", [this](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = errno_cell_.value();
                return GuestHookResult{};
            })
            || !bind("__errno_location", [this](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = errno_cell_.value();
                return GuestHookResult{};
            })
            || !bind("open", [this](GuestCpuState32& state, GuestMemory&) { return file_open(state); })
            || !bind("close", [this](GuestCpuState32& state, GuestMemory&) { return file_close(state); })
            || !bind("read", [this](GuestCpuState32& state, GuestMemory&) { return file_read(state); })
            || !bind("write", [this](GuestCpuState32& state, GuestMemory&) { return file_write(state); })
            || !bind("pread", [this](GuestCpuState32& state, GuestMemory&) { return file_pread(state); })
            || !bind("pwrite", [this](GuestCpuState32& state, GuestMemory&) { return file_pwrite(state); })
            || !bind("lseek", [this](GuestCpuState32& state, GuestMemory&) { return file_seek(state); })
            || !bind("lseek64", [this](GuestCpuState32& state, GuestMemory&) { return file_seek64(state); })
            || !bind("stat64", [this](GuestCpuState32& state, GuestMemory&) { return file_stat64(state, false); })
            || !bind("lstat64", [this](GuestCpuState32& state, GuestMemory&) { return file_stat64(state, true); })
            || !bind("fstat64", [this](GuestCpuState32& state, GuestMemory&) { return file_fstat64(state); })
            || !bind("mkdir", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[0]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->mkdirat(kAtFdcwd, *path, state.r[1]);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("unlink", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[0]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->unlinkat(kAtFdcwd, *path, 0);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("rmdir", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[0]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->unlinkat(kAtFdcwd, *path, kAtRemoveDir);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("access", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[0]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->access(*path, as_i32(state.r[1]));
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("rename", [this](GuestCpuState32& state, GuestMemory&) {
                const auto old_path = read_c_string(state.r[0]);
                const auto new_path = read_c_string(state.r[1]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!old_path.has_value() || !new_path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->renameat(kAtFdcwd, *old_path, kAtFdcwd, *new_path);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("openat", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[1]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->openat(as_i32(state.r[0]), *path, as_i32(state.r[2]), state.r[3]);
                    if (result < 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("mkdirat", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[1]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->mkdirat(as_i32(state.r[0]), *path, state.r[2]);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("unlinkat", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[1]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->unlinkat(as_i32(state.r[0]), *path, as_i32(state.r[2]));
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("renameat", [this](GuestCpuState32& state, GuestMemory&) {
                const auto old_path = read_c_string(state.r[1]);
                const auto new_path = read_c_string(state.r[3]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!old_path.has_value() || !new_path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->renameat(
                        as_i32(state.r[0]), *old_path, as_i32(state.r[2]), *new_path);
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("faccessat", [this](GuestCpuState32& state, GuestMemory&) {
                const auto path = read_c_string(state.r[1]);
                if (vfs_ == nullptr) {
                    set_errno(ENOSYS);
                    state.r[0] = as_u32(-1);
                } else if (!path.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else {
                    const auto result = vfs_->faccessat(
                        as_i32(state.r[0]), *path, as_i32(state.r[2]), as_i32(state.r[3]));
                    if (result != 0) set_errno(errno);
                    state.r[0] = as_u32(result);
                }
                return GuestHookResult{};
            })
            || !bind("fstatat64", [this](GuestCpuState32& state, GuestMemory&) { return file_statat64(state); })
            || !bind("getdents64", [this](GuestCpuState32& state, GuestMemory&) { return file_getdents64(state); })
            || !bind("__getdents64", [this](GuestCpuState32& state, GuestMemory&) { return file_getdents64(state); })
            || !bind("pthread_mutex_init", [this](GuestCpuState32& state, GuestMemory&) {
                const auto address = state.r[0];
                if (!memory_.is_accessible(GuestAddress32{address}, 4, GuestPermission::Write)) {
                    state.r[0] = kPthreadInvalid;
                    return GuestHookResult{};
                }
                std::lock_guard lock(pthread_table_mutex_);
                if (pthread_mutexes_.contains(address)) {
                    state.r[0] = kPthreadBusy;
                } else {
                    pthread_mutexes_.emplace(address, std::make_shared<GuestMutex>());
                    (void)memory_.write_u32(GuestAddress32{address}, 0x52424d58U);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_mutex_destroy", [this](GuestCpuState32& state, GuestMemory&) {
                std::lock_guard lock(pthread_table_mutex_);
                const auto found = pthread_mutexes_.find(state.r[0]);
                if (found == pthread_mutexes_.end()) {
                    state.r[0] = kPthreadInvalid;
                } else if (found->second->locked) {
                    state.r[0] = kPthreadBusy;
                } else {
                    pthread_mutexes_.erase(found);
                    (void)memory_.write_u32(GuestAddress32{state.r[0]}, 0);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_mutex_lock", [this](GuestCpuState32& state, GuestMemory&) {
                const auto mutex = find_or_create_mutex(state.r[0], true);
                if (!mutex) {
                    state.r[0] = kPthreadInvalid;
                    return GuestHookResult{};
                }
                std::lock_guard lock(pthread_table_mutex_);
                if (mutex->locked) state.r[0] = kPthreadDeadlock;
                else {
                    mutex->locked = true;
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_mutex_trylock", [this](GuestCpuState32& state, GuestMemory&) {
                const auto mutex = find_or_create_mutex(state.r[0], true);
                if (!mutex) {
                    state.r[0] = kPthreadInvalid;
                    return GuestHookResult{};
                }
                std::lock_guard lock(pthread_table_mutex_);
                if (mutex->locked) state.r[0] = kPthreadBusy;
                else {
                    mutex->locked = true;
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_mutex_unlock", [this](GuestCpuState32& state, GuestMemory&) {
                std::lock_guard lock(pthread_table_mutex_);
                const auto found = pthread_mutexes_.find(state.r[0]);
                if (found == pthread_mutexes_.end() || !found->second->locked) {
                    state.r[0] = kPthreadInvalid;
                } else {
                    found->second->locked = false;
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_self", [](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = kSyntheticThreadId;
                return GuestHookResult{};
            })
            || !bind("pthread_equal", [](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = state.r[0] == state.r[1] ? 1U : 0U;
                return GuestHookResult{};
            })
            || !bind("pthread_key_create", [this](GuestCpuState32& state, GuestMemory&) {
                if (!memory_.is_accessible(GuestAddress32{state.r[0]}, 4, GuestPermission::Write)) {
                    state.r[0] = kPthreadInvalid;
                    return GuestHookResult{};
                }
                std::lock_guard lock(pthread_table_mutex_);
                if (next_pthread_key_ == 0) {
                    state.r[0] = kPthreadAgain;
                } else {
                    const auto key = next_pthread_key_++;
                    pthread_keys_[key] = true;
                    pthread_values_[key] = 0;
                    (void)memory_.write_u32(GuestAddress32{state.r[0]}, key);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_key_delete", [this](GuestCpuState32& state, GuestMemory&) {
                std::lock_guard lock(pthread_table_mutex_);
                if (!pthread_keys_.erase(state.r[0])) state.r[0] = kPthreadInvalid;
                else {
                    pthread_values_.erase(state.r[0]);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_getspecific", [this](GuestCpuState32& state, GuestMemory&) {
                std::lock_guard lock(pthread_table_mutex_);
                const auto found = pthread_values_.find(state.r[0]);
                state.r[0] = found == pthread_values_.end() ? 0U : found->second;
                return GuestHookResult{};
            })
            || !bind("pthread_setspecific", [this](GuestCpuState32& state, GuestMemory&) {
                std::lock_guard lock(pthread_table_mutex_);
                if (!pthread_keys_.contains(state.r[0])) state.r[0] = kPthreadInvalid;
                else {
                    pthread_values_[state.r[0]] = state.r[1];
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind("pthread_create", [](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = kPthreadAgain;
                return GuestHookResult{};
            })
            || !bind("pthread_join", [](GuestCpuState32& state, GuestMemory&) {
                state.r[0] = kPthreadInvalid;
                return GuestHookResult{};
            })
            || !bind("abort", fault_thunk)
            || !bind("__stack_chk_fail", fault_thunk)
            || !bind("__stack_chk_fail_local", fault_thunk)) {
            return fail("unable to register one or more libc/pthread thunks");
        }

        const auto bind_unary_float = [&](std::string name, auto function) {
            return bind(std::move(name), [function](GuestCpuState32& state, GuestMemory&) {
                const auto input = std::bit_cast<float>(state.r[0]);
                state.r[0] = std::bit_cast<std::uint32_t>(static_cast<float>(function(input)));
                return GuestHookResult{};
            });
        };
        const auto bind_unary_double = [&](std::string name, auto function) {
            return bind(std::move(name), [function](GuestCpuState32& state, GuestMemory&) {
                const auto input = std::bit_cast<double>(read_u64(state.r[0], state.r[1]));
                write_double_result(state, static_cast<double>(function(input)));
                return GuestHookResult{};
            });
        };
        const auto bind_binary_float = [&](std::string name, auto function) {
            return bind(std::move(name), [function](GuestCpuState32& state, GuestMemory&) {
                const auto left = std::bit_cast<float>(state.r[0]);
                const auto right = std::bit_cast<float>(state.r[1]);
                state.r[0] = std::bit_cast<std::uint32_t>(static_cast<float>(function(left, right)));
                return GuestHookResult{};
            });
        };
        const auto bind_binary_double = [&](std::string name, auto function) {
            return bind(std::move(name), [function](GuestCpuState32& state, GuestMemory&) {
                const auto left = std::bit_cast<double>(read_u64(state.r[0], state.r[1]));
                const auto right = std::bit_cast<double>(read_u64(state.r[2], state.r[3]));
                write_double_result(state, static_cast<double>(function(left, right)));
                return GuestHookResult{};
            });
        };
        if (!bind_unary_float("sqrtf", static_cast<float(*)(float)>(std::sqrt))
            || !bind_unary_float("sinf", static_cast<float(*)(float)>(std::sin))
            || !bind_unary_float("cosf", static_cast<float(*)(float)>(std::cos))
            || !bind_unary_float("tanf", static_cast<float(*)(float)>(std::tan))
            || !bind_unary_float("fabsf", static_cast<float(*)(float)>(std::fabs))
            || !bind_unary_float("floorf", static_cast<float(*)(float)>(std::floor))
            || !bind_unary_float("ceilf", static_cast<float(*)(float)>(std::ceil))
            || !bind_unary_float("expf", static_cast<float(*)(float)>(std::exp))
            || !bind_unary_float("logf", static_cast<float(*)(float)>(std::log))
            || !bind_binary_float("powf", static_cast<float(*)(float, float)>(std::pow))
            || !bind_binary_float("atan2f", static_cast<float(*)(float, float)>(std::atan2))
            || !bind_binary_float("fmodf", static_cast<float(*)(float, float)>(std::fmod))
            || !bind_unary_double("sqrt", static_cast<double(*)(double)>(std::sqrt))
            || !bind_unary_double("sin", static_cast<double(*)(double)>(std::sin))
            || !bind_unary_double("cos", static_cast<double(*)(double)>(std::cos))
            || !bind_unary_double("tan", static_cast<double(*)(double)>(std::tan))
            || !bind_unary_double("fabs", static_cast<double(*)(double)>(std::fabs))
            || !bind_unary_double("floor", static_cast<double(*)(double)>(std::floor))
            || !bind_unary_double("ceil", static_cast<double(*)(double)>(std::ceil))
            || !bind_unary_double("exp", static_cast<double(*)(double)>(std::exp))
            || !bind_unary_double("log", static_cast<double(*)(double)>(std::log))
            || !bind_binary_double("pow", static_cast<double(*)(double, double)>(std::pow))
            || !bind_binary_double("atan2", static_cast<double(*)(double, double)>(std::atan2))
            || !bind_binary_double("fmod", static_cast<double(*)(double, double)>(std::fmod))) {
            return fail("unable to register one or more libm thunks");
        }

        if (!bind("__aeabi_idiv", [this](GuestCpuState32& state, GuestMemory&) {
                const auto numerator = as_i32(state.r[0]);
                const auto denominator = as_i32(state.r[1]);
                if (denominator == 0) {
                    set_errno(EDOM);
                    state.r[0] = 0;
                } else if (numerator == std::numeric_limits<std::int32_t>::min() && denominator == -1) {
                    state.r[0] = as_u32(std::numeric_limits<std::int32_t>::min());
                } else {
                    state.r[0] = as_u32(numerator / denominator);
                }
                return GuestHookResult{};
            })
            || !bind("__aeabi_uidiv", [this](GuestCpuState32& state, GuestMemory&) {
                if (state.r[1] == 0) {
                    set_errno(EDOM);
                    state.r[0] = 0;
                } else state.r[0] /= state.r[1];
                return GuestHookResult{};
            })
            || !bind("__aeabi_idivmod", [this](GuestCpuState32& state, GuestMemory&) {
                const auto numerator = as_i32(state.r[0]);
                const auto denominator = as_i32(state.r[1]);
                if (denominator == 0) {
                    set_errno(EDOM);
                    state.r[0] = 0;
                    state.r[1] = as_u32(numerator);
                } else if (numerator == std::numeric_limits<std::int32_t>::min() && denominator == -1) {
                    state.r[0] = as_u32(std::numeric_limits<std::int32_t>::min());
                    state.r[1] = 0;
                } else {
                    state.r[0] = as_u32(numerator / denominator);
                    state.r[1] = as_u32(numerator % denominator);
                }
                return GuestHookResult{};
            })
            || !bind("__aeabi_uidivmod", [this](GuestCpuState32& state, GuestMemory&) {
                const auto numerator = state.r[0];
                const auto denominator = state.r[1];
                if (denominator == 0) {
                    set_errno(EDOM);
                    state.r[0] = 0;
                    state.r[1] = numerator;
                } else {
                    state.r[0] = numerator / denominator;
                    state.r[1] = numerator % denominator;
                }
                return GuestHookResult{};
            })
            || !bind("__aeabi_lmul", [](GuestCpuState32& state, GuestMemory&) {
                const auto product = read_u64(state.r[0], state.r[1]) * read_u64(state.r[2], state.r[3]);
                state.r[0] = static_cast<std::uint32_t>(product);
                state.r[1] = static_cast<std::uint32_t>(product >> 32U);
                return GuestHookResult{};
            })
            || !bind("__aeabi_llsl", [](GuestCpuState32& state, GuestMemory&) {
                const auto value = read_u64(state.r[0], state.r[1]);
                const auto shifted = value << (state.r[2] & 63U);
                state.r[0] = static_cast<std::uint32_t>(shifted);
                state.r[1] = static_cast<std::uint32_t>(shifted >> 32U);
                return GuestHookResult{};
            })
            || !bind("__aeabi_llsr", [](GuestCpuState32& state, GuestMemory&) {
                const auto value = read_u64(state.r[0], state.r[1]);
                const auto shifted = value >> (state.r[2] & 63U);
                state.r[0] = static_cast<std::uint32_t>(shifted);
                state.r[1] = static_cast<std::uint32_t>(shifted >> 32U);
                return GuestHookResult{};
            })
            || !bind("__aeabi_lasr", [](GuestCpuState32& state, GuestMemory&) {
                const auto value = std::bit_cast<std::int64_t>(read_u64(state.r[0], state.r[1]));
                const auto shifted = std::bit_cast<std::uint64_t>(value >> (state.r[2] & 63U));
                state.r[0] = static_cast<std::uint32_t>(shifted);
                state.r[1] = static_cast<std::uint32_t>(shifted >> 32U);
                return GuestHookResult{};
            })
            || !bind("__aeabi_fadd", [](GuestCpuState32& state, GuestMemory&) {
                const auto result = std::bit_cast<float>(state.r[0]) + std::bit_cast<float>(state.r[1]);
                state.r[0] = std::bit_cast<std::uint32_t>(result);
                return GuestHookResult{};
            })
            || !bind("__aeabi_fsub", [](GuestCpuState32& state, GuestMemory&) {
                const auto result = std::bit_cast<float>(state.r[0]) - std::bit_cast<float>(state.r[1]);
                state.r[0] = std::bit_cast<std::uint32_t>(result);
                return GuestHookResult{};
            })
            || !bind("__aeabi_fmul", [](GuestCpuState32& state, GuestMemory&) {
                const auto result = std::bit_cast<float>(state.r[0]) * std::bit_cast<float>(state.r[1]);
                state.r[0] = std::bit_cast<std::uint32_t>(result);
                return GuestHookResult{};
            })
            || !bind("__aeabi_fdiv", [](GuestCpuState32& state, GuestMemory&) {
                const auto result = std::bit_cast<float>(state.r[0]) / std::bit_cast<float>(state.r[1]);
                state.r[0] = std::bit_cast<std::uint32_t>(result);
                return GuestHookResult{};
            })
            || !bind("__aeabi_dadd", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, std::bit_cast<double>(read_u64(state.r[0], state.r[1]))
                    + std::bit_cast<double>(read_u64(state.r[2], state.r[3])));
                return GuestHookResult{};
            })
            || !bind("__aeabi_dsub", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, std::bit_cast<double>(read_u64(state.r[0], state.r[1]))
                    - std::bit_cast<double>(read_u64(state.r[2], state.r[3])));
                return GuestHookResult{};
            })
            || !bind("__aeabi_dmul", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, std::bit_cast<double>(read_u64(state.r[0], state.r[1]))
                    * std::bit_cast<double>(read_u64(state.r[2], state.r[3])));
                return GuestHookResult{};
            })
            || !bind("__aeabi_ddiv", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, std::bit_cast<double>(read_u64(state.r[0], state.r[1]))
                    / std::bit_cast<double>(read_u64(state.r[2], state.r[3])));
                return GuestHookResult{};
            })
            || !bind("__aeabi_i2d", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, static_cast<double>(as_i32(state.r[0])));
                return GuestHookResult{};
            })
            || !bind("__aeabi_ui2d", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, static_cast<double>(state.r[0]));
                return GuestHookResult{};
            })
            || !bind("__aeabi_d2iz", [](GuestCpuState32& state, GuestMemory&) {
                const auto value = std::bit_cast<double>(read_u64(state.r[0], state.r[1]));
                state.r[0] = std::isfinite(value) && value >= std::numeric_limits<std::int32_t>::min()
                    && value <= std::numeric_limits<std::int32_t>::max()
                    ? as_u32(static_cast<std::int32_t>(value)) : 0U;
                return GuestHookResult{};
            })
            || !bind("__aeabi_d2f", [](GuestCpuState32& state, GuestMemory&) {
                const auto value = std::bit_cast<double>(read_u64(state.r[0], state.r[1]));
                state.r[0] = std::bit_cast<std::uint32_t>(static_cast<float>(value));
                return GuestHookResult{};
            })
            || !bind("__aeabi_f2d", [](GuestCpuState32& state, GuestMemory&) {
                write_double_result(state, static_cast<double>(std::bit_cast<float>(state.r[0])));
                return GuestHookResult{};
            })) {
            return fail("unable to register one or more ARM EABI arithmetic thunks");
        }

        if (!bind("__android_log_write", [this](GuestCpuState32& state, GuestMemory&) {
                const auto priority = as_i32(state.r[0]);
                const auto tag = read_c_string(state.r[1], 4096);
                const auto text = read_c_string(state.r[2]);
                if (!tag.has_value() || !text.has_value()) {
                    set_errno(EFAULT);
                    state.r[0] = as_u32(-1);
                } else if (std::fprintf(stderr, "RetroBridge guest [%s] %d: %s\n", tag->c_str(), priority, text->c_str()) < 0) {
                    set_errno(EIO);
                    state.r[0] = as_u32(-1);
                } else {
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })) {
            return fail("unable to register Android log thunks");
        }
        installed_ = true;
        return true;
    } catch (...) {
        return fail("host resource failure while installing Bionic thunks");
    }
}

void GuestBionicThunks::shutdown() noexcept {
    for (auto address = trampoline_allocations_.rbegin(); address != trampoline_allocations_.rend(); ++address) {
        (void)trampolines_.unregister_trampoline(*address);
    }
    trampoline_allocations_.clear();
    for (const auto address : data_allocations_) (void)heap_.free(address);
    data_allocations_.clear();
    symbols_.clear();
    data_symbols_.clear();
    errno_cell_ = GuestAddress32{0};
    stack_guard_cell_ = GuestAddress32{0};
    {
        std::lock_guard lock(pthread_table_mutex_);
        pthread_mutexes_.clear();
        pthread_values_.clear();
        pthread_keys_.clear();
    }
    installed_ = false;
}

std::optional<std::uint32_t> GuestBionicThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    return found == symbols_.end() ? std::nullopt : std::optional<std::uint32_t>{found->second};
}

std::optional<std::uint32_t> GuestBionicThunks::resolve_guest_symbol(std::string_view name) const noexcept {
    if (const auto function = resolve_symbol(name); function.has_value()) return function;
    const auto data = resolve_data_symbol(name);
    return data.has_value() ? std::optional<std::uint32_t>{data->value()} : std::nullopt;
}

std::optional<GuestAddress32> GuestBionicThunks::resolve_data_symbol(std::string_view name) const noexcept {
    const auto found = data_symbols_.find(name);
    return found == data_symbols_.end() ? std::nullopt : std::optional<GuestAddress32>{found->second};
}

std::optional<std::uint32_t> GuestBionicThunks::add_thunk(std::string name, Callback callback) {
    while (next_trampoline_address_ < 0xf3000000U
        && memory_.is_mapped(GuestAddress32{next_trampoline_address_}, 4)) next_trampoline_address_ += 4U;
    if (next_trampoline_address_ >= 0xf3000000U) return std::nullopt;
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) return GuestHookResult{GuestHookAction::Fault, "Bionic thunk received unrelated guest memory"};
        try {
            return callback(state, memory);
        } catch (...) {
            set_errno(ENOMEM);
            state.r[0] = 0;
            return GuestHookResult{};
        }
    };
    const auto symbol_name = name;
    if (!trampolines_.register_trampoline(std::move(name), GuestAddress32{address}, std::move(wrapped))) return std::nullopt;
    try {
        trampoline_allocations_.push_back(GuestAddress32{address});
        symbols_.emplace(symbol_name, address);
    } catch (...) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<std::string> GuestBionicThunks::read_c_string(std::uint32_t address, std::size_t maximum) const {
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

std::optional<std::uint32_t> GuestBionicThunks::stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept {
    const auto address = static_cast<std::uint64_t>(state.r[13]) + index * sizeof(std::uint32_t);
    if (address > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(address)});
}

bool GuestBionicThunks::read_bytes(std::uint32_t address, std::size_t size, std::vector<std::byte>& output) const {
    if (size > kMaxMemoryOperation || !memory_.is_accessible(GuestAddress32{address}, size, GuestPermission::Read)) return false;
    output.resize(size);
    return size == 0 || memory_.read(GuestAddress32{address}, output);
}

bool GuestBionicThunks::write_bytes(std::uint32_t address, std::span<const std::byte> input) const noexcept {
    return memory_.is_accessible(GuestAddress32{address}, input.size(), GuestPermission::Write)
        && (input.empty() || memory_.write(GuestAddress32{address}, input));
}

void GuestBionicThunks::set_errno(int value) noexcept {
    if (errno_cell_.value() != 0) (void)memory_.write_u32(errno_cell_, static_cast<std::uint32_t>(value));
}

std::shared_ptr<GuestBionicThunks::GuestMutex> GuestBionicThunks::find_or_create_mutex(std::uint32_t address, bool create) {
    if (address == 0 || !memory_.is_accessible(GuestAddress32{address}, 4, GuestPermission::Write)) return {};
    std::lock_guard lock(pthread_table_mutex_);
    const auto found = pthread_mutexes_.find(address);
    if (found != pthread_mutexes_.end()) return found->second;
    if (!create) return {};
    auto mutex = std::make_shared<GuestMutex>();
    pthread_mutexes_.emplace(address, mutex);
    return mutex;
}

GuestHookResult GuestBionicThunks::copy_memory(GuestCpuState32& state, bool move) {
    (void)move; // A temporary byte vector gives memmove semantics and safe guest/host separation.
    const auto size = static_cast<std::size_t>(state.r[2]);
    std::vector<std::byte> buffer;
    if (!read_bytes(state.r[1], size, buffer)) {
        set_errno(EFAULT);
        state.r[0] = 0;
    } else if (!write_bytes(state.r[0], buffer)) {
        set_errno(EFAULT);
        state.r[0] = 0;
    }
    return {};
}

GuestHookResult GuestBionicThunks::set_memory(GuestCpuState32& state, bool aeabi_order, bool clear) {
    const auto address = state.r[0];
    const auto length = static_cast<std::size_t>(aeabi_order ? state.r[1] : state.r[2]);
    const auto value = clear ? 0U : (aeabi_order ? state.r[2] : state.r[1]);
    if (length > kMaxMemoryOperation || !memory_.is_accessible(GuestAddress32{address}, length, GuestPermission::Write)) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    std::vector<std::byte> bytes(length, static_cast<std::byte>(value & 0xffU));
    if (!write_bytes(address, bytes)) {
        set_errno(EFAULT);
        state.r[0] = 0;
    }
    return {};
}

GuestHookResult GuestBionicThunks::compare_memory(GuestCpuState32& state) {
    const auto size = static_cast<std::size_t>(state.r[2]);
    std::vector<std::byte> left;
    std::vector<std::byte> right;
    if (!read_bytes(state.r[0], size, left) || !read_bytes(state.r[1], size, right)) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    for (std::size_t index = 0; index < size; ++index) {
        const auto a = std::to_integer<std::uint8_t>(left[index]);
        const auto b = std::to_integer<std::uint8_t>(right[index]);
        if (a != b) {
            state.r[0] = as_u32(static_cast<std::int32_t>(a) - static_cast<std::int32_t>(b));
            return {};
        }
    }
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestBionicThunks::find_memory_character(GuestCpuState32& state, bool reverse) {
    const auto size = static_cast<std::size_t>(state.r[2]);
    std::vector<std::byte> bytes;
    if (!read_bytes(state.r[0], size, bytes)) {
        set_errno(size > kMaxMemoryOperation ? EINVAL : EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto wanted = static_cast<std::byte>(state.r[1] & 0xffU);
    std::optional<std::size_t> offset;
    if (reverse) {
        for (std::size_t index = bytes.size(); index > 0; --index) {
            if (bytes[index - 1U] == wanted) {
                offset = index - 1U;
                break;
            }
        }
    } else {
        const auto found = std::find(bytes.begin(), bytes.end(), wanted);
        if (found != bytes.end()) offset = static_cast<std::size_t>(found - bytes.begin());
    }
    if (!offset.has_value()) {
        state.r[0] = 0;
    } else {
        const auto result = static_cast<std::uint64_t>(state.r[0]) + *offset;
        state.r[0] = result <= std::numeric_limits<std::uint32_t>::max()
            ? static_cast<std::uint32_t>(result) : 0U;
    }
    return {};
}

GuestHookResult GuestBionicThunks::string_length(GuestCpuState32& state) {
    const auto value = read_c_string(state.r[0], kMaxStringOperation);
    if (!value.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
    } else {
        state.r[0] = static_cast<std::uint32_t>(value->size());
    }
    return {};
}

GuestHookResult GuestBionicThunks::bounded_string_length(GuestCpuState32& state) {
    const auto requested = static_cast<std::size_t>(state.r[1]);
    const auto scan_limit = std::min(requested, kMaxStringOperation);
    const auto base = static_cast<std::uint64_t>(state.r[0]);
    for (std::size_t index = 0; index < scan_limit; ++index) {
        const auto address = base + index;
        if (address > std::numeric_limits<std::uint32_t>::max()) {
            set_errno(EFAULT);
            state.r[0] = 0;
            return {};
        }
        const auto value = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(address)});
        if (!value.has_value()) {
            set_errno(EFAULT);
            state.r[0] = 0;
            return {};
        }
        if (*value == 0) {
            state.r[0] = static_cast<std::uint32_t>(index);
            return {};
        }
    }
    if (requested > scan_limit) {
        set_errno(EINVAL);
        state.r[0] = 0;
    } else {
        state.r[0] = static_cast<std::uint32_t>(requested);
    }
    return {};
}

GuestHookResult GuestBionicThunks::find_string_character(GuestCpuState32& state, bool reverse) {
    const auto text = read_c_string(state.r[0], kMaxStringOperation);
    if (!text.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto wanted = static_cast<unsigned char>(state.r[1] & 0xffU);
    std::optional<std::size_t> offset;
    if (wanted == 0) {
        offset = text->size();
    } else if (reverse) {
        for (std::size_t index = text->size(); index > 0; --index) {
            if (static_cast<unsigned char>((*text)[index - 1U]) == wanted) {
                offset = index - 1U;
                break;
            }
        }
    } else {
        for (std::size_t index = 0; index < text->size(); ++index) {
            if (static_cast<unsigned char>((*text)[index]) == wanted) {
                offset = index;
                break;
            }
        }
    }
    if (!offset.has_value()) {
        state.r[0] = 0;
        return {};
    }
    const auto result = static_cast<std::uint64_t>(state.r[0]) + *offset;
    state.r[0] = result <= std::numeric_limits<std::uint32_t>::max()
        ? static_cast<std::uint32_t>(result) : 0U;
    return {};
}

GuestHookResult GuestBionicThunks::find_string_substring(GuestCpuState32& state, bool character_set) {
    const auto text = read_c_string(state.r[0], kMaxStringOperation);
    const auto pattern = read_c_string(state.r[1], kMaxStringOperation);
    if (!text.has_value() || !pattern.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto offset = character_set ? text->find_first_of(*pattern) : text->find(*pattern);
    if (offset == std::string::npos) {
        state.r[0] = 0;
        return {};
    }
    const auto result = static_cast<std::uint64_t>(state.r[0]) + offset;
    state.r[0] = result <= std::numeric_limits<std::uint32_t>::max()
        ? static_cast<std::uint32_t>(result) : 0U;
    return {};
}

GuestHookResult GuestBionicThunks::string_span(GuestCpuState32& state, bool reject_set) {
    const auto text = read_c_string(state.r[0], kMaxStringOperation);
    const auto set = read_c_string(state.r[1], kMaxStringOperation);
    if (!text.has_value() || !set.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto boundary = reject_set ? text->find_first_of(*set) : text->find_first_not_of(*set);
    state.r[0] = static_cast<std::uint32_t>(boundary == std::string::npos ? text->size() : boundary);
    return {};
}

GuestHookResult GuestBionicThunks::string_compare(GuestCpuState32& state, bool bounded) {
    if (bounded) {
        const auto requested_count = static_cast<std::size_t>(state.r[2]);
        if (requested_count > kMaxStringOperation) {
            set_errno(EOVERFLOW);
            state.r[0] = 0;
            return {};
        }
        const auto count = requested_count;
        for (std::size_t index = 0; index < count; ++index) {
            const auto left_address = static_cast<std::uint64_t>(state.r[0]) + index;
            const auto right_address = static_cast<std::uint64_t>(state.r[1]) + index;
            if (left_address > std::numeric_limits<std::uint32_t>::max()
                || right_address > std::numeric_limits<std::uint32_t>::max()) {
                set_errno(EFAULT);
                state.r[0] = 0;
                return {};
            }
            const auto left = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(left_address)});
            const auto right = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(right_address)});
            if (!left.has_value() || !right.has_value()) {
                set_errno(EFAULT);
                state.r[0] = 0;
                return {};
            }
            if (*left != *right) {
                state.r[0] = as_u32(static_cast<std::int32_t>(*left) - static_cast<std::int32_t>(*right));
                return {};
            }
            if (*left == 0) break;
        }
        state.r[0] = 0;
        return {};
    }
    const auto left = read_c_string(state.r[0], kMaxStringOperation);
    const auto right = read_c_string(state.r[1], kMaxStringOperation);
    if (!left.has_value() || !right.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
    } else {
        state.r[0] = as_u32(compare_bytes(*left, *right));
    }
    return {};
}

GuestHookResult GuestBionicThunks::string_copy(GuestCpuState32& state, bool bounded) {
    if (bounded) {
        const auto count = static_cast<std::size_t>(state.r[2]);
        if (count == 0) return {};
        if (count > kMaxStringOperation
            || !memory_.is_accessible(GuestAddress32{state.r[0]}, count, GuestPermission::Write)) {
            set_errno(count > kMaxStringOperation ? EINVAL : EFAULT);
            state.r[0] = 0;
            return {};
        }
        std::vector<std::byte> output(count, std::byte{0});
        for (std::size_t index = 0; index < count; ++index) {
            const auto source_address = static_cast<std::uint64_t>(state.r[1]) + index;
            if (source_address > std::numeric_limits<std::uint32_t>::max()) {
                set_errno(EFAULT);
                state.r[0] = 0;
                return {};
            }
            const auto value = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(source_address)});
            if (!value.has_value()) {
                set_errno(EFAULT);
                state.r[0] = 0;
                return {};
            }
            output[index] = static_cast<std::byte>(*value);
            if (*value == 0) break;
        }
        if (!write_bytes(state.r[0], output)) {
            set_errno(EFAULT);
            state.r[0] = 0;
        }
        return {};
    }
    const auto source = read_c_string(state.r[1], kMaxStringOperation);
    if (!source.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto count = source->size() + 1U;
    if (!memory_.is_accessible(GuestAddress32{state.r[0]}, count, GuestPermission::Write)) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    std::vector<std::byte> output(count, std::byte{0});
    for (std::size_t index = 0; index < source->size(); ++index) {
        output[index] = static_cast<std::byte>(static_cast<unsigned char>((*source)[index]));
    }
    if (!write_bytes(state.r[0], output)) {
        set_errno(EFAULT);
        state.r[0] = 0;
    }
    return {};
}

GuestHookResult GuestBionicThunks::string_duplicate(GuestCpuState32& state) {
    const auto source = read_c_string(state.r[0], kMaxStringOperation);
    if (!source.has_value()) {
        set_errno(EFAULT);
        state.r[0] = 0;
        return {};
    }
    const auto address = heap_.malloc(source->size() + 1U);
    if (!address.has_value()) {
        set_errno(ENOMEM);
        state.r[0] = 0;
        return {};
    }
    std::vector<std::byte> bytes(source->size() + 1U, std::byte{0});
    for (std::size_t index = 0; index < source->size(); ++index) bytes[index] = static_cast<std::byte>(static_cast<unsigned char>((*source)[index]));
    if (!memory_.write(*address, bytes)) {
        (void)heap_.free(*address);
        set_errno(EFAULT);
        state.r[0] = 0;
    } else state.r[0] = address->value();
    return {};
}

GuestHookResult GuestBionicThunks::file_open(GuestCpuState32& state) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto path = read_c_string(state.r[0]);
    if (!path.has_value()) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto descriptor = vfs_->open(*path, static_cast<int>(state.r[1]), state.r[2]);
    if (descriptor < 0) set_errno(errno);
    state.r[0] = as_u32(descriptor);
    return {};
}

GuestHookResult GuestBionicThunks::file_close(GuestCpuState32& state) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto result = vfs_->close(as_i32(state.r[0]));
    if (result != 0) set_errno(errno);
    state.r[0] = as_u32(result);
    return {};
}

GuestHookResult GuestBionicThunks::file_read(GuestCpuState32& state) {
    const auto count = static_cast<std::size_t>(state.r[2]);
    if (vfs_ == nullptr || count > kMaxMemoryOperation || !memory_.is_accessible(GuestAddress32{state.r[1]}, count, GuestPermission::Write)) {
        set_errno(vfs_ == nullptr ? ENOSYS : EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    std::vector<std::byte> bytes(count);
    const auto result = vfs_->read(as_i32(state.r[0]), bytes);
    if (result < 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
    } else if (result > 0 && !memory_.write(GuestAddress32{state.r[1]}, std::span<const std::byte>{bytes.data(), static_cast<std::size_t>(result)})) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
    } else state.r[0] = static_cast<std::uint32_t>(result);
    return {};
}

GuestHookResult GuestBionicThunks::file_write(GuestCpuState32& state) {
    const auto count = static_cast<std::size_t>(state.r[2]);
    std::vector<std::byte> bytes;
    if (vfs_ == nullptr || !read_bytes(state.r[1], count, bytes)) {
        set_errno(vfs_ == nullptr ? ENOSYS : EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto result = vfs_->write(as_i32(state.r[0]), bytes);
    if (result < 0) set_errno(errno);
    state.r[0] = as_u32(static_cast<std::int32_t>(result));
    return {};
}

GuestHookResult GuestBionicThunks::file_pread(GuestCpuState32& state) {
    const auto count = static_cast<std::size_t>(state.r[2]);
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (count > kMaxMemoryOperation
        || (count != 0 && !memory_.is_accessible(GuestAddress32{state.r[1]}, count, GuestPermission::Write))) {
        set_errno(count > kMaxMemoryOperation ? EINVAL : EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    std::vector<std::byte> bytes(count);
    const auto result = vfs_->pread(as_i32(state.r[0]), bytes, as_i32(state.r[3]));
    if (result < 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
    } else if (result > 0 && !memory_.write(GuestAddress32{state.r[1]},
            std::span<const std::byte>{bytes.data(), static_cast<std::size_t>(result)})) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
    } else {
        state.r[0] = static_cast<std::uint32_t>(result);
    }
    return {};
}

GuestHookResult GuestBionicThunks::file_pwrite(GuestCpuState32& state) {
    const auto count = static_cast<std::size_t>(state.r[2]);
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (count > kMaxMemoryOperation) {
        set_errno(EINVAL);
        state.r[0] = as_u32(-1);
        return {};
    }
    std::vector<std::byte> bytes;
    if (!read_bytes(state.r[1], count, bytes)) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto result = vfs_->pwrite(as_i32(state.r[0]), bytes, as_i32(state.r[3]));
    if (result < 0) set_errno(errno);
    state.r[0] = as_u32(static_cast<std::int32_t>(result));
    return {};
}

GuestHookResult GuestBionicThunks::file_seek(GuestCpuState32& state) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto offset = static_cast<long long>(as_i32(state.r[1]));
    const auto result = vfs_->seek(as_i32(state.r[0]), offset, static_cast<int>(state.r[2]));
    if (result < 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
    } else if (result > std::numeric_limits<std::int32_t>::max()) {
        set_errno(EOVERFLOW);
        state.r[0] = as_u32(-1);
    } else state.r[0] = static_cast<std::uint32_t>(result);
    return {};
}

GuestHookResult GuestBionicThunks::file_seek64(GuestCpuState32& state) {
    const auto whence = stack_argument(state, 0);
    if (vfs_ == nullptr || !whence.has_value()) {
        set_errno(vfs_ == nullptr ? ENOSYS : EFAULT);
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        state.r[1] = std::numeric_limits<std::uint32_t>::max();
        return {};
    }
    const auto offset = std::bit_cast<std::int64_t>(read_u64(state.r[2], state.r[3]));
    const auto result = vfs_->seek(as_i32(state.r[0]), static_cast<long long>(offset), static_cast<int>(*whence));
    if (result < 0) {
        set_errno(errno);
        state.r[0] = std::numeric_limits<std::uint32_t>::max();
        state.r[1] = std::numeric_limits<std::uint32_t>::max();
    } else {
        const auto bits = static_cast<std::uint64_t>(result);
        state.r[0] = static_cast<std::uint32_t>(bits);
        state.r[1] = static_cast<std::uint32_t>(bits >> 32U);
    }
    return {};
}

GuestHookResult GuestBionicThunks::file_stat64(GuestCpuState32& state, bool no_follow) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto path = read_c_string(state.r[0]);
    if (!path.has_value()) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    struct stat status{};
    if (vfs_->stat_path(*path, &status, no_follow) != 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (!write_arm32_guest_stat64(memory_, GuestAddress32{state.r[1]}, status)) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestBionicThunks::file_fstat64(GuestCpuState32& state) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    struct stat status{};
    if (vfs_->fstat(as_i32(state.r[0]), &status) != 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (!write_arm32_guest_stat64(memory_, GuestAddress32{state.r[1]}, status)) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestBionicThunks::file_statat64(GuestCpuState32& state) {
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    const auto path = read_c_string(state.r[1]);
    if (!path.has_value()) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    struct stat status{};
    if (vfs_->statat(as_i32(state.r[0]), *path, &status, as_i32(state.r[3])) != 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (!write_arm32_guest_stat64(memory_, GuestAddress32{state.r[2]}, status)) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestBionicThunks::file_getdents64(GuestCpuState32& state) {
    const auto count = static_cast<std::size_t>(state.r[2]);
    if (vfs_ == nullptr) {
        set_errno(ENOSYS);
        state.r[0] = as_u32(-1);
        return {};
    }
    if (count > kMaxMemoryOperation
        || !memory_.is_accessible(GuestAddress32{state.r[1]}, count, GuestPermission::Write)) {
        set_errno(count > kMaxMemoryOperation ? EINVAL : EFAULT);
        state.r[0] = as_u32(-1);
        return {};
    }
    std::vector<std::byte> entries(count);
    const auto result = vfs_->getdents64(as_i32(state.r[0]), entries);
    if (result < 0) {
        set_errno(errno);
        state.r[0] = as_u32(-1);
    } else if (result > 0 && !memory_.write(GuestAddress32{state.r[1]},
            std::span<const std::byte>{entries.data(), static_cast<std::size_t>(result)})) {
        set_errno(EFAULT);
        state.r[0] = as_u32(-1);
    } else {
        state.r[0] = static_cast<std::uint32_t>(result);
    }
    return {};
}

std::uint64_t GuestBionicThunks::read_u64(std::uint32_t low, std::uint32_t high) noexcept {
    return static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
}

void GuestBionicThunks::write_double_result(GuestCpuState32& state, double value) noexcept {
    const auto bits = std::bit_cast<std::uint64_t>(value);
    state.r[0] = static_cast<std::uint32_t>(bits);
    state.r[1] = static_cast<std::uint32_t>(bits >> 32U);
}

}  // namespace retrobridge::runtime
