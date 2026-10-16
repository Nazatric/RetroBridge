#pragma once

#include "retrobridge/arm32_interpreter.h"
#include "retrobridge/guest_heap.h"
#include "retrobridge/handle_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {

/**
 * A single-threaded, synthetic 32-bit JNI/JavaVM ABI surface. Tables and opaque handles live in
 * guest memory; host references and callbacks never cross the guest boundary as host pointers.
 * Only the explicitly implemented JNI subset is callable; other entries report a pending error.
 */
class GuestJniBridge final {
public:
    GuestJniBridge(GuestMemory& memory, GuestHeap32& heap, GuestTrampolineRegistry& trampolines);
    ~GuestJniBridge();

    GuestJniBridge(const GuestJniBridge&) = delete;
    GuestJniBridge& operator=(const GuestJniBridge&) = delete;

    [[nodiscard]] bool initialize(std::string* diagnostic = nullptr);
    void shutdown() noexcept;
    [[nodiscard]] bool initialized() const noexcept { return initialized_; }
    [[nodiscard]] GuestAddress32 jni_env_address() const noexcept { return jni_env_; }
    [[nodiscard]] GuestAddress32 java_vm_address() const noexcept { return java_vm_; }
    [[nodiscard]] std::optional<std::uint32_t> resolve_symbol(std::string_view name) const noexcept;
    [[nodiscard]] std::size_t registered_native_count() const noexcept { return native_methods_.size(); }
    [[nodiscard]] const std::string& pending_exception() const noexcept { return pending_exception_; }

private:
    enum class ObjectKind : std::uint8_t { Class, Instance, String, ByteArray, IntArray, ObjectArray, Throwable };
    enum class PinKind : std::uint8_t { Utf8String, Utf16String, ByteArray, IntArray };
    struct Object final {
        Object() = default;
        Object(ObjectKind object_kind, const std::string& object_class, const std::string& string = {})
            : kind(object_kind), class_name(object_class), string_value(string) {}

        ObjectKind kind = ObjectKind::Instance;
        std::string class_name;
        std::string string_value;
        std::vector<std::byte> bytes;
        std::vector<std::uint64_t> object_elements;
    };
    struct NativeMethod final {
        std::uint32_t class_handle = 0;
        std::string class_name;
        std::string name;
        std::string signature;
        std::uint32_t guest_function = 0;
        bool is_static = false;
    };
    struct StringPin final {
        std::uint64_t token = 0;
        GuestAddress32 address{0};
        PinKind kind = PinKind::Utf8String;
    };
    using Callback = GuestTrampolineFunction;

    [[nodiscard]] std::optional<GuestAddress32> allocate_guest(std::size_t size);
    [[nodiscard]] std::optional<std::uint32_t> register_callback(std::string name, Callback callback);
    [[nodiscard]] std::optional<std::uint64_t> create_object(Object object);
    [[nodiscard]] std::optional<std::uint32_t> create_local_ref(std::uint64_t token);
    [[nodiscard]] std::optional<std::uint64_t> resolve_token(std::uint32_t handle) const;
    [[nodiscard]] Object* object_for_handle(std::uint32_t handle) noexcept;
    [[nodiscard]] const Object* object_for_handle(std::uint32_t handle) const noexcept;
    [[nodiscard]] std::optional<std::string> read_c_string(std::uint32_t address, std::size_t maximum = 1U << 20U) const;
    [[nodiscard]] std::optional<std::uint32_t> stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> make_method_id(
        std::uint32_t class_handle, std::string name, std::string signature, bool is_static);
    [[nodiscard]] std::string class_name_for_handle(std::uint32_t handle) const;
    [[nodiscard]] GuestHookResult unsupported(GuestCpuState32& state);
    void set_exception(std::string message);
    [[nodiscard]] std::uint32_t release_reference(std::uint32_t handle) noexcept;
    [[nodiscard]] std::optional<std::uint32_t> duplicate_reference(std::uint32_t handle, ReferenceKind kind);
    [[nodiscard]] GuestHookResult pin_primitive_array(GuestCpuState32& state, ObjectKind kind, bool copy_flag);
    [[nodiscard]] GuestHookResult release_primitive_array(GuestCpuState32& state, ObjectKind kind);
    [[nodiscard]] GuestHookResult array_region(GuestCpuState32& state, ObjectKind kind, bool write_to_array);
    [[nodiscard]] static std::vector<std::uint16_t> utf8_to_utf16(std::string_view text);
    [[nodiscard]] static std::string utf16_to_utf8(std::span<const std::uint16_t> text);

    GuestMemory& memory_;
    GuestHeap32& heap_;
    GuestTrampolineRegistry& trampolines_;
    HandleTable handles_;
    bool initialized_ = false;
    GuestAddress32 jni_table_{0};
    GuestAddress32 jni_env_{0};
    GuestAddress32 java_vm_table_{0};
    GuestAddress32 java_vm_{0};
    std::uint32_t next_trampoline_address_ = 0xf1000000U;
    std::uint32_t next_method_id_ = 0xf3000000U;
    std::uint64_t next_object_token_ = 1;
    std::vector<GuestAddress32> guest_allocations_;
    std::vector<GuestAddress32> trampoline_allocations_;
    std::vector<std::uint32_t> local_references_;
    std::vector<std::size_t> local_frame_bases_;
    std::map<std::uint64_t, Object> objects_;
    std::map<std::uint32_t, NativeMethod> method_ids_;
    std::vector<NativeMethod> native_methods_;
    std::map<std::uint32_t, StringPin> string_pins_;
    std::string pending_exception_;
};

}  // namespace retrobridge::runtime
