#include "retrobridge/guest_jni_bridge.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::size_t kJniTableEntries = 234;
constexpr std::size_t kJavaVmTableEntries = 8;
constexpr std::size_t kMaxJniStringBytes = 1U << 20U;
constexpr std::size_t kMaxJniArrayElements = 1U << 20U;
constexpr std::uint32_t kJniVersion16 = 0x00010006U;
constexpr std::uint32_t kJniError = 0xffffffffU;
constexpr std::uint32_t kJniVersionError = 0xfffffffdU;
constexpr std::uint32_t kJniAbort = 2U;
constexpr std::uint32_t kJniCommit = 1U;

enum class JniIndex : std::size_t {
    GetVersion = 4,
    FindClass = 6,
    Throw = 13,
    ThrowNew = 14,
    ExceptionOccurred = 15,
    ExceptionDescribe = 16,
    ExceptionClear = 17,
    FatalError = 18,
    PushLocalFrame = 19,
    PopLocalFrame = 20,
    NewGlobalRef = 21,
    DeleteGlobalRef = 22,
    DeleteLocalRef = 23,
    IsSameObject = 24,
    NewLocalRef = 25,
    EnsureLocalCapacity = 26,
    AllocObject = 27,
    NewObject = 28,
    NewObjectV = 29,
    NewObjectA = 30,
    GetObjectClass = 31,
    IsInstanceOf = 32,
    GetMethodId = 33,
    GetStaticMethodId = 113,
    NewString = 163,
    GetStringLength = 164,
    GetStringChars = 165,
    ReleaseStringChars = 166,
    NewStringUtf = 167,
    GetStringUtfLength = 168,
    GetStringUtfChars = 169,
    ReleaseStringUtfChars = 170,
    GetArrayLength = 171,
    NewObjectArray = 172,
    GetObjectArrayElement = 173,
    SetObjectArrayElement = 174,
    NewByteArray = 176,
    NewIntArray = 179,
    GetByteArrayElements = 184,
    GetIntArrayElements = 187,
    ReleaseByteArrayElements = 192,
    ReleaseIntArrayElements = 195,
    GetByteArrayRegion = 200,
    GetIntArrayRegion = 203,
    SetByteArrayRegion = 208,
    SetIntArrayRegion = 211,
    RegisterNatives = 215,
    UnregisterNatives = 216,
    GetJavaVm = 219,
    GetStringRegion = 220,
    GetStringUtfRegion = 221,
    NewWeakGlobalRef = 226,
    DeleteWeakGlobalRef = 227,
    ExceptionCheck = 228,
    GetObjectRefType = 232,
};

enum class VmIndex : std::size_t {
    DestroyJavaVm = 3,
    AttachCurrentThread = 4,
    DetachCurrentThread = 5,
    GetEnv = 6,
    AttachCurrentThreadAsDaemon = 7,
};

[[nodiscard]] std::uint32_t read_le32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + index])) << (index * 8U);
    }
    return value;
}

void append_utf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7fU) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
}

}  // namespace

GuestJniBridge::GuestJniBridge(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines)
    : memory_(memory), heap_(heap), trampolines_(trampolines), handles_(4096) {}

GuestJniBridge::~GuestJniBridge() {
    shutdown();
}

bool GuestJniBridge::initialize(std::string* diagnostic) {
    const auto fail = [&](const std::string& message) {
        if (diagnostic != nullptr) *diagnostic = message;
        shutdown();
        return false;
    };
    if (initialized_) return true;
    if (!heap_.initialized()) return fail("guest JNI bridge requires an initialized guest heap");
    try {
        const auto table = allocate_guest(kJniTableEntries * sizeof(std::uint32_t));
        const auto env = allocate_guest(sizeof(std::uint32_t));
        const auto vm_table = allocate_guest(kJavaVmTableEntries * sizeof(std::uint32_t));
        const auto vm = allocate_guest(sizeof(std::uint32_t));
        if (!table.has_value() || !env.has_value() || !vm_table.has_value() || !vm.has_value()) {
            return fail("guest JNI tables do not fit in the guest heap");
        }
        jni_table_ = *table;
        jni_env_ = *env;
        java_vm_table_ = *vm_table;
        java_vm_ = *vm;

        const auto unsupported_address = register_callback("jni.unsupported", [this](GuestCpuState32& state, GuestMemory&) {
            return unsupported(state);
        });
        if (!unsupported_address.has_value()) return fail("unable to register the JNI unsupported-call thunk");

        std::array<std::uint32_t, kJniTableEntries> table_entries{};
        std::fill(table_entries.begin() + 4, table_entries.end(), *unsupported_address);
        const auto bind = [&](JniIndex index, std::string name, Callback callback) -> bool {
            const auto address = register_callback("jni." + name, std::move(callback));
            if (!address.has_value()) return false;
            table_entries[static_cast<std::size_t>(index)] = *address;
            return true;
        };
        const auto env_is_valid = [this](GuestCpuState32& state) {
            if (state.r[0] == jni_env_.value()) return true;
            set_exception("JNI call used an invalid JNIEnv pointer");
            state.r[0] = 0;
            return false;
        };
        const Callback new_object_callback = [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
            if (!env_is_valid(state)) return GuestHookResult{};
            const auto* klass = object_for_handle(state.r[1]);
            if (klass == nullptr || klass->kind != ObjectKind::Class) {
                set_exception("NewObject received an invalid jclass");
                state.r[0] = 0;
            } else {
                const auto token = create_object(Object{ObjectKind::Instance, klass->class_name});
                state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
            }
            return GuestHookResult{};
        };

        if (!bind(JniIndex::GetVersion, "GetVersion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = kJniVersion16;
                return GuestHookResult{};
            })
            || !bind(JniIndex::FindClass, "FindClass", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto name = read_c_string(state.r[1], 4096);
                if (!name.has_value() || name->empty()) {
                    set_exception("FindClass received an invalid class name");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto token = create_object(Object{ObjectKind::Class, *name});
                const auto handle = token.has_value() ? create_local_ref(*token) : std::nullopt;
                state.r[0] = handle.value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::Throw, "Throw", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                if (object == nullptr || object->kind != ObjectKind::Throwable) {
                    set_exception("Throw received an invalid throwable");
                    state.r[0] = kJniError;
                } else {
                    set_exception(object->string_value);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::ThrowNew, "ThrowNew", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* klass = object_for_handle(state.r[1]);
                const auto message = read_c_string(state.r[2]);
                if (klass == nullptr || klass->kind != ObjectKind::Class || !message.has_value()) {
                    set_exception("ThrowNew received an invalid class or message");
                    state.r[0] = kJniError;
                } else {
                    set_exception(klass->class_name + ": " + *message);
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::ExceptionOccurred, "ExceptionOccurred", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                if (pending_exception_.empty()) {
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto token = create_object(Object{ObjectKind::Throwable, "java/lang/Throwable", pending_exception_});
                const auto handle = token.has_value() ? create_local_ref(*token) : std::nullopt;
                state.r[0] = handle.value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::ExceptionDescribe, "ExceptionDescribe", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                (void)this;
                (void)env_is_valid(state);
                return GuestHookResult{};
            })
            || !bind(JniIndex::ExceptionClear, "ExceptionClear", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                pending_exception_.clear();
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::FatalError, "FatalError", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{GuestHookAction::Fault, "invalid JNIEnv in FatalError"};
                const auto message = read_c_string(state.r[1]);
                return GuestHookResult{GuestHookAction::Fault,
                    message.has_value() ? "guest JNI FatalError: " + *message : "guest JNI FatalError"};
            })
            || !bind(JniIndex::PushLocalFrame, "PushLocalFrame", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto capacity = std::bit_cast<std::int32_t>(state.r[1]);
                if (capacity < 0 || capacity > 4096) {
                    set_exception("PushLocalFrame capacity is outside the supported range");
                    state.r[0] = kJniError;
                    return GuestHookResult{};
                }
                local_frame_bases_.push_back(local_references_.size());
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::PopLocalFrame, "PopLocalFrame", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto preserved = resolve_token(state.r[1]);
                if (state.r[1] != 0 && !preserved.has_value()) set_exception("PopLocalFrame received a stale result reference");
                const auto base = local_frame_bases_.empty() ? std::size_t{0} : local_frame_bases_.back();
                if (!local_frame_bases_.empty()) local_frame_bases_.pop_back();
                while (local_references_.size() > base) {
                    const auto handle = local_references_.back();
                    local_references_.pop_back();
                    (void)handles_.release(handle);
                }
                const auto result = preserved.has_value() && *preserved != 0 ? create_local_ref(*preserved) : std::optional<std::uint32_t>{0};
                state.r[0] = result.value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewGlobalRef, "NewGlobalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = duplicate_reference(state.r[1], ReferenceKind::Global).value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::DeleteGlobalRef, "DeleteGlobalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                if (state.r[1] != 0
                    && (handles_.kind_of(state.r[1]) != ReferenceKind::Global || !release_reference(state.r[1]))) {
                    set_exception("DeleteGlobalRef received a stale or non-global handle");
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::DeleteLocalRef, "DeleteLocalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                if (state.r[1] != 0 && (handles_.kind_of(state.r[1]) != ReferenceKind::Local || !release_reference(state.r[1]))) {
                    set_exception("DeleteLocalRef received a stale or non-local handle");
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::IsSameObject, "IsSameObject", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto left = resolve_token(state.r[1]);
                const auto right = resolve_token(state.r[2]);
                if (!left.has_value() || !right.has_value()) {
                    set_exception("IsSameObject received a stale handle");
                    state.r[0] = 0;
                } else {
                    state.r[0] = *left == *right ? 1U : 0U;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewLocalRef, "NewLocalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = duplicate_reference(state.r[1], ReferenceKind::Local).value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::EnsureLocalCapacity, "EnsureLocalCapacity", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto capacity = std::bit_cast<std::int32_t>(state.r[1]);
                state.r[0] = capacity >= 0 && capacity <= 4096 ? 0U : kJniError;
                if (state.r[0] != 0) set_exception("EnsureLocalCapacity exceeds the supported handle table");
                return GuestHookResult{};
            })
            || !bind(JniIndex::AllocObject, "AllocObject", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* klass = object_for_handle(state.r[1]);
                if (klass == nullptr || klass->kind != ObjectKind::Class) {
                    set_exception("AllocObject received an invalid jclass");
                    state.r[0] = 0;
                } else {
                    const auto token = create_object(Object{ObjectKind::Instance, klass->class_name});
                    state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewObject, "NewObject", new_object_callback)
            || !bind(JniIndex::NewObjectV, "NewObjectV", new_object_callback)
            || !bind(JniIndex::NewObjectA, "NewObjectA", new_object_callback)
            || !bind(JniIndex::GetObjectClass, "GetObjectClass", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                if (object == nullptr) {
                    set_exception("GetObjectClass received a null or stale object");
                    state.r[0] = 0;
                } else {
                    const auto token = create_object(Object{ObjectKind::Class, object->class_name});
                    state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::IsInstanceOf, "IsInstanceOf", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                const auto* klass = object_for_handle(state.r[2]);
                if (state.r[1] == 0) {
                    state.r[0] = 1;
                } else if (object == nullptr || klass == nullptr || klass->kind != ObjectKind::Class) {
                    set_exception("IsInstanceOf received an invalid handle");
                    state.r[0] = 0;
                } else {
                    state.r[0] = object->class_name == klass->class_name || klass->class_name == "java/lang/Object" ? 1U : 0U;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetMethodId, "GetMethodID", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto name = read_c_string(state.r[2], 4096);
                const auto signature = read_c_string(state.r[3], 4096);
                const auto class_name = class_name_for_handle(state.r[1]);
                const auto method = name.has_value() && signature.has_value() && !class_name.empty()
                    ? make_method_id(state.r[1], *name, *signature, false) : std::nullopt;
                if (!method.has_value()) set_exception("GetMethodID received an invalid class, name, or signature");
                state.r[0] = method.value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStaticMethodId, "GetStaticMethodID", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto name = read_c_string(state.r[2], 4096);
                const auto signature = read_c_string(state.r[3], 4096);
                const auto class_name = class_name_for_handle(state.r[1]);
                const auto method = name.has_value() && signature.has_value() && !class_name.empty()
                    ? make_method_id(state.r[1], *name, *signature, true) : std::nullopt;
                if (!method.has_value()) set_exception("GetStaticMethodID received an invalid class, name, or signature");
                state.r[0] = method.value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewString, "NewString", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto length = std::bit_cast<std::int32_t>(state.r[2]);
                if (length < 0 || static_cast<std::size_t>(length) > kMaxJniStringBytes / 2U) {
                    set_exception("NewString length is outside the supported range");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                std::vector<std::uint16_t> units(static_cast<std::size_t>(length));
                for (std::size_t index = 0; index < units.size(); ++index) {
                    const auto address = static_cast<std::uint64_t>(state.r[1]) + index * 2U;
                    if (address > std::numeric_limits<std::uint32_t>::max()) {
                        set_exception("NewString guest buffer overflows");
                        state.r[0] = 0;
                        return GuestHookResult{};
                    }
                    const auto unit = memory_.read_u16(GuestAddress32{static_cast<std::uint32_t>(address)});
                    if (!unit.has_value()) {
                        set_exception("NewString guest buffer is unreadable");
                        state.r[0] = 0;
                        return GuestHookResult{};
                    }
                    units[index] = *unit;
                }
                const auto value = utf16_to_utf8(units);
                const auto token = create_object(Object{ObjectKind::String, "java/lang/String", value});
                state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringLength, "GetStringLength", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                if (object == nullptr || object->kind != ObjectKind::String) {
                    set_exception("GetStringLength received an invalid jstring");
                    state.r[0] = 0;
                } else {
                    state.r[0] = static_cast<std::uint32_t>(utf8_to_utf16(object->string_value).size());
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringChars, "GetStringChars", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto token = resolve_token(state.r[1]);
                const auto* object = object_for_handle(state.r[1]);
                if (!token.has_value() || object == nullptr || object->kind != ObjectKind::String) {
                    set_exception("GetStringChars received an invalid jstring");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto units = utf8_to_utf16(object->string_value);
                const auto bytes = (units.size() + 1U) * sizeof(std::uint16_t);
                const auto address = heap_.malloc(bytes);
                if (!address.has_value()) {
                    set_exception("guest heap exhausted while pinning a jstring");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                for (std::size_t index = 0; index < units.size(); ++index) {
                    if (!memory_.write_u16(GuestAddress32{address->value() + static_cast<std::uint32_t>(index * 2U)}, units[index])) {
                        (void)heap_.free(*address);
                        set_exception("unable to marshal UTF-16 jstring into guest memory");
                        state.r[0] = 0;
                        return GuestHookResult{};
                    }
                }
                (void)memory_.write_u16(GuestAddress32{address->value() + static_cast<std::uint32_t>(units.size() * 2U)}, 0);
                if (state.r[2] != 0) {
                    const std::array<std::byte, 1> copy_flag{std::byte{1}};
                    if (!memory_.write(GuestAddress32{state.r[2]}, copy_flag)) {
                        (void)heap_.free(*address);
                        set_exception("GetStringChars isCopy pointer is unreadable");
                        state.r[0] = 0;
                        return GuestHookResult{};
                    }
                }
                string_pins_.emplace(address->value(), StringPin{*token, *address, PinKind::Utf16String});
                state.r[0] = address->value();
                return GuestHookResult{};
            })
            || !bind(JniIndex::ReleaseStringChars, "ReleaseStringChars", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto pin = string_pins_.find(state.r[2]);
                const auto token = resolve_token(state.r[1]);
                if (pin == string_pins_.end() || pin->second.kind != PinKind::Utf16String || !token.has_value() || pin->second.token != *token) {
                    set_exception("ReleaseStringChars received an unknown guest string buffer");
                } else {
                    (void)heap_.free(pin->second.address);
                    string_pins_.erase(pin);
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewStringUtf, "NewStringUTF", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto value = read_c_string(state.r[1], kMaxJniStringBytes);
                if (!value.has_value()) {
                    set_exception("NewStringUTF received an unreadable or unterminated string");
                    state.r[0] = 0;
                } else {
                    const auto token = create_object(Object{ObjectKind::String, "java/lang/String", *value});
                    state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringUtfLength, "GetStringUTFLength", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                if (object == nullptr || object->kind != ObjectKind::String) {
                    set_exception("GetStringUTFLength received an invalid jstring");
                    state.r[0] = 0;
                } else {
                    state.r[0] = static_cast<std::uint32_t>(object->string_value.size());
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringUtfChars, "GetStringUTFChars", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto token = resolve_token(state.r[1]);
                const auto* object = object_for_handle(state.r[1]);
                if (!token.has_value() || object == nullptr || object->kind != ObjectKind::String) {
                    set_exception("GetStringUTFChars received an invalid jstring");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto address = heap_.malloc(object->string_value.size() + 1U);
                if (!address.has_value()) {
                    set_exception("guest heap exhausted while pinning a jstring");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                std::vector<std::byte> bytes(object->string_value.size() + 1U, std::byte{0});
                for (std::size_t index = 0; index < object->string_value.size(); ++index) {
                    bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(object->string_value[index]));
                }
                if (!memory_.write(*address, bytes)) {
                    (void)heap_.free(*address);
                    set_exception("unable to marshal UTF-8 jstring into guest memory");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                if (state.r[2] != 0) {
                    const std::array<std::byte, 1> copy_flag{std::byte{1}};
                    if (!memory_.write(GuestAddress32{state.r[2]}, copy_flag)) {
                        (void)heap_.free(*address);
                        set_exception("GetStringUTFChars isCopy pointer is unreadable");
                        state.r[0] = 0;
                        return GuestHookResult{};
                    }
                }
                string_pins_.emplace(address->value(), StringPin{*token, *address, PinKind::Utf8String});
                state.r[0] = address->value();
                return GuestHookResult{};
            })
            || !bind(JniIndex::ReleaseStringUtfChars, "ReleaseStringUTFChars", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto pin = string_pins_.find(state.r[2]);
                const auto token = resolve_token(state.r[1]);
                if (pin == string_pins_.end() || pin->second.kind != PinKind::Utf8String || !token.has_value() || pin->second.token != *token) {
                    set_exception("ReleaseStringUTFChars received an unknown guest string buffer");
                } else {
                    (void)heap_.free(pin->second.address);
                    string_pins_.erase(pin);
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetArrayLength, "GetArrayLength", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                if (object == nullptr) {
                    set_exception("GetArrayLength received an invalid array");
                    state.r[0] = 0;
                } else if (object->kind == ObjectKind::ByteArray) {
                    state.r[0] = static_cast<std::uint32_t>(object->bytes.size());
                } else if (object->kind == ObjectKind::IntArray) {
                    state.r[0] = static_cast<std::uint32_t>(object->bytes.size() / 4U);
                } else if (object->kind == ObjectKind::ObjectArray) {
                    state.r[0] = static_cast<std::uint32_t>(object->object_elements.size());
                } else {
                    set_exception("GetArrayLength received a non-array object");
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewObjectArray, "NewObjectArray", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto length = std::bit_cast<std::int32_t>(state.r[1]);
                const auto class_name = class_name_for_handle(state.r[2]);
                if (length < 0 || static_cast<std::size_t>(length) > kMaxJniArrayElements || class_name.empty()) {
                    set_exception("NewObjectArray received invalid length or component class");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto initial = resolve_token(state.r[3]);
                if (!initial.has_value()) {
                    set_exception("NewObjectArray received a stale initial element");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                Object object{ObjectKind::ObjectArray, "[L" + class_name + ";"};
                object.object_elements.resize(static_cast<std::size_t>(length), *initial);
                const auto token = create_object(std::move(object));
                state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetObjectArrayElement, "GetObjectArrayElement", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                auto* object = object_for_handle(state.r[1]);
                const auto index = std::bit_cast<std::int32_t>(state.r[2]);
                if (object == nullptr || object->kind != ObjectKind::ObjectArray || index < 0
                    || static_cast<std::size_t>(index) >= object->object_elements.size()) {
                    set_exception("GetObjectArrayElement received an invalid array or index");
                    state.r[0] = 0;
                } else {
                    state.r[0] = create_local_ref(object->object_elements[static_cast<std::size_t>(index)]).value_or(0);
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::SetObjectArrayElement, "SetObjectArrayElement", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                auto* object = object_for_handle(state.r[1]);
                const auto index = std::bit_cast<std::int32_t>(state.r[2]);
                if (object == nullptr || object->kind != ObjectKind::ObjectArray || index < 0
                    || static_cast<std::size_t>(index) >= object->object_elements.size()
                    || !resolve_token(state.r[3]).has_value()) {
                    set_exception("SetObjectArrayElement received an invalid array, index, or value");
                } else {
                    const auto value = resolve_token(state.r[3]);
                    if (!value.has_value()) {
                        set_exception("SetObjectArrayElement received a stale element reference");
                    } else {
                        object->object_elements[static_cast<std::size_t>(index)] = *value;
                    }
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewByteArray, "NewByteArray", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto length = std::bit_cast<std::int32_t>(state.r[1]);
                if (length < 0 || static_cast<std::size_t>(length) > kMaxJniArrayElements) {
                    set_exception("NewByteArray length is outside the supported range");
                    state.r[0] = 0;
                } else {
                    Object object{ObjectKind::ByteArray, "[B"};
                    object.bytes.resize(static_cast<std::size_t>(length));
                    const auto token = create_object(std::move(object));
                    state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewIntArray, "NewIntArray", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto length = std::bit_cast<std::int32_t>(state.r[1]);
                if (length < 0 || static_cast<std::size_t>(length) > kMaxJniArrayElements / 4U) {
                    set_exception("NewIntArray length is outside the supported range");
                    state.r[0] = 0;
                } else {
                    Object object{ObjectKind::IntArray, "[I"};
                    object.bytes.resize(static_cast<std::size_t>(length) * 4U);
                    const auto token = create_object(std::move(object));
                    state.r[0] = token.has_value() ? create_local_ref(*token).value_or(0) : 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetByteArrayElements, "GetByteArrayElements", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return pin_primitive_array(state, ObjectKind::ByteArray, true);
            })
            || !bind(JniIndex::GetIntArrayElements, "GetIntArrayElements", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return pin_primitive_array(state, ObjectKind::IntArray, true);
            })
            || !bind(JniIndex::ReleaseByteArrayElements, "ReleaseByteArrayElements", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return release_primitive_array(state, ObjectKind::ByteArray);
            })
            || !bind(JniIndex::ReleaseIntArrayElements, "ReleaseIntArrayElements", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return release_primitive_array(state, ObjectKind::IntArray);
            })
            || !bind(JniIndex::GetByteArrayRegion, "GetByteArrayRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return array_region(state, ObjectKind::ByteArray, false);
            })
            || !bind(JniIndex::GetIntArrayRegion, "GetIntArrayRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return array_region(state, ObjectKind::IntArray, false);
            })
            || !bind(JniIndex::SetByteArrayRegion, "SetByteArrayRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return array_region(state, ObjectKind::ByteArray, true);
            })
            || !bind(JniIndex::SetIntArrayRegion, "SetIntArrayRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                return array_region(state, ObjectKind::IntArray, true);
            })
            || !bind(JniIndex::RegisterNatives, "RegisterNatives", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* klass = object_for_handle(state.r[1]);
                const auto count = std::bit_cast<std::int32_t>(state.r[3]);
                if (klass == nullptr || klass->kind != ObjectKind::Class || count < 0 || count > 1024) {
                    set_exception("RegisterNatives received an invalid class or method count");
                    state.r[0] = kJniError;
                    return GuestHookResult{};
                }
                const auto bytes_count = static_cast<std::uint64_t>(count) * 12U;
                if (!memory_.is_accessible(GuestAddress32{state.r[2]}, bytes_count, GuestPermission::Read)) {
                    set_exception("RegisterNatives method table is unreadable");
                    state.r[0] = kJniError;
                    return GuestHookResult{};
                }
                std::vector<NativeMethod> staged;
                staged.reserve(static_cast<std::size_t>(count));
                for (std::int32_t index = 0; index < count; ++index) {
                    const auto entry_address = static_cast<std::uint64_t>(state.r[2]) + static_cast<std::uint64_t>(index) * 12U;
                    std::array<std::byte, 12> entry{};
                    if (!memory_.read(GuestAddress32{static_cast<std::uint32_t>(entry_address)}, entry)) {
                        set_exception("RegisterNatives method table changed during validation");
                        state.r[0] = kJniError;
                        return GuestHookResult{};
                    }
                    const auto name = read_c_string(read_le32(entry, 0), 4096);
                    const auto signature = read_c_string(read_le32(entry, 4), 4096);
                    const auto function = read_le32(entry, 8);
                    if (!name.has_value() || !signature.has_value() || function == 0
                        || !memory_.is_executable(GuestAddress32{function & ~1U})) {
                        set_exception("RegisterNatives contains an invalid name, signature, or guest entry point");
                        state.r[0] = kJniError;
                        return GuestHookResult{};
                    }
                    staged.push_back(NativeMethod{state.r[1], klass->class_name, *name, *signature, function, false});
                }
                for (auto& method : staged) {
                    const auto old = std::find_if(native_methods_.begin(), native_methods_.end(), [&](const NativeMethod& candidate) {
                        return candidate.class_name == method.class_name && candidate.name == method.name
                            && candidate.signature == method.signature;
                    });
                    if (old == native_methods_.end()) native_methods_.push_back(std::move(method));
                    else *old = std::move(method);
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::UnregisterNatives, "UnregisterNatives", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto class_name = class_name_for_handle(state.r[1]);
                if (class_name.empty()) {
                    set_exception("UnregisterNatives received an invalid jclass");
                    state.r[0] = kJniError;
                } else {
                    std::erase_if(native_methods_, [&](const NativeMethod& method) { return method.class_name == class_name; });
                    state.r[0] = 0;
                }
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetJavaVm, "GetJavaVM", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = memory_.write_u32(GuestAddress32{state.r[1]}, java_vm_.value()) ? 0U : kJniError;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringRegion, "GetStringRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                const auto start = std::bit_cast<std::int32_t>(state.r[2]);
                const auto length = std::bit_cast<std::int32_t>(state.r[3]);
                const auto output = stack_argument(state, 0);
                if (object == nullptr || object->kind != ObjectKind::String || start < 0 || length < 0 || !output.has_value()) {
                    set_exception("GetStringRegion received invalid arguments");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto units = utf8_to_utf16(object->string_value);
                if (static_cast<std::size_t>(start) > units.size() || static_cast<std::size_t>(length) > units.size() - static_cast<std::size_t>(start)
                    || !memory_.is_accessible(GuestAddress32{*output}, static_cast<std::uint64_t>(length) * 2U, GuestPermission::Write)) {
                    set_exception("GetStringRegion range or destination is invalid");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                for (std::int32_t index = 0; index < length; ++index) {
                    const auto unit = units[static_cast<std::size_t>(start + index)];
                    (void)memory_.write_u16(GuestAddress32{*output + static_cast<std::uint32_t>(index * 2)}, unit);
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetStringUtfRegion, "GetStringUTFRegion", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto* object = object_for_handle(state.r[1]);
                const auto start = std::bit_cast<std::int32_t>(state.r[2]);
                const auto length = std::bit_cast<std::int32_t>(state.r[3]);
                const auto output = stack_argument(state, 0);
                if (object == nullptr || object->kind != ObjectKind::String || start < 0 || length < 0 || !output.has_value()) {
                    set_exception("GetStringUTFRegion received invalid arguments");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto units = utf8_to_utf16(object->string_value);
                if (static_cast<std::size_t>(start) > units.size() || static_cast<std::size_t>(length) > units.size() - static_cast<std::size_t>(start)) {
                    set_exception("GetStringUTFRegion range is invalid");
                    state.r[0] = 0;
                    return GuestHookResult{};
                }
                const auto text = utf16_to_utf8(std::span<const std::uint16_t>{units}.subspan(
                    static_cast<std::size_t>(start), static_cast<std::size_t>(length)));
                std::vector<std::byte> bytes(text.size());
                for (std::size_t index = 0; index < text.size(); ++index) bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(text[index]));
                if (!memory_.write(GuestAddress32{*output}, bytes)) set_exception("GetStringUTFRegion destination is unwritable");
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::NewWeakGlobalRef, "NewWeakGlobalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = duplicate_reference(state.r[1], ReferenceKind::WeakGlobal).value_or(0);
                return GuestHookResult{};
            })
            || !bind(JniIndex::DeleteWeakGlobalRef, "DeleteWeakGlobalRef", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                if (state.r[1] != 0
                    && (handles_.kind_of(state.r[1]) != ReferenceKind::WeakGlobal || !release_reference(state.r[1]))) {
                    set_exception("DeleteWeakGlobalRef received a stale or non-weak handle");
                }
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind(JniIndex::ExceptionCheck, "ExceptionCheck", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                state.r[0] = pending_exception_.empty() ? 0U : 1U;
                return GuestHookResult{};
            })
            || !bind(JniIndex::GetObjectRefType, "GetObjectRefType", [this, env_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!env_is_valid(state)) return GuestHookResult{};
                const auto kind = handles_.kind_of(state.r[1]);
                if (!kind.has_value()) {
                    state.r[0] = 0;
                } else if (*kind == ReferenceKind::Local) {
                    state.r[0] = 1;
                } else if (*kind == ReferenceKind::Global) {
                    state.r[0] = 2;
                } else {
                    state.r[0] = 3;
                }
                return GuestHookResult{};
            })) {
            return fail("unable to register one or more JNI function thunks");
        }

        std::array<std::uint32_t, kJavaVmTableEntries> vm_entries{};
        const auto bind_vm = [&](VmIndex index, std::string name, Callback callback) -> bool {
            const auto address = register_callback("java_vm." + name, std::move(callback));
            if (!address.has_value()) return false;
            vm_entries[static_cast<std::size_t>(index)] = *address;
            return true;
        };
        const auto vm_is_valid = [this](GuestCpuState32& state) {
            if (state.r[0] == java_vm_.value()) return true;
            set_exception("JavaVM call used an invalid JavaVM pointer");
            state.r[0] = kJniError;
            return false;
        };
        if (!bind_vm(VmIndex::DestroyJavaVm, "DestroyJavaVM", [this, vm_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!vm_is_valid(state)) return GuestHookResult{};
                state.r[0] = kJniError;
                return GuestHookResult{};
            })
            || !bind_vm(VmIndex::AttachCurrentThread, "AttachCurrentThread", [this, vm_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!vm_is_valid(state)) return GuestHookResult{};
                const auto output = state.r[1];
                state.r[0] = memory_.write_u32(GuestAddress32{output}, jni_env_.value()) ? 0U : kJniError;
                return GuestHookResult{};
            })
            || !bind_vm(VmIndex::DetachCurrentThread, "DetachCurrentThread", [this, vm_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!vm_is_valid(state)) return GuestHookResult{};
                state.r[0] = 0;
                return GuestHookResult{};
            })
            || !bind_vm(VmIndex::GetEnv, "GetEnv", [this, vm_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!vm_is_valid(state)) return GuestHookResult{};
                if (state.r[2] != kJniVersion16) {
                    state.r[0] = kJniVersionError;
                    return GuestHookResult{};
                }
                state.r[0] = memory_.write_u32(GuestAddress32{state.r[1]}, jni_env_.value()) ? 0U : kJniError;
                return GuestHookResult{};
            })
            || !bind_vm(VmIndex::AttachCurrentThreadAsDaemon, "AttachCurrentThreadAsDaemon", [this, vm_is_valid](GuestCpuState32& state, GuestMemory&) {
                if (!vm_is_valid(state)) return GuestHookResult{};
                state.r[0] = memory_.write_u32(GuestAddress32{state.r[1]}, jni_env_.value()) ? 0U : kJniError;
                return GuestHookResult{};
            })) {
            return fail("unable to register one or more JavaVM thunks");
        }

        const auto write_entries = [&](GuestAddress32 address, std::span<const std::uint32_t> entries) {
            for (std::size_t index = 0; index < entries.size(); ++index) {
                if (!memory_.write_u32(GuestAddress32{address.value() + static_cast<std::uint32_t>(index * 4U)}, entries[index])) return false;
            }
            return true;
        };
        if (!write_entries(jni_table_, table_entries) || !write_entries(java_vm_table_, vm_entries)
            || !memory_.write_u32(jni_env_, jni_table_.value())
            || !memory_.write_u32(java_vm_, java_vm_table_.value())) {
            return fail("unable to write synthetic JNI/JavaVM tables into guest memory");
        }
        initialized_ = true;
        return true;
    } catch (...) {
        return fail("allocation failure while constructing synthetic JNI/JavaVM tables");
    }
}

void GuestJniBridge::shutdown() noexcept {
    for (auto address = trampoline_allocations_.rbegin(); address != trampoline_allocations_.rend(); ++address) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{*address});
    }
    trampoline_allocations_.clear();
    for (auto address = string_pins_.begin(); address != string_pins_.end(); ++address) (void)heap_.free(address->second.address);
    string_pins_.clear();
    for (const auto address : guest_allocations_) (void)heap_.free(address);
    guest_allocations_.clear();
    handles_.clear(ReferenceKind::Local);
    handles_.clear(ReferenceKind::Global);
    handles_.clear(ReferenceKind::WeakGlobal);
    objects_.clear();
    method_ids_.clear();
    native_methods_.clear();
    local_references_.clear();
    local_frame_bases_.clear();
    pending_exception_.clear();
    jni_table_ = GuestAddress32{0};
    jni_env_ = GuestAddress32{0};
    java_vm_table_ = GuestAddress32{0};
    java_vm_ = GuestAddress32{0};
    initialized_ = false;
}

std::optional<std::uint32_t> GuestJniBridge::resolve_symbol(std::string_view name) const noexcept {
    return trampolines_.resolve_symbol(name);
}

std::optional<GuestAddress32> GuestJniBridge::allocate_guest(std::size_t size) {
    const auto address = heap_.malloc(size);
    if (!address.has_value()) return std::nullopt;
    try {
        guest_allocations_.push_back(*address);
    } catch (...) {
        (void)heap_.free(*address);
        return std::nullopt;
    }
    return address;
}

std::optional<std::uint32_t> GuestJniBridge::register_callback(std::string name, Callback callback) {
    while (next_trampoline_address_ < 0xf2000000U
        && memory_.is_mapped(GuestAddress32{next_trampoline_address_}, 4)) {
        next_trampoline_address_ += 4U;
    }
    if (next_trampoline_address_ >= 0xf2000000U) return std::nullopt;
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) return GuestHookResult{GuestHookAction::Fault, "JNI thunk received an unrelated guest memory space"};
        try {
            return callback(state, memory);
        } catch (...) {
            set_exception("guest JNI thunk ran out of host resources");
            state.r[0] = 0;
            return GuestHookResult{};
        }
    };
    std::string diagnostic;
    if (!trampolines_.register_trampoline(std::move(name), GuestAddress32{address}, std::move(wrapped), &diagnostic)) {
        return std::nullopt;
    }
    try {
        trampoline_allocations_.push_back(address);
    } catch (...) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<std::uint64_t> GuestJniBridge::create_object(Object object) {
    constexpr std::size_t kMaxObjects = 16384;
    if (objects_.size() >= kMaxObjects || next_object_token_ == 0) {
        set_exception("synthetic Java object table is full");
        return std::nullopt;
    }
    const auto token = next_object_token_++;
    objects_.emplace(token, std::move(object));
    return token;
}

std::optional<std::uint32_t> GuestJniBridge::create_local_ref(std::uint64_t token) {
    if (token == 0) return std::uint32_t{0};
    const auto handle = handles_.insert(token, ReferenceKind::Local);
    if (!handle.has_value()) {
        set_exception("JNI local/global reference table is full");
        return std::nullopt;
    }
    try {
        local_references_.push_back(*handle);
    } catch (...) {
        (void)handles_.release(*handle);
        return std::nullopt;
    }
    return handle;
}

std::optional<std::uint64_t> GuestJniBridge::resolve_token(std::uint32_t handle) const {
    const auto token = handles_.resolve(handle);
    if (!token.has_value() || (*token != 0 && !objects_.contains(*token))) return std::nullopt;
    return token;
}

GuestJniBridge::Object* GuestJniBridge::object_for_handle(std::uint32_t handle) noexcept {
    const auto token = handles_.resolve(handle);
    if (!token.has_value() || *token == 0) return nullptr;
    const auto found = objects_.find(*token);
    return found == objects_.end() ? nullptr : &found->second;
}

const GuestJniBridge::Object* GuestJniBridge::object_for_handle(std::uint32_t handle) const noexcept {
    const auto token = handles_.resolve(handle);
    if (!token.has_value() || *token == 0) return nullptr;
    const auto found = objects_.find(*token);
    return found == objects_.end() ? nullptr : &found->second;
}

std::optional<std::string> GuestJniBridge::read_c_string(std::uint32_t address, std::size_t maximum) const {
    std::string output;
    output.reserve(std::min<std::size_t>(maximum, 256));
    for (std::size_t index = 0; index < maximum; ++index) {
        const auto current = static_cast<std::uint64_t>(address) + index;
        if (current > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        const auto byte = memory_.read_u8(GuestAddress32{static_cast<std::uint32_t>(current)});
        if (!byte.has_value()) return std::nullopt;
        if (*byte == 0) return output;
        output.push_back(static_cast<char>(*byte));
    }
    return std::nullopt;
}

std::optional<std::uint32_t> GuestJniBridge::stack_argument(const GuestCpuState32& state, std::size_t index) const noexcept {
    const auto address = static_cast<std::uint64_t>(state.r[13]) + index * sizeof(std::uint32_t);
    if (address > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(address)});
}

std::optional<std::uint32_t> GuestJniBridge::make_method_id(
    std::uint32_t class_handle,
    std::string name,
    std::string signature,
    bool is_static) {
    const auto class_name = class_name_for_handle(class_handle);
    if (class_name.empty() || name.empty() || signature.empty() || next_method_id_ >= 0xf4000000U) return std::nullopt;
    const auto registered = std::find_if(native_methods_.begin(), native_methods_.end(), [&](const NativeMethod& method) {
        return method.class_name == class_name && method.name == name && method.signature == signature;
    });
    const auto guest_function = registered == native_methods_.end() ? 0U : registered->guest_function;
    const auto id = next_method_id_;
    next_method_id_ += 4U;
    method_ids_.emplace(id, NativeMethod{class_handle, class_name, std::move(name), std::move(signature), guest_function, is_static});
    return id;
}

std::string GuestJniBridge::class_name_for_handle(std::uint32_t handle) const {
    const auto* object = object_for_handle(handle);
    if (object == nullptr) return {};
    return object->kind == ObjectKind::Class ? object->class_name : std::string{};
}

GuestHookResult GuestJniBridge::unsupported(GuestCpuState32& state) {
    set_exception("unsupported JNI function-table entry");
    state.r[0] = 0;
    return {};
}

void GuestJniBridge::set_exception(std::string message) {
    if (pending_exception_.empty()) pending_exception_ = std::move(message);
}

std::uint32_t GuestJniBridge::release_reference(std::uint32_t handle) noexcept {
    if (handle == 0) return 0;
    const auto token = handles_.resolve(handle);
    const auto kind = handles_.kind_of(handle);
    if (!token.has_value() || !kind.has_value() || !handles_.release(handle)) return 0;
    if (*kind == ReferenceKind::Local) {
        const auto found = std::find(local_references_.begin(), local_references_.end(), handle);
        if (found != local_references_.end()) local_references_.erase(found);
    }
    return 1;
}

std::optional<std::uint32_t> GuestJniBridge::duplicate_reference(std::uint32_t handle, ReferenceKind kind) {
    if (handle == 0) return std::uint32_t{0};
    const auto token = resolve_token(handle);
    if (!token.has_value()) {
        set_exception("JNI reference operation received a stale handle");
        return std::nullopt;
    }
    if (kind == ReferenceKind::Local) return create_local_ref(*token);
    const auto duplicated = handles_.insert(*token, kind);
    if (!duplicated.has_value()) {
        set_exception("JNI local/global reference table is full");
        return std::nullopt;
    }
    return duplicated;
}

GuestHookResult GuestJniBridge::pin_primitive_array(GuestCpuState32& state, ObjectKind kind, bool copy_flag) {
    const auto token = resolve_token(state.r[1]);
    auto* object = object_for_handle(state.r[1]);
    if (!token.has_value() || object == nullptr || object->kind != kind) {
        set_exception("GetArrayElements received an invalid primitive array");
        state.r[0] = 0;
        return {};
    }
    const auto bytes_to_copy = object->bytes.size();
    const auto address = heap_.malloc(std::max<std::size_t>(bytes_to_copy, 1U));
    if (!address.has_value()) {
        set_exception("guest heap exhausted while pinning a primitive array");
        state.r[0] = 0;
        return {};
    }
    if (!object->bytes.empty() && !memory_.write(*address, object->bytes)) {
        (void)heap_.free(*address);
        set_exception("unable to marshal primitive array into guest memory");
        state.r[0] = 0;
        return {};
    }
    if (copy_flag && state.r[2] != 0) {
        const std::array<std::byte, 1> copied{std::byte{1}};
        if (!memory_.write(GuestAddress32{state.r[2]}, copied)) {
            (void)heap_.free(*address);
            set_exception("GetArrayElements isCopy pointer is unwritable");
            state.r[0] = 0;
            return {};
        }
    }
    const auto pin_kind = kind == ObjectKind::ByteArray ? PinKind::ByteArray : PinKind::IntArray;
    string_pins_.emplace(address->value(), StringPin{*token, *address, pin_kind});
    state.r[0] = address->value();
    return {};
}

GuestHookResult GuestJniBridge::release_primitive_array(GuestCpuState32& state, ObjectKind kind) {
    const auto token = resolve_token(state.r[1]);
    auto* object = object_for_handle(state.r[1]);
    const auto pin = string_pins_.find(state.r[2]);
    const auto expected_kind = kind == ObjectKind::ByteArray ? PinKind::ByteArray : PinKind::IntArray;
    if (!token.has_value() || object == nullptr || object->kind != kind || pin == string_pins_.end()
        || pin->second.kind != expected_kind || pin->second.token != *token) {
        set_exception("ReleaseArrayElements received an unknown or mismatched guest buffer");
        state.r[0] = 0;
        return {};
    }
    const auto mode = state.r[3];
    if (mode != kJniAbort && !object->bytes.empty()) {
        if (!memory_.read(pin->second.address, object->bytes)) {
            set_exception("ReleaseArrayElements guest buffer is unreadable");
            state.r[0] = 0;
            return {};
        }
    }
    if (mode != kJniCommit) {
        (void)heap_.free(pin->second.address);
        string_pins_.erase(pin);
    }
    state.r[0] = 0;
    return {};
}

GuestHookResult GuestJniBridge::array_region(GuestCpuState32& state, ObjectKind kind, bool write_to_array) {
    auto* object = object_for_handle(state.r[1]);
    const auto start = std::bit_cast<std::int32_t>(state.r[2]);
    const auto length = std::bit_cast<std::int32_t>(state.r[3]);
    const auto buffer = stack_argument(state, 0);
    if (object == nullptr || object->kind != kind || start < 0 || length < 0 || !buffer.has_value()) {
        set_exception("array region call received an invalid array, range, or stack argument");
        state.r[0] = 0;
        return {};
    }
    const std::size_t element_size = kind == ObjectKind::IntArray ? 4U : 1U;
    const auto total_elements = object->bytes.size() / element_size;
    const auto start_index = static_cast<std::size_t>(start);
    const auto count = static_cast<std::size_t>(length);
    if (start_index > total_elements || count > total_elements - start_index) {
        set_exception("array region exceeds the guest array bounds");
        state.r[0] = 0;
        return {};
    }
    const auto byte_count = count * element_size;
    const auto offset = start_index * element_size;
    if (write_to_array) {
        if (!memory_.is_accessible(GuestAddress32{*buffer}, byte_count, GuestPermission::Read)) {
            set_exception("array region input buffer is unreadable");
        } else if (byte_count != 0 && !memory_.read(GuestAddress32{*buffer},
            std::span<std::byte>{object->bytes.data() + offset, byte_count})) {
            set_exception("array region input buffer changed during read");
        }
    } else if (!memory_.is_accessible(GuestAddress32{*buffer}, byte_count, GuestPermission::Write)) {
        set_exception("array region output buffer is unwritable");
    } else if (byte_count != 0 && !memory_.write(GuestAddress32{*buffer},
        std::span<const std::byte>{object->bytes.data() + offset, byte_count})) {
        set_exception("array region output buffer changed during write");
    }
    state.r[0] = 0;
    return {};
}

std::vector<std::uint16_t> GuestJniBridge::utf8_to_utf16(std::string_view text) {
    std::vector<std::uint16_t> output;
    output.reserve(text.size());
    for (std::size_t index = 0; index < text.size();) {
        const auto first = static_cast<std::uint8_t>(text[index]);
        std::uint32_t codepoint = 0xfffdU;
        std::size_t count = 1;
        if (first <= 0x7fU) {
            codepoint = first;
        } else if ((first & 0xe0U) == 0xc0U && index + 1U < text.size()) {
            const auto second = static_cast<std::uint8_t>(text[index + 1U]);
            if ((second & 0xc0U) == 0x80U) {
                codepoint = ((first & 0x1fU) << 6U) | (second & 0x3fU);
                count = 2;
                if (codepoint < 0x80U) codepoint = 0xfffdU;
            }
        } else if ((first & 0xf0U) == 0xe0U && index + 2U < text.size()) {
            const auto second = static_cast<std::uint8_t>(text[index + 1U]);
            const auto third = static_cast<std::uint8_t>(text[index + 2U]);
            if ((second & 0xc0U) == 0x80U && (third & 0xc0U) == 0x80U) {
                codepoint = ((first & 0x0fU) << 12U) | ((second & 0x3fU) << 6U) | (third & 0x3fU);
                count = 3;
                if (codepoint < 0x800U || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) codepoint = 0xfffdU;
            }
        } else if ((first & 0xf8U) == 0xf0U && index + 3U < text.size()) {
            const auto second = static_cast<std::uint8_t>(text[index + 1U]);
            const auto third = static_cast<std::uint8_t>(text[index + 2U]);
            const auto fourth = static_cast<std::uint8_t>(text[index + 3U]);
            if ((second & 0xc0U) == 0x80U && (third & 0xc0U) == 0x80U && (fourth & 0xc0U) == 0x80U) {
                codepoint = ((first & 7U) << 18U) | ((second & 0x3fU) << 12U)
                    | ((third & 0x3fU) << 6U) | (fourth & 0x3fU);
                count = 4;
                if (codepoint < 0x10000U || codepoint > 0x10ffffU) codepoint = 0xfffdU;
            }
        }
        index += count;
        if (codepoint <= 0xffffU) {
            output.push_back(static_cast<std::uint16_t>(codepoint));
        } else {
            codepoint -= 0x10000U;
            output.push_back(static_cast<std::uint16_t>(0xd800U | (codepoint >> 10U)));
            output.push_back(static_cast<std::uint16_t>(0xdc00U | (codepoint & 0x3ffU)));
        }
    }
    return output;
}

std::string GuestJniBridge::utf16_to_utf8(std::span<const std::uint16_t> text) {
    std::string output;
    output.reserve(text.size() * 3U);
    for (std::size_t index = 0; index < text.size(); ++index) {
        std::uint32_t codepoint = text[index];
        if (codepoint >= 0xd800U && codepoint <= 0xdbffU && index + 1U < text.size()
            && text[index + 1U] >= 0xdc00U && text[index + 1U] <= 0xdfffU) {
            codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (text[++index] - 0xdc00U);
        } else if (codepoint >= 0xd800U && codepoint <= 0xdfffU) {
            codepoint = 0xfffdU;
        }
        append_utf8(output, codepoint);
    }
    return output;
}

}  // namespace retrobridge::runtime
