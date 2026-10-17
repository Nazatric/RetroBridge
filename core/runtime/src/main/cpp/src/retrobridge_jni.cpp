#if defined(__ANDROID__)

#include "retrobridge/native_execution_session.h"

#include <jni.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <span>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace retrobridge::runtime {
namespace {

constexpr std::uint64_t kMaximumLibraryBytes = 64ULL * 1024ULL * 1024ULL;
std::mutex sessions_mutex;
std::map<jlong, std::shared_ptr<NativeExecutionSession>> sessions;
std::atomic<jlong> next_session_id{1};

void throw_java(JNIEnv* environment, const char* class_name, const std::string& message) {
    if (environment->ExceptionCheck()) return;
    const auto exception_class = environment->FindClass(class_name);
    if (exception_class != nullptr) environment->ThrowNew(exception_class, message.c_str());
}

std::optional<std::string> from_java_string(JNIEnv* environment, jstring value, std::size_t maximum) {
    if (value == nullptr) return std::nullopt;
    const auto length = environment->GetStringUTFLength(value);
    if (length < 0 || static_cast<std::size_t>(length) > maximum) return std::nullopt;
    const auto characters = environment->GetStringUTFChars(value, nullptr);
    if (characters == nullptr) return std::nullopt;
    std::string output(characters, static_cast<std::size_t>(length));
    environment->ReleaseStringUTFChars(value, characters);
    if (output.find('\0') != std::string::npos) return std::nullopt;
    return output;
}

jstring to_java_string(JNIEnv* environment, const std::string& value) {
    return environment->NewStringUTF(value.c_str());
}

jobjectArray to_java_string_array(JNIEnv* environment, const std::vector<std::string>& values) {
    const auto string_class = environment->FindClass("java/lang/String");
    if (string_class == nullptr) return nullptr;
    const auto count = static_cast<jsize>(std::min<std::size_t>(values.size(), 256));
    auto array = environment->NewObjectArray(count, string_class, nullptr);
    if (array == nullptr) return nullptr;
    for (jsize index = 0; index < count; ++index) {
        const auto value = to_java_string(environment, values[static_cast<std::size_t>(index)]);
        if (value == nullptr) return nullptr;
        environment->SetObjectArrayElement(array, index, value);
        environment->DeleteLocalRef(value);
        if (environment->ExceptionCheck()) return nullptr;
    }
    return array;
}

jobject make_metadata(JNIEnv* environment, const NativeLibraryMetadata& metadata) {
    const auto type = environment->FindClass("dev/retrobridge/runtime/NativeLibraryMetadata");
    if (type == nullptr) return nullptr;
    const auto constructor = environment->GetMethodID(
        type, "<init>", "(ZLjava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)V");
    if (constructor == nullptr) return nullptr;
    const auto name = to_java_string(environment, metadata.library_name);
    const auto soname = to_java_string(environment, metadata.soname.empty() ? metadata.library_name : metadata.soname);
    const auto dependencies = to_java_string_array(environment, metadata.needed_libraries);
    const auto diagnostic = to_java_string(environment, metadata.diagnostic);
    if (name == nullptr || soname == nullptr || dependencies == nullptr || diagnostic == nullptr) return nullptr;
    const auto result = environment->NewObject(type, constructor,
        metadata.valid ? JNI_TRUE : JNI_FALSE, name, soname, dependencies, diagnostic);
    environment->DeleteLocalRef(name);
    environment->DeleteLocalRef(soname);
    environment->DeleteLocalRef(dependencies);
    environment->DeleteLocalRef(diagnostic);
    return result;
}

jobject make_load_result(JNIEnv* environment, const NativeLoadResult& result) {
    const auto type = environment->FindClass("dev/retrobridge/runtime/NativeLoadResult");
    if (type == nullptr) return nullptr;
    const auto constructor = environment->GetMethodID(
        type, "<init>", "(ZLjava/lang/String;J[Ljava/lang/String;Ljava/lang/String;)V");
    if (constructor == nullptr) return nullptr;
    const auto name = to_java_string(environment, result.library_name);
    const auto dependencies = to_java_string_array(environment, result.needed_libraries);
    const auto diagnostic = to_java_string(environment, result.diagnostic);
    if (name == nullptr || dependencies == nullptr || diagnostic == nullptr) return nullptr;
    const auto object = environment->NewObject(type, constructor,
        result.loaded ? JNI_TRUE : JNI_FALSE, name, static_cast<jlong>(result.load_address), dependencies, diagnostic);
    environment->DeleteLocalRef(name);
    environment->DeleteLocalRef(dependencies);
    environment->DeleteLocalRef(diagnostic);
    return object;
}

jobject make_execution_report(JNIEnv* environment, const NativeExecutionReport& report) {
    const auto type = environment->FindClass("dev/retrobridge/runtime/NativeExecutionReport");
    if (type == nullptr) return nullptr;
    const auto constructor = environment->GetMethodID(
        type, "<init>", "(ZJIII[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V");
    if (constructor == nullptr) return nullptr;
    const auto loaded = to_java_string_array(environment, report.loaded_libraries);
    const auto entrypoints = to_java_string_array(environment, report.entrypoint_results);
    const auto diagnostics = to_java_string_array(environment, report.diagnostics);
    if (loaded == nullptr || entrypoints == nullptr || diagnostics == nullptr) return nullptr;
    const auto object = environment->NewObject(type, constructor,
        report.success ? JNI_TRUE : JNI_FALSE,
        static_cast<jlong>(report.guest_instructions),
        static_cast<jint>(report.relocation_count),
        static_cast<jint>(report.jni_on_load_version),
        static_cast<jint>(report.registered_native_count), loaded, entrypoints, diagnostics);
    environment->DeleteLocalRef(loaded);
    environment->DeleteLocalRef(entrypoints);
    environment->DeleteLocalRef(diagnostics);
    return object;
}

std::shared_ptr<NativeExecutionSession> find_session(jlong session_id) {
    std::scoped_lock lock(sessions_mutex);
    const auto found = sessions.find(session_id);
    return found == sessions.end() ? nullptr : found->second;
}

bool path_is_within(const std::filesystem::path& root, const std::filesystem::path& path) {
    const auto normalized_root = root.lexically_normal();
    const auto normalized_path = path.lexically_normal();
    const auto relative = normalized_path.lexically_relative(normalized_root);
    if (relative.empty() || relative.is_absolute()) return false;
    for (const auto& segment : relative) {
        if (segment == ".." || segment == ".") return false;
    }
    return true;
}

bool has_symlink_below(const std::filesystem::path& root, const std::filesystem::path& candidate) {
    std::error_code error;
    auto current = root;
    const auto root_status = std::filesystem::symlink_status(current, error);
    if (error || std::filesystem::is_symlink(root_status)) return true;
    const auto relative = candidate.lexically_relative(root);
    if (relative.empty() || relative.is_absolute()) return true;
    for (const auto& segment : relative) {
        if (segment == ".." || segment == ".") return true;
        current /= segment;
        error.clear();
        const auto status = std::filesystem::symlink_status(current, error);
        if (error || std::filesystem::is_symlink(status)) return true;
    }
    return false;
}

bool read_private_library(
    const NativeExecutionSession& session,
    const std::filesystem::path& requested,
    std::vector<std::byte>& output,
    std::string& diagnostic) {
    std::error_code error;
    const auto path = std::filesystem::absolute(requested, error).lexically_normal();
    if (error || !path_is_within(session.native_library_root(), path)) {
        diagnostic = "native library path is outside the app-private extraction root";
        return false;
    }
    if (has_symlink_below(session.app_root(), path)) {
        diagnostic = "native library path crosses a symbolic link or contains a traversal component";
        return false;
    }
    const auto status = std::filesystem::status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        diagnostic = "native library is missing or not a regular file";
        return false;
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaximumLibraryBytes) {
        diagnostic = "native library is empty or exceeds the 64 MiB limit";
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        diagnostic = "native library could not be opened";
        return false;
    }
    output.resize(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(output.data()), static_cast<std::streamsize>(output.size()));
    if (input.gcount() != static_cast<std::streamsize>(output.size()) || input.peek() != std::char_traits<char>::eof()) {
        output.clear();
        diagnostic = "native library changed or could not be read completely";
        return false;
    }
    return true;
}

bool valid_sha256(std::string_view digest) {
    if (digest.size() != 64) return false;
    return std::all_of(digest.begin(), digest.end(), [](unsigned char character) {
        return (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
            || (character >= 'A' && character <= 'F');
    });
}

bool sha256_matches(JNIEnv* environment, std::span<const std::byte> bytes, std::string_view expected) {
    const auto digest_class = environment->FindClass("java/security/MessageDigest");
    if (digest_class == nullptr) return false;
    const auto get_instance = environment->GetStaticMethodID(
        digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    const auto update = environment->GetMethodID(digest_class, "update", "([BII)V");
    const auto finish = environment->GetMethodID(digest_class, "digest", "()[B");
    if (get_instance == nullptr || update == nullptr || finish == nullptr) return false;
    const auto algorithm = environment->NewStringUTF("SHA-256");
    if (algorithm == nullptr) return false;
    const auto digest = environment->CallStaticObjectMethod(digest_class, get_instance, algorithm);
    environment->DeleteLocalRef(algorithm);
    if (digest == nullptr || environment->ExceptionCheck()) return false;
    constexpr jsize kChunkSize = 8192;
    const auto chunk = environment->NewByteArray(kChunkSize);
    if (chunk == nullptr) return false;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = static_cast<jsize>(std::min<std::size_t>(kChunkSize, bytes.size() - offset));
        environment->SetByteArrayRegion(chunk, 0, count,
            reinterpret_cast<const jbyte*>(bytes.data() + offset));
        if (environment->ExceptionCheck()) return false;
        environment->CallVoidMethod(digest, update, chunk, 0, count);
        if (environment->ExceptionCheck()) return false;
        offset += static_cast<std::size_t>(count);
    }
    const auto output = static_cast<jbyteArray>(environment->CallObjectMethod(digest, finish));
    if (output == nullptr || environment->ExceptionCheck()) return false;
    if (environment->GetArrayLength(output) != 32) return false;
    std::array<jbyte, 32> hash{};
    environment->GetByteArrayRegion(output, 0, static_cast<jsize>(hash.size()), hash.data());
    if (environment->ExceptionCheck()) return false;
    constexpr char kHex[] = "0123456789abcdef";
    std::string actual;
    actual.reserve(64);
    for (const auto value : hash) {
        const auto byte = static_cast<unsigned char>(value);
        actual.push_back(kHex[byte >> 4U]);
        actual.push_back(kHex[byte & 0x0fU]);
    }
    return std::equal(actual.begin(), actual.end(), expected.begin(), expected.end(), [](char left, char right) {
        return left == static_cast<char>(std::tolower(static_cast<unsigned char>(right)));
    });
}

}  // namespace
}  // namespace retrobridge::runtime

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) {
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_retrobridge_runtime_RetroBridgeNativeBridge_nativeCreateSession(
    JNIEnv* environment,
    jobject,
    jstring package_name_value,
    jstring internal_directory_value,
    jstring external_data_directory_value,
    jstring obb_directory_value,
    jstring native_library_root_value) {
    using namespace retrobridge::runtime;
    try {
        const auto package_name = from_java_string(environment, package_name_value, 256);
        const auto internal_directory = from_java_string(environment, internal_directory_value, 4096);
        const auto external_directory = from_java_string(environment, external_data_directory_value, 4096);
        const auto obb_directory = from_java_string(environment, obb_directory_value, 4096);
        const auto native_root = from_java_string(environment, native_library_root_value, 4096);
        if (!package_name || !internal_directory || !external_directory || !obb_directory || !native_root) {
            throw_java(environment, "java/lang/IllegalArgumentException", "invalid native session path or package name");
            return 0;
        }
        const std::filesystem::path internal(*internal_directory);
        const auto app_root = internal.parent_path().lexically_normal();
        if (!internal.is_absolute() || internal.lexically_normal() != app_root / "internal"
            || std::filesystem::path(*external_directory).lexically_normal() != app_root / "external" / "data"
            || std::filesystem::path(*obb_directory).lexically_normal() != app_root / "obb"
            || std::filesystem::path(*native_root).lexically_normal() != app_root / "runtime" / "native") {
            throw_java(environment, "java/lang/SecurityException", "native session paths do not match the guest app-private layout");
            return 0;
        }
        auto session = std::make_shared<NativeExecutionSession>(app_root, *package_name);
        std::string diagnostic;
        if (!session->initialize(&diagnostic)) {
            throw_java(environment, "java/lang/IllegalStateException", diagnostic.empty()
                ? "native guest runtime initialization failed" : diagnostic);
            return 0;
        }
        const auto session_id = next_session_id.fetch_add(1);
        if (session_id <= 0) {
            throw_java(environment, "java/lang/IllegalStateException", "native runtime session ID space exhausted");
            return 0;
        }
        {
            std::scoped_lock lock(sessions_mutex);
            sessions.emplace(session_id, std::move(session));
        }
        return session_id;
    } catch (const std::exception& failure) {
        throw_java(environment, "java/lang/IllegalStateException", failure.what());
        return 0;
    } catch (...) {
        throw_java(environment, "java/lang/IllegalStateException", "unexpected native runtime session creation failure");
        return 0;
    }
}

extern "C" JNIEXPORT jobject JNICALL
Java_dev_retrobridge_runtime_RetroBridgeNativeBridge_nativeInspectLibrary(
    JNIEnv* environment,
    jobject,
    jlong session_id,
    jstring library_path_value) {
    using namespace retrobridge::runtime;
    try {
        const auto session = find_session(session_id);
        if (!session) {
            throw_java(environment, "java/lang/IllegalStateException", "native runtime session is not active");
            return nullptr;
        }
        const auto path_text = from_java_string(environment, library_path_value, 4096);
        if (!path_text) {
            throw_java(environment, "java/lang/IllegalArgumentException", "invalid native library path");
            return nullptr;
        }
        std::vector<std::byte> bytes;
        std::string diagnostic;
        NativeLibraryMetadata metadata;
        if (!read_private_library(*session, *path_text, bytes, diagnostic)) {
            metadata.library_name = std::filesystem::path(*path_text).filename().string();
            metadata.diagnostic = std::move(diagnostic);
        } else {
            metadata = session->inspect_library(bytes, std::filesystem::path(*path_text).filename().string());
        }
        return make_metadata(environment, metadata);
    } catch (const std::exception& failure) {
        throw_java(environment, "java/lang/IllegalStateException", failure.what());
        return nullptr;
    } catch (...) {
        throw_java(environment, "java/lang/IllegalStateException", "unexpected native ELF inspection failure");
        return nullptr;
    }
}

extern "C" JNIEXPORT jobject JNICALL
Java_dev_retrobridge_runtime_RetroBridgeNativeBridge_nativeLoadLibrary(
    JNIEnv* environment,
    jobject,
    jlong session_id,
    jstring library_path_value,
    jstring expected_sha256_value) {
    using namespace retrobridge::runtime;
    try {
        const auto session = find_session(session_id);
        if (!session) {
            throw_java(environment, "java/lang/IllegalStateException", "native runtime session is not active");
            return nullptr;
        }
        const auto path_text = from_java_string(environment, library_path_value, 4096);
        const auto expected_sha256 = from_java_string(environment, expected_sha256_value, 64);
        if (!path_text || !expected_sha256 || !valid_sha256(*expected_sha256)) {
            throw_java(environment, "java/lang/IllegalArgumentException", "invalid native library path or SHA-256");
            return nullptr;
        }
        std::vector<std::byte> bytes;
        std::string diagnostic;
        NativeLoadResult result;
        result.library_name = std::filesystem::path(*path_text).filename().string();
        if (!read_private_library(*session, *path_text, bytes, diagnostic)) {
            result.diagnostic = std::move(diagnostic);
        } else if (!sha256_matches(environment, bytes, *expected_sha256)) {
            if (environment->ExceptionCheck()) return nullptr;
            result.diagnostic = "native library SHA-256 does not match the verified extraction digest";
        } else {
            result = session->load_library(bytes, std::filesystem::path(*path_text).filename().string());
        }
        return make_load_result(environment, result);
    } catch (const std::exception& failure) {
        throw_java(environment, "java/lang/IllegalStateException", failure.what());
        return nullptr;
    } catch (...) {
        throw_java(environment, "java/lang/IllegalStateException", "unexpected native ELF load failure");
        return nullptr;
    }
}

extern "C" JNIEXPORT jobject JNICALL
Java_dev_retrobridge_runtime_RetroBridgeNativeBridge_nativeExecute(
    JNIEnv* environment,
    jobject,
    jlong session_id,
    jlong instruction_budget) {
    using namespace retrobridge::runtime;
    try {
        const auto session = find_session(session_id);
        if (!session) {
            throw_java(environment, "java/lang/IllegalStateException", "native runtime session is not active");
            return nullptr;
        }
        const auto budget = instruction_budget <= 0 ? 0U : static_cast<std::uint64_t>(instruction_budget);
        const auto report = session->execute(budget);
        return make_execution_report(environment, report);
    } catch (const std::exception& failure) {
        throw_java(environment, "java/lang/IllegalStateException", failure.what());
        return nullptr;
    } catch (...) {
        throw_java(environment, "java/lang/IllegalStateException", "unexpected ARM32 guest execution failure");
        return nullptr;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_dev_retrobridge_runtime_RetroBridgeNativeBridge_nativeDestroySession(
    JNIEnv* environment,
    jobject,
    jlong session_id) {
    using namespace retrobridge::runtime;
    try {
        std::shared_ptr<NativeExecutionSession> session;
        {
            std::scoped_lock lock(sessions_mutex);
            const auto found = sessions.find(session_id);
            if (found == sessions.end()) return;
            session = std::move(found->second);
            sessions.erase(found);
        }
        session->stop();
    } catch (const std::exception& failure) {
        throw_java(environment, "java/lang/IllegalStateException", failure.what());
    } catch (...) {
        throw_java(environment, "java/lang/IllegalStateException", "unexpected native runtime teardown failure");
    }
}

#endif  // __ANDROID__
