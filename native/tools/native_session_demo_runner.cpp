#include "retrobridge/native_execution_session.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <unistd.h>

namespace {

constexpr std::size_t kMaximumDemoLibraryBytes = 64U * 1024U * 1024U;

bool read_library(const std::filesystem::path& path, std::vector<std::byte>& bytes) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaximumDemoLibraryBytes) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    bytes.resize(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return input.gcount() == static_cast<std::streamsize>(bytes.size())
        && input.peek() == std::char_traits<char>::eof();
}

int fail(const std::string& message) {
    std::cerr << "ARM32 native demo session failed: " << message << '\n';
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace retrobridge::runtime;
    if (argc != 2) return fail("usage: retrobridge_native_session_demo_runner <libretrobridge_demo.so>");
    const std::filesystem::path library_path(argv[1]);
    std::vector<std::byte> library_bytes;
    if (!read_library(library_path, library_bytes)) return fail("demo shared object could not be read under the 64 MiB limit");

    const auto root = std::filesystem::temp_directory_path()
        / ("retrobridge-native-demo-" + std::to_string(static_cast<unsigned long long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "internal/files");
    std::filesystem::create_directories(root / "external/data");
    std::filesystem::create_directories(root / "obb");
    std::filesystem::create_directories(root / "runtime/native");

    int result_code = 0;
    {
        NativeExecutionSession session(root, "org.retrobridge.guestdemo");
        std::string diagnostic;
        if (!session.initialize(&diagnostic)) {
            result_code = fail("runtime initialization: " + diagnostic);
        } else {
            const auto loaded = session.load_library(library_bytes, library_path.filename().string());
            if (!loaded.loaded) {
                result_code = fail("library mapping: " + loaded.diagnostic);
            } else {
                const auto report = session.execute(2'000'000);
                if (!report.success) {
                    session.stop();
                    const auto output_path = root / "internal/files/native-demo.txt";
                    std::ifstream output(output_path);
                    const std::string observed_output((std::istreambuf_iterator<char>(output)), std::istreambuf_iterator<char>());
                    result_code = fail("interpreter execution: "
                        + (report.diagnostics.empty() ? std::string("no diagnostic") : report.diagnostics.front())
                        + "; guest VFS output=[" + (observed_output.empty() ? std::string("<empty>") : observed_output) + "]");
                } else {
                    if (report.guest_instructions == 0) result_code = fail("no guest machine instructions were executed");
                    if (report.relocation_count == 0) result_code = fail("the shared object reported no applied relocations");
                    if (report.loaded_libraries.empty()) result_code = fail("the session reported no loaded guest libraries");
                    if (report.jni_on_load_version != 0x00010006) {
                        result_code = fail("JNI_OnLoad did not return JNI_VERSION_1_6");
                    }
                    const auto entrypoint = std::find_if(report.entrypoint_results.begin(), report.entrypoint_results.end(),
                        [](const std::string& value) { return value.find("!retrobridge_main => ") != std::string::npos; });
                    if (entrypoint == report.entrypoint_results.end()) {
                        result_code = fail("session reported no retrobridge_main result; entrypoints=["
                            + (report.entrypoint_results.empty() ? std::string("<empty>") : report.entrypoint_results.front()) + "]");
                    } else if (entrypoint->find("!retrobridge_main => 42") == std::string::npos) {
                        result_code = fail("retrobridge_main returned an unexpected result: " + *entrypoint);
                    }
                    const auto output_path = root / "internal/files/native-demo.txt";
                    std::ifstream output(output_path);
                    const std::string before_stop((std::istreambuf_iterator<char>(output)), std::istreambuf_iterator<char>());
                    const auto constructor = before_stop.find("constructor\n");
                    const auto on_load = before_stop.find("JNI_OnLoad\n");
                    const auto entry = before_stop.find("entrypoint\n");
                    if (constructor == std::string::npos || on_load == std::string::npos || entry == std::string::npos
                        || before_stop.find("math-failed") != std::string::npos
                        || !(constructor < on_load && on_load < entry)) {
                        result_code = fail("constructor, JNI_OnLoad, entrypoint, or VFS file-write order is incorrect; guest VFS output=["
                            + (before_stop.empty() ? std::string("<empty>") : before_stop) + "]");
                    }
                    session.stop();
                    std::ifstream final_output(output_path);
                    const std::string after_stop((std::istreambuf_iterator<char>(final_output)), std::istreambuf_iterator<char>());
                    const auto destructor = after_stop.find("destructor\n");
                    if (destructor == std::string::npos || entry == std::string::npos || entry >= destructor) {
                        result_code = fail("guest destructor did not write after the selected entrypoint; guest VFS output=["
                            + (after_stop.empty() ? std::string("<empty>") : after_stop) + "]");
                    }
                    if (result_code == 0) {
                        std::cout << "{\"success\":true,\"guest_instructions\":" << report.guest_instructions
                            << ",\"relocations\":" << report.relocation_count
                            << ",\"jni_on_load_version\":" << report.jni_on_load_version
                            << ",\"registered_natives\":" << report.registered_native_count
                            << ",\"entrypoint\":\"" << *entrypoint << "\",\"vfs_file\":\"native-demo.txt\"}\n";
                    }
                }
            }
        }
    }
    std::filesystem::remove_all(root);
    return result_code;
}
