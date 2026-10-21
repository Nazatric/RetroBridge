#include "retrobridge/native_execution_session.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>
#include <limits>
#include <map>
#include <string_view>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::uint32_t kPageSize = 0x1000U;
constexpr std::uint64_t kMaximumInstructionBudget = 100'000'000ULL;
constexpr const char* kReturnThunkDiagnostic = "__retrobridge_native_return__";
// Virtual dependency names only: no host/system DSO is loaded, and imports still require an APK-local image or registered thunk.
constexpr std::array<std::string_view, 12> kPlatformLibraries{
    "libc.so", "libstdc++.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so", "libEGL.so",
    "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libjnigraphics.so",
};

[[nodiscard]] bool valid_library_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 255 || name.find('\0') != std::string_view::npos
        || name.find('/') != std::string_view::npos || name.find('\\') != std::string_view::npos
        || !name.ends_with(".so")) return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '_' || character == '-' || character == '.' || character == '+';
    });
}

[[nodiscard]] std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) noexcept {
    if (alignment == 0 || value > std::numeric_limits<std::uint64_t>::max() - (alignment - 1)) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return (value + alignment - 1) / alignment * alignment;
}

}  // namespace

NativeExecutionSession::NativeExecutionSession(std::filesystem::path app_root, std::string package_name)
    : app_root_(std::filesystem::absolute(std::move(app_root)).lexically_normal()),
      native_library_root_(app_root_ / "runtime" / "native"),
      package_name_(std::move(package_name)),
      memory_(kGuestMemoryLimit),
      heap_(memory_),
      vfs_(app_root_, package_name_),
      syscalls_(memory_, heap_, vfs_),
      engine_(memory_, trampolines_, syscalls_.as_handler()),
      lifecycle_(memory_, engine_, trampolines_),
      bionic_(memory_, heap_, trampolines_, &vfs_),
      jni_(memory_, heap_, trampolines_),
      assets_(memory_, heap_, trampolines_),
      windows_(memory_, heap_, trampolines_),
      input_(memory_, heap_, trampolines_),
      gles_(memory_, heap_, trampolines_, windows_),
      opensl_(memory_, heap_, trampolines_) {}

NativeExecutionSession::~NativeExecutionSession() {
    stop();
}

bool NativeExecutionSession::initialize(std::string* diagnostic) {
    std::scoped_lock lock(mutex_);
    const auto fail = [&](std::string message) {
        if (diagnostic != nullptr) *diagnostic = std::move(message);
        return false;
    };
    if (initialized_) return true;
    if (stopped_) return fail("native execution session has already been stopped");
    if (!vfs_.available()) return fail("app-private guest VFS could not open its storage root");

    std::string detail;
    if (!heap_.initialize(GuestAddress32{0x10000000U}, 16U * 1024U * 1024U, &detail)) {
        return fail("guest heap initialization failed: " + detail);
    }
    if (!memory_.map_zeroed(
            GuestAddress32{kGuestStackBase}, kGuestStackSize,
            GuestPermission::Read | GuestPermission::Write, &detail)) {
        return fail("guest stack mapping failed: " + detail);
    }
    const auto install = [&](bool result, std::string_view component) {
        if (result) return true;
        if (detail.empty()) detail = "install returned false without a diagnostic";
        if (diagnostic != nullptr) *diagnostic = std::string(component) + " initialization failed: " + detail;
        return false;
    };
    if (!install(bionic_.install(&detail), "Bionic thunks")) return false;
    if (!install(jni_.initialize(&detail), "synthetic JNI")) return false;
    if (!install(assets_.install(&detail), "Android asset thunks")) return false;
    if (!install(windows_.install(&detail), "headless native-window thunks")) return false;
    if (!install(input_.install(&detail), "synthetic Android input thunks")) return false;
    if (!install(gles_.install(&detail), "headless EGL/GLES thunks")) return false;
    if (!install(opensl_.install(&detail), "synthetic OpenSL ES thunks")) return false;

    cpu_state_ = GuestCpuState32{};
    cpu_state_.r[13] = kGuestStackBase + kGuestStackSize - 16U;
    initialized_ = true;
    if (diagnostic != nullptr) diagnostic->clear();
    return true;
}

NativeLibraryMetadata NativeExecutionSession::inspect_library(
    std::span<const std::byte> file,
    std::string library_name) const {
    NativeLibraryMetadata result;
    result.library_name = std::move(library_name);
    if (!valid_library_name(result.library_name)) {
        result.diagnostic = "native library filename is invalid";
        return result;
    }
    if (file.empty() || file.size() > kMaximumLibraryBytes) {
        result.diagnostic = "native library is empty or exceeds the 64 MiB per-library limit";
        return result;
    }
    auto parsed = Elf32Image::parse(file, result.library_name, package_name_);
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&parsed)) {
        result.diagnostic = diagnostic->format();
        return result;
    }
    const auto& image = std::get<Elf32Image>(parsed);
    if (image.type() != 3U) {
        result.diagnostic = "native runtime accepts ET_DYN shared libraries only";
        return result;
    }
    result.valid = true;
    result.soname = image.soname().value_or(result.library_name);
    result.needed_libraries = image.needed_libraries();
    return result;
}

NativeLoadResult NativeExecutionSession::load_library(
    std::span<const std::byte> file,
    std::string library_name) {
    std::scoped_lock lock(mutex_);
    NativeLoadResult result;
    result.library_name = library_name;
    if (!initialized_ || stopped_) {
        result.diagnostic = "native execution session is not active";
        return result;
    }
    if (executed_) {
        result.diagnostic = "libraries cannot be added after execution has started";
        return result;
    }
    if (images_.size() >= kMaximumLibraries) {
        result.diagnostic = "native library count exceeds the 32-library session limit";
        return result;
    }
    if (file.empty() || file.size() > kMaximumLibraryBytes
        || loaded_file_bytes_ > kMaximumTotalLibraryBytes - file.size()) {
        result.diagnostic = "native library bytes exceed the configured per-library or session limit";
        return result;
    }
    const auto metadata = inspect_library(file, library_name);
    if (!metadata.valid) {
        result.diagnostic = metadata.diagnostic;
        return result;
    }
    for (const auto& existing : images_) {
        if (existing.image.name == library_name
            || (existing.image.soname.has_value() && *existing.image.soname == library_name)) {
            result.diagnostic = "duplicate native library name: " + library_name;
            return result;
        }
    }

    std::uint64_t maximum_virtual_end = 0;
    const auto parsed = Elf32Image::parse(file, library_name, package_name_);
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&parsed)) {
        result.diagnostic = diagnostic->format();
        return result;
    }
    for (const auto& segment : std::get<Elf32Image>(parsed).segments()) {
        if (segment.type != 1U) continue;
        maximum_virtual_end = std::max(
            maximum_virtual_end,
            static_cast<std::uint64_t>(segment.virtual_address) + segment.memory_size);
    }
    const auto bias = align_up(next_load_bias_, kPageSize);
    const auto image_end = bias + maximum_virtual_end;
    if (bias > 0x5f000000ULL || image_end > 0x5f000000ULL || maximum_virtual_end == 0) {
        result.diagnostic = "guest shared-library address space limit reached";
        return result;
    }

    Elf32LoadOptions options;
    options.load_bias = static_cast<std::uint32_t>(bias);
    options.maximum_symbols = 200'000;
    options.maximum_relocations = 400'000;
    auto loaded = Elf32Loader::load(file, memory_, options, library_name, package_name_);
    if (const auto* diagnostic = std::get_if<ElfDiagnostic>(&loaded)) {
        result.diagnostic = diagnostic->format();
        return result;
    }
    auto image = std::get<Elf32LoadedImage>(std::move(loaded));
    result.loaded = true;
    result.library_name = image.soname.value_or(image.name);
    result.load_address = image.load_bias;
    result.needed_libraries = image.needed_libraries;
    images_.push_back(Library{std::move(image), file.size()});
    loaded_file_bytes_ += file.size();

    const auto next = align_up(image_end, kPageSize) + kPageSize;
    if (next > 0x5f000000ULL) next_load_bias_ = 0x5f000000ULL;
    else next_load_bias_ = next;
    return result;
}

std::vector<std::size_t> NativeExecutionSession::dependency_order(std::vector<std::string>& diagnostics) const {
    std::map<std::string, std::size_t, std::less<>> by_name;
    for (std::size_t index = 0; index < images_.size(); ++index) {
        const auto& image = images_[index].image;
        if (!by_name.emplace(image.name, index).second) {
            diagnostics.push_back("duplicate loaded library name: " + image.name);
            return {};
        }
        if (image.soname.has_value()) {
            const auto [position, inserted] = by_name.emplace(*image.soname, index);
            if (!inserted && position->second != index) {
                diagnostics.push_back("duplicate loaded library SONAME: " + *image.soname);
                return {};
            }
        }
    }

    std::vector<std::uint8_t> marks(images_.size(), 0);
    std::vector<std::size_t> order;
    order.reserve(images_.size());
    std::function<bool(std::size_t)> visit = [&](std::size_t index) {
        if (marks[index] == 2) return true;
        if (marks[index] == 1) return true; // Cyclic DT_NEEDED graphs are loaded as a deterministic SCC.
        marks[index] = 1;
        for (const auto& dependency : images_[index].image.needed_libraries) {
            const auto found = by_name.find(dependency);
            if (found == by_name.end()) {
                if (!supported_platform_library(dependency)) {
                    diagnostics.push_back(images_[index].image.name + " requires unavailable library " + dependency);
                    return false;
                }
                continue;
            }
            if (!visit(found->second)) return false;
        }
        marks[index] = 2;
        order.push_back(index);
        return true;
    };
    for (std::size_t index = 0; index < images_.size(); ++index) {
        if (marks[index] == 0 && !visit(index)) return {};
    }
    return order;
}

bool NativeExecutionSession::supported_platform_library(std::string_view name) const noexcept {
    return std::find(kPlatformLibraries.begin(), kPlatformLibraries.end(), name) != kPlatformLibraries.end();
}

std::optional<std::uint32_t> NativeExecutionSession::resolve_symbol(
    std::string_view name,
    std::size_t importing_image,
    const std::vector<std::size_t>& order) const noexcept {
    for (const auto index : order) {
        if (index == importing_image) continue;
        if (const auto address = images_[index].image.lookup_symbol(name); address.has_value()) return address;
    }
    if (const auto data = bionic_.resolve_data_symbol(name); data.has_value()) return data->value();
    if (const auto address = bionic_.resolve_guest_symbol(name); address.has_value()) return address;
    if (const auto address = jni_.resolve_symbol(name); address.has_value()) return address;
    if (const auto address = assets_.resolve_symbol(name); address.has_value()) return address;
    if (const auto address = windows_.resolve_symbol(name); address.has_value()) return address;
    if (const auto address = input_.resolve_symbol(name); address.has_value()) return address;
    if (const auto address = gles_.resolve_symbol(name); address.has_value()) return address;
    if (const auto address = opensl_.resolve_symbol(name); address.has_value()) return address;
    return trampolines_.resolve_symbol(name);
}

ExecutionResult NativeExecutionSession::invoke_guest_function(
    GuestAddress32 function,
    std::uint64_t instruction_budget,
    std::uint32_t first_argument,
    std::uint32_t second_argument,
    std::uint32_t& return_value,
    std::string_view label) {
    if (instruction_budget == 0) {
        return {ExecutionStatus::BudgetExhausted, 0, "guest execution instruction budget exhausted before " + std::string(label)};
    }
    std::optional<GuestAddress32> return_address;
    for (std::uint32_t index = 0; index < 256; ++index) {
        const auto normalized = 0xfffffff0U - index * 16U;
        if (memory_.is_mapped(GuestAddress32{normalized}, 1)) continue;
        const auto name = "__retrobridge.native.return." + std::to_string(index);
        if (trampolines_.register_trampoline(name, GuestAddress32{normalized | 1U},
                [](GuestCpuState32&, GuestMemory&) {
                    return GuestHookResult{GuestHookAction::Stop, kReturnThunkDiagnostic};
                })) {
            return_address = GuestAddress32{normalized | 1U};
            break;
        }
    }
    if (!return_address.has_value()) {
        return {ExecutionStatus::BackendUnavailable, 0, "no guest address is available for a native return thunk"};
    }
    struct ReturnThunk final {
        GuestTrampolineRegistry& registry;
        GuestAddress32 address;
        ~ReturnThunk() { (void)registry.unregister_trampoline(address); }
    } thunk{trampolines_, *return_address};

    cpu_state_ = GuestCpuState32{};
    cpu_state_.r[0] = first_argument;
    cpu_state_.r[1] = second_argument;
    cpu_state_.r[13] = kGuestStackBase + kGuestStackSize - 16U;
    cpu_state_.r[14] = return_address->value();
    auto result = engine_.run(cpu_state_, function, instruction_budget);
    if (result.status != ExecutionStatus::Completed) return result;
    if (result.diagnostic != kReturnThunkDiagnostic) {
        return {ExecutionStatus::GuestFault, result.guest_instructions,
            "guest function " + std::string(label) + " stopped before returning"
                + (result.diagnostic.empty() ? std::string{} : ": " + result.diagnostic)};
    }
    return_value = cpu_state_.r[0];
    return result;
}

std::uint64_t NativeExecutionSession::remaining_budget(std::uint64_t budget) const noexcept {
    return budget > instructions_executed_ ? budget - instructions_executed_ : 0;
}

void NativeExecutionSession::append_diagnostic(NativeExecutionReport& report, std::string diagnostic) const {
    if (report.diagnostics.size() < 128 && diagnostic.size() > 512) diagnostic.resize(512);
    if (report.diagnostics.size() < 128) report.diagnostics.push_back(std::move(diagnostic));
}

NativeExecutionReport NativeExecutionSession::execute(std::uint64_t instruction_budget) {
    std::scoped_lock lock(mutex_);
    NativeExecutionReport report;
    if (!initialized_ || stopped_) {
        report.diagnostics.push_back("native execution session is not active");
        return report;
    }
    if (executed_) {
        report.diagnostics.push_back("native execution session has already run its lifecycle");
        return report;
    }
    executed_ = true;
    instructions_executed_ = 0;
    if (instruction_budget == 0) {
        report.diagnostics.push_back("guest instruction budget must be greater than zero");
        return report;
    }
    instruction_budget = std::min(instruction_budget, kMaximumInstructionBudget);
    if (images_.empty()) {
        report.diagnostics.push_back("APK contains no supported ARM32 native libraries");
        return report;
    }

    std::vector<std::string> order_diagnostics;
    const auto order = dependency_order(order_diagnostics);
    if (!order_diagnostics.empty() || order.size() != images_.size()) {
        report.diagnostics = std::move(order_diagnostics);
        if (report.diagnostics.empty()) report.diagnostics.push_back("native dependency ordering failed");
        return report;
    }
    for (const auto index : order) report.loaded_libraries.push_back(images_[index].image.name);

    for (const auto index : order) {
        const auto resolver = [this, index, &order](std::string_view symbol) {
            return resolve_symbol(symbol, index, order);
        };
        if (const auto diagnostic = Elf32Loader::relocate(images_[index].image, memory_, resolver); diagnostic.has_value()) {
            append_diagnostic(report, diagnostic->format());
            return report;
        }
        const auto relocation_count = std::count_if(
            images_[index].image.relocations.begin(), images_[index].image.relocations.end(),
            [](const Elf32Relocation& relocation) { return relocation.type != ArmRelocationType::None; });
        report.relocation_count += static_cast<std::uint32_t>(relocation_count);
    }

    cpu_state_ = GuestCpuState32{};
    cpu_state_.r[13] = kGuestStackBase + kGuestStackSize - 16U;
    for (const auto index : order) {
        auto result = lifecycle_.run_constructors(images_[index].image, cpu_state_, remaining_budget(instruction_budget));
        report.guest_instructions += result.guest_instructions;
        instructions_executed_ += result.guest_instructions;
        if (result.guest_instructions != 0) guest_code_started_ = true;
        if (result.status != ExecutionStatus::Completed) {
            append_diagnostic(report, images_[index].image.name + " constructors failed: " + result.diagnostic);
            return report;
        }
        initialized_image_order_.push_back(index);
    }

    for (const auto index : order) {
        auto& image = images_[index].image;
        const auto on_load = image.lookup_symbol("JNI_OnLoad");
        if (!on_load.has_value()) continue;
        std::uint32_t returned_version = 0;
        auto result = invoke_guest_function(
            GuestAddress32{*on_load}, remaining_budget(instruction_budget), jni_.java_vm_address().value(), 0,
            returned_version, image.name + "!JNI_OnLoad");
        report.guest_instructions += result.guest_instructions;
        instructions_executed_ += result.guest_instructions;
        if (result.guest_instructions != 0) guest_code_started_ = true;
        if (result.status != ExecutionStatus::Completed) {
            append_diagnostic(report, image.name + " JNI_OnLoad failed: " + result.diagnostic);
            return report;
        }
        const bool supported_version = returned_version == 0x00010002U
            || returned_version == 0x00010004U || returned_version == 0x00010006U;
        report.jni_on_load_version = static_cast<std::int32_t>(returned_version);
        report.entrypoint_results.push_back(image.name + "!JNI_OnLoad => " + std::to_string(returned_version));
        if (!supported_version) {
            append_diagnostic(report, image.name + " JNI_OnLoad returned unsupported JNI version "
                + std::to_string(returned_version));
            return report;
        }
        if (!jni_.pending_exception().empty()) {
            append_diagnostic(report, image.name + " JNI_OnLoad left a pending exception: " + jni_.pending_exception());
            return report;
        }
    }
    report.registered_native_count = static_cast<std::uint32_t>(jni_.registered_native_count());

    constexpr std::array<std::string_view, 3> supported_entrypoints{
        "retrobridge_main", "retrobridge_entrypoint", "main",
    };
    for (const auto index : order) {
        const auto& image = images_[index].image;
        for (const auto entrypoint : supported_entrypoints) {
            const auto function = image.lookup_symbol(entrypoint);
            if (!function.has_value()) continue;
            std::uint32_t returned = 0;
            auto result = invoke_guest_function(
                GuestAddress32{*function}, remaining_budget(instruction_budget), 0, 0,
                returned, image.name + "!" + std::string(entrypoint));
            report.guest_instructions += result.guest_instructions;
            instructions_executed_ += result.guest_instructions;
            if (result.guest_instructions != 0) guest_code_started_ = true;
            if (result.status != ExecutionStatus::Completed) {
                append_diagnostic(report, image.name + "!" + std::string(entrypoint) + " failed: " + result.diagnostic);
                return report;
            }
            report.entrypoint_results.push_back(
                image.name + "!" + std::string(entrypoint) + " => " + std::to_string(returned));
        }
    }

    if (!guest_code_started_) {
        append_diagnostic(report, "no constructor, JNI_OnLoad, or supported native entrypoint executed guest instructions");
        return report;
    }
    report.success = true;
    return report;
}

void NativeExecutionSession::stop() noexcept {
    try {
        std::scoped_lock lock(mutex_);
        if (stopped_) return;
        stopped_ = true;
        if (initialized_ && guest_code_started_) {
            std::uint64_t remaining = 1'000'000;
            for (auto iterator = initialized_image_order_.rbegin();
                 iterator != initialized_image_order_.rend() && remaining > 0; ++iterator) {
                const auto result = lifecycle_.run_destructors(images_[*iterator].image, cpu_state_, remaining);
                remaining -= std::min(remaining, result.guest_instructions);
                if (result.status != ExecutionStatus::Completed) break;
            }
        }
    } catch (...) {
        // Destructors are best-effort during teardown; no C++ exception crosses JNI destruction.
    }
}

}  // namespace retrobridge::runtime
