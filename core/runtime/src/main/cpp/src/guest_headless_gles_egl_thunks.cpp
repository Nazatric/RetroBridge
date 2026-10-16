#include "retrobridge/guest_headless_gles_egl_thunks.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>
#include <new>
#include <utility>

namespace retrobridge::runtime {
namespace {
constexpr std::uint32_t kEglWindowBit = 0x0004;
constexpr std::uint32_t kEglOpenGles2Bit = 0x0004;
constexpr std::uint32_t kEglContextClientVersion = 0x3098;
constexpr std::uint32_t kEglDraw = 0x3059;
constexpr std::uint32_t kEglRead = 0x305a;
constexpr std::uint32_t kGlScissorTest = GuestHeadlessGlesEglThunks::kGlScissorTest;
constexpr std::uint32_t kGlColorBufferBit = GuestHeadlessGlesEglThunks::kGlColorBufferBit;
constexpr std::uint32_t kGlDepthBufferBit = 0x00000100;
constexpr std::uint32_t kGlStencilBufferBit = 0x00000400;
constexpr std::uint32_t kEglBadAccess = 0x3002;
constexpr std::uint32_t kEglRgbBuffer = 0x308e;
constexpr std::uint32_t kEglNoneValue = GuestHeadlessGlesEglThunks::kEglNone;
}

GuestHeadlessGlesEglThunks::GuestHeadlessGlesEglThunks(
    GuestMemory& memory,
    GuestHeap32& heap,
    GuestTrampolineRegistry& trampolines,
    GuestAndroidWindowThunks& windows)
    : memory_(memory), heap_(heap), trampolines_(trampolines), windows_(windows) {}

GuestHeadlessGlesEglThunks::~GuestHeadlessGlesEglThunks() {
    shutdown();
}

bool GuestHeadlessGlesEglThunks::install(std::string* diagnostic) {
    if (diagnostic != nullptr) diagnostic->clear();
    if (installed_) return true;
    if (!windows_.installed()) {
        if (diagnostic != nullptr) *diagnostic = "headless native-window thunks must be installed first";
        return false;
    }
    const auto display = allocate_handle_cell(kDisplayToken);
    const auto config = allocate_handle_cell(kConfigToken);
    if (!display.has_value() || !config.has_value()) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "guest heap or handle table could not allocate EGL display/config handles";
        return false;
    }
    display_handle_ = *display;
    config_handle_ = *config;
    try {
        const auto add = [&](std::string name, Callback callback) {
            return add_thunk(std::move(name), std::move(callback)).has_value();
        };
        if (!add("eglGetDisplay", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_display(state); })
        || !add("eglInitialize", [this](GuestCpuState32& state, GuestMemory&) { return egl_initialize(state); })
        || !add("eglTerminate", [this](GuestCpuState32& state, GuestMemory&) { return egl_terminate(state); })
        || !add("eglChooseConfig", [this](GuestCpuState32& state, GuestMemory&) { return egl_choose_config(state); })
        || !add("eglGetConfigAttrib", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_config_attrib(state); })
        || !add("eglCreateWindowSurface", [this](GuestCpuState32& state, GuestMemory&) { return egl_create_window_surface(state); })
        || !add("eglCreateContext", [this](GuestCpuState32& state, GuestMemory&) { return egl_create_context(state); })
        || !add("eglMakeCurrent", [this](GuestCpuState32& state, GuestMemory&) { return egl_make_current(state); })
        || !add("eglSwapBuffers", [this](GuestCpuState32& state, GuestMemory&) { return egl_swap_buffers(state); })
        || !add("eglDestroySurface", [this](GuestCpuState32& state, GuestMemory&) { return egl_destroy_surface(state); })
        || !add("eglDestroyContext", [this](GuestCpuState32& state, GuestMemory&) { return egl_destroy_context(state); })
        || !add("eglBindAPI", [this](GuestCpuState32& state, GuestMemory&) { return egl_bind_api(state); })
        || !add("eglGetError", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_error(state); })
        || !add("eglGetCurrentDisplay", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_current_display(state); })
        || !add("eglGetCurrentContext", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_current_context(state); })
        || !add("eglGetCurrentSurface", [this](GuestCpuState32& state, GuestMemory&) { return egl_get_current_surface(state); })
        || !add("glClearColor", [this](GuestCpuState32& state, GuestMemory&) { return gl_clear_color(state); })
        || !add("glClear", [this](GuestCpuState32& state, GuestMemory&) { return gl_clear(state); })
        || !add("glViewport", [this](GuestCpuState32& state, GuestMemory&) { return gl_viewport(state); })
        || !add("glScissor", [this](GuestCpuState32& state, GuestMemory&) { return gl_scissor(state); })
        || !add("glEnable", [this](GuestCpuState32& state, GuestMemory&) { return gl_enable(state); })
        || !add("glDisable", [this](GuestCpuState32& state, GuestMemory&) { return gl_disable(state); })
        || !add("glGetError", [this](GuestCpuState32& state, GuestMemory&) { return gl_get_error(state); })
        || !add("glGetString", [this](GuestCpuState32& state, GuestMemory&) { return gl_get_string(state); })
        || !add("glFlush", [this](GuestCpuState32& state, GuestMemory&) { return gl_flush(state); })
        || !add("glFinish", [this](GuestCpuState32& state, GuestMemory&) { return gl_finish(state); })) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "unable to register a bounded headless EGL/GLES thunk";
            return false;
        }
    } catch (...) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "host allocation failed while registering EGL/GLES thunks";
        return false;
    }
    try {
        const auto add_string = [&](std::uint32_t name, std::string_view value) {
            GuestAddress32 address{0};
            if (!write_c_string(value, address)) return false;
            try {
                const auto [entry, inserted] = gl_strings_.emplace(name, address);
                (void)entry;
                if (!inserted) (void)heap_.free(address);
                return inserted;
            } catch (...) {
                (void)heap_.free(address);
                throw;
            }
        };
        if (!add_string(kGlVersion, "OpenGL ES 2.0 RetroBridge clear-only subset")
            || !add_string(kGlVendor, "RetroBridge")
            || !add_string(kGlRenderer, "RetroBridge software clear renderer")
            || !add_string(kGlExtensions, "")) {
            shutdown();
            if (diagnostic != nullptr) *diagnostic = "guest heap could not allocate GLES query strings";
            return false;
        }
    } catch (...) {
        shutdown();
        if (diagnostic != nullptr) *diagnostic = "host allocation failed while preparing GLES query strings";
        return false;
    }
    installed_ = true;
    if (diagnostic != nullptr) diagnostic->clear();
    return true;
}

void GuestHeadlessGlesEglThunks::shutdown() noexcept {
    for (const auto address : trampoline_addresses_) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
    }
    trampoline_addresses_.clear();
    symbols_.clear();
    {
        std::lock_guard lock(state_mutex_);
        for (const auto& [token, surface] : surfaces_) {
            (void)token;
            windows_.release_headless_window(surface.native_window);
        }
        surfaces_.clear();
        contexts_.clear();
        current_context_token_ = 0;
        current_surface_token_ = 0;
        initialized_ = false;
        display_handle_ = 0;
        config_handle_ = 0;
        external_handles_.clear();
        for (const auto cell : handle_cells_) (void)heap_.free(cell);
        handle_cells_.clear();
        for (const auto& [name, address] : gl_strings_) {
            (void)name;
            (void)heap_.free(address);
        }
        gl_strings_.clear();
    }
    handles_.clear(ReferenceKind::Global);
    egl_error_ = kEglSuccess;
    bound_api_ = kEglOpenGlesApi;
    installed_ = false;
}

std::optional<std::uint32_t> GuestHeadlessGlesEglThunks::resolve_symbol(std::string_view name) const noexcept {
    const auto found = symbols_.find(name);
    if (found == symbols_.end()) return std::nullopt;
    return found->second;
}

std::optional<std::uint32_t> GuestHeadlessGlesEglThunks::add_thunk(std::string name, Callback callback) {
    if (symbols_.contains(name) || next_trampoline_address_ > std::numeric_limits<std::uint32_t>::max() - 4U) {
        return std::nullopt;
    }
    const auto address = next_trampoline_address_;
    next_trampoline_address_ += 4U;
    auto wrapped = [this, callback = std::move(callback)](GuestCpuState32& state, GuestMemory& memory) {
        if (&memory != &memory_) {
            return GuestHookResult{GuestHookAction::Fault, "EGL/GLES thunk received unrelated guest memory"};
        }
        try {
            return callback(state, memory);
        } catch (...) {
            return GuestHookResult{GuestHookAction::Fault, "EGL/GLES thunk failed while handling guest input"};
        }
    };
    if (!trampolines_.register_trampoline(name, GuestAddress32{address}, std::move(wrapped))) return std::nullopt;
    try {
        const auto [symbol, inserted] = symbols_.emplace(name, address);
        if (!inserted) {
            (void)trampolines_.unregister_trampoline(GuestAddress32{address});
            return std::nullopt;
        }
        try {
            trampoline_addresses_.push_back(address);
        } catch (...) {
            symbols_.erase(symbol);
            throw;
        }
    } catch (...) {
        (void)trampolines_.unregister_trampoline(GuestAddress32{address});
        return std::nullopt;
    }
    return address;
}

std::optional<std::uint32_t> GuestHeadlessGlesEglThunks::allocate_handle_cell(std::uint64_t token) {
    if (handle_cells_.size() >= kMaxHandleCells) return std::nullopt;
    const auto table_handle = handles_.insert(token, ReferenceKind::Global);
    if (!table_handle.has_value() || *table_handle == 0) return std::nullopt;
    const auto cell = heap_.malloc(2U * sizeof(std::uint32_t));
    if (!cell.has_value()) {
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    const auto field = cell->checked_add(sizeof(std::uint32_t));
    if (!field.has_value() || !memory_.write_u32(*cell, kHandleMagic)
        || !memory_.write_u32(*field, *table_handle)) {
        (void)heap_.free(*cell);
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    try {
        const auto [alias, inserted] = external_handles_.emplace(cell->value(), *table_handle);
        (void)alias;
        if (!inserted) {
            (void)heap_.free(*cell);
            (void)handles_.release(*table_handle);
            return std::nullopt;
        }
        handle_cells_.push_back(*cell);
    } catch (...) {
        external_handles_.erase(cell->value());
        (void)heap_.free(*cell);
        (void)handles_.release(*table_handle);
        return std::nullopt;
    }
    return cell->value();
}

std::optional<std::uint64_t> GuestHeadlessGlesEglThunks::resolve_token(std::uint32_t handle) const noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return std::nullopt;
    const auto kind = handles_.kind_of(alias->second);
    if (!kind.has_value() || *kind != ReferenceKind::Global) return std::nullopt;
    return handles_.resolve(alias->second);
}

bool GuestHeadlessGlesEglThunks::is_display(std::uint32_t handle) const noexcept {
    const auto token = resolve_token(handle);
    return token.has_value() && *token == kDisplayToken && handle == display_handle_;
}

bool GuestHeadlessGlesEglThunks::is_config(std::uint32_t handle) const noexcept {
    const auto token = resolve_token(handle);
    return token.has_value() && *token == kConfigToken && handle == config_handle_;
}

GuestHeadlessGlesEglThunks::Surface* GuestHeadlessGlesEglThunks::find_surface(std::uint32_t handle) noexcept {
    const auto token = resolve_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = surfaces_.find(*token);
    return found == surfaces_.end() ? nullptr : &found->second;
}

const GuestHeadlessGlesEglThunks::Surface* GuestHeadlessGlesEglThunks::find_surface(std::uint32_t handle) const noexcept {
    const auto token = resolve_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = surfaces_.find(*token);
    return found == surfaces_.end() ? nullptr : &found->second;
}

GuestHeadlessGlesEglThunks::Context* GuestHeadlessGlesEglThunks::find_context(std::uint32_t handle) noexcept {
    const auto token = resolve_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = contexts_.find(*token);
    return found == contexts_.end() ? nullptr : &found->second;
}

const GuestHeadlessGlesEglThunks::Context* GuestHeadlessGlesEglThunks::find_context(std::uint32_t handle) const noexcept {
    const auto token = resolve_token(handle);
    if (!token.has_value()) return nullptr;
    const auto found = contexts_.find(*token);
    return found == contexts_.end() ? nullptr : &found->second;
}

void GuestHeadlessGlesEglThunks::invalidate_handle(std::uint32_t handle) noexcept {
    const auto alias = external_handles_.find(handle);
    if (alias == external_handles_.end()) return;
    (void)handles_.release(alias->second);
    external_handles_.erase(alias);
    (void)memory_.write_u32(GuestAddress32{handle}, 0U);
}

std::optional<std::uint32_t> GuestHeadlessGlesEglThunks::stack_argument(
    const GuestCpuState32& state,
    std::size_t index) const noexcept {
    const auto address = static_cast<std::uint64_t>(state.r[13]) + index * sizeof(std::uint32_t);
    if (address > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(address)});
}

void GuestHeadlessGlesEglThunks::set_egl_error(std::uint32_t error) noexcept {
    if (egl_error_ == kEglSuccess) egl_error_ = error;
}

void GuestHeadlessGlesEglThunks::set_gl_error(Context& context, std::uint32_t error) noexcept {
    if (context.error == kGlNoError) context.error = error;
}

bool GuestHeadlessGlesEglThunks::write_c_string(std::string_view value, GuestAddress32& output) {
    std::vector<std::byte> bytes(value.size() + 1U, std::byte{0});
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = static_cast<std::byte>(static_cast<unsigned char>(value[index]));
    }
    const auto allocation = heap_.malloc(bytes.size());
    if (!allocation.has_value()) return false;
    if (!memory_.write(*allocation, bytes)) {
        (void)heap_.free(*allocation);
        return false;
    }
    output = *allocation;
    return true;
}


bool GuestHeadlessGlesEglThunks::supported_config_attributes(std::uint32_t address, bool& matches) const noexcept {
    matches = true;
    if (address == 0) return true;
    for (std::size_t pair = 0; pair < 64; ++pair) {
        const auto key_address = static_cast<std::uint64_t>(address) + pair * 2U * sizeof(std::uint32_t);
        const auto value_address = key_address + sizeof(std::uint32_t);
        if (value_address > std::numeric_limits<std::uint32_t>::max()) return false;
        const auto key = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(key_address)});
        if (!key.has_value()) return false;
        if (*key == kEglNoneValue) return true;
        const auto value = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(value_address)});
        if (!value.has_value()) return false;
        const auto requested = std::bit_cast<std::int32_t>(*value);
        if (requested == -1) continue;
        switch (*key) {
            case 0x3020: // EGL_BUFFER_SIZE
                matches = matches && requested <= 32;
                break;
            case 0x3021: // EGL_ALPHA_SIZE
            case 0x3022: // EGL_BLUE_SIZE
            case 0x3023: // EGL_GREEN_SIZE
            case 0x3024: // EGL_RED_SIZE
                matches = matches && requested <= 8;
                break;
            case 0x3025: // EGL_DEPTH_SIZE
            case 0x3026: // EGL_STENCIL_SIZE
            case 0x3031: // EGL_SAMPLES
            case 0x3032: // EGL_SAMPLE_BUFFERS
                matches = matches && requested == 0;
                break;
            case 0x3028: // EGL_CONFIG_ID
                matches = matches && requested == 1;
                break;
            case 0x3029: // EGL_LEVEL
                matches = matches && requested == 0;
                break;
            case 0x302d: // EGL_NATIVE_RENDERABLE
                matches = matches && requested == 0;
                break;
            case 0x302e: // EGL_NATIVE_VISUAL_ID
                matches = matches && requested == 1;
                break;
            case 0x302f: // EGL_NATIVE_VISUAL_TYPE
                matches = matches && requested == 0;
                break;
            case 0x3033: // EGL_SURFACE_TYPE
                matches = matches && static_cast<std::uint32_t>(requested) == kEglWindowBit;
                break;
            case 0x3034: // EGL_TRANSPARENT_TYPE
                matches = matches && static_cast<std::uint32_t>(requested) == kEglNoneValue;
                break;
            case 0x303b: // EGL_MIN_SWAP_INTERVAL
                matches = matches && requested <= 0;
                break;
            case 0x303c: // EGL_MAX_SWAP_INTERVAL
                matches = matches && requested >= 1;
                break;
            case 0x303d: // EGL_LUMINANCE_SIZE
            case 0x303e: // EGL_ALPHA_MASK_SIZE
                matches = matches && requested == 0;
                break;
            case 0x303f: // EGL_COLOR_BUFFER_TYPE
                matches = matches && static_cast<std::uint32_t>(requested) == kEglRgbBuffer;
                break;
            case 0x3040: // EGL_RENDERABLE_TYPE
            case 0x3042: // EGL_CONFORMANT
                matches = matches && static_cast<std::uint32_t>(requested) == kEglOpenGles2Bit;
                break;
            default:
                return false;
        }
    }
    return false;
}

bool GuestHeadlessGlesEglThunks::supported_surface_attributes(std::uint32_t address) const noexcept {
    if (address == 0) return true;
    for (std::size_t index = 0; index < 32; ++index) {
        const auto current = static_cast<std::uint64_t>(address) + index * sizeof(std::uint32_t);
        if (current > std::numeric_limits<std::uint32_t>::max()) return false;
        const auto value = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(current)});
        if (!value.has_value()) return false;
        if (*value == kEglNoneValue) return true;
        return false;
    }
    return false;
}

bool GuestHeadlessGlesEglThunks::supported_context_attributes(std::uint32_t address) const noexcept {
    if (address == 0) return false; // EGL defaults to ES 1.x when the client-version attribute is omitted.
    bool explicit_es2 = false;
    for (std::size_t pair = 0; pair < 16; ++pair) {
        const auto key_address = static_cast<std::uint64_t>(address) + pair * 2U * sizeof(std::uint32_t);
        const auto value_address = key_address + sizeof(std::uint32_t);
        if (value_address > std::numeric_limits<std::uint32_t>::max()) return false;
        const auto key = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(key_address)});
        if (!key.has_value()) return false;
        if (*key == kEglNoneValue) return explicit_es2;
        const auto value = memory_.read_u32(GuestAddress32{static_cast<std::uint32_t>(value_address)});
        if (!value.has_value() || *key != kEglContextClientVersion || *value != 2U) return false;
        explicit_es2 = true;
    }
    return false;
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_display(GuestCpuState32& state) {
    const auto native_display = state.r[0];
    std::lock_guard lock(state_mutex_);
    if (!installed_ || native_display != 0) {
        set_egl_error(kEglBadParameter);
        state.r[0] = 0;
        return {};
    }
    state.r[0] = display_handle_;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_initialize(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto major = state.r[1];
    const auto minor = state.r[2];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    if ((major != 0 && !memory_.is_accessible(GuestAddress32{major}, sizeof(std::uint32_t), GuestPermission::Write))
        || (minor != 0 && !memory_.is_accessible(GuestAddress32{minor}, sizeof(std::uint32_t), GuestPermission::Write))) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    if ((major != 0 && !memory_.write_u32(GuestAddress32{major}, 1U))
        || (minor != 0 && !memory_.write_u32(GuestAddress32{minor}, 4U))) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    initialized_ = true;
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_terminate(GuestCpuState32& state) {
    const auto display = state.r[0];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    for (const auto& [token, surface] : surfaces_) {
        (void)token;
        windows_.release_headless_window(surface.native_window);
        invalidate_handle(surface.guest_handle);
    }
    for (const auto& [token, context] : contexts_) {
        (void)token;
        invalidate_handle(context.guest_handle);
    }
    surfaces_.clear();
    contexts_.clear();
    current_context_token_ = 0;
    current_surface_token_ = 0;
    initialized_ = false;
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_choose_config(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto attributes = state.r[1];
    const auto configs = state.r[2];
    const auto requested_count = std::bit_cast<std::int32_t>(state.r[3]);
    const auto count_address = stack_argument(state, 0);
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!count_address.has_value() || *count_address == 0 || requested_count < 0
        || !memory_.is_accessible(GuestAddress32{*count_address}, sizeof(std::uint32_t), GuestPermission::Write)) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    bool matches = false;
    if (!supported_config_attributes(attributes, matches)) {
        set_egl_error(kEglBadAttribute);
        state.r[0] = kEglFalse;
        return {};
    }
    if (matches && configs != 0 && requested_count > 0
        && !memory_.is_accessible(GuestAddress32{configs}, sizeof(std::uint32_t), GuestPermission::Write)) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto count = matches ? 1U : 0U;
    if (!memory_.write_u32(GuestAddress32{*count_address}, count)
        || (matches && configs != 0 && requested_count > 0
            && !memory_.write_u32(GuestAddress32{configs}, config_handle_))) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_config_attrib(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto config = state.r[1];
    const auto attribute = state.r[2];
    const auto output = state.r[3];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!is_config(config)) {
        set_egl_error(kEglBadConfig);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        state.r[0] = kEglFalse;
        return {};
    }
    if (output == 0 || !memory_.is_accessible(GuestAddress32{output}, sizeof(std::uint32_t), GuestPermission::Write)) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    std::optional<std::uint32_t> value;
    switch (attribute) {
        case 0x3020: value = 32; break; // EGL_BUFFER_SIZE
        case 0x3021: value = 8; break; // EGL_ALPHA_SIZE
        case 0x3022: value = 8; break; // EGL_BLUE_SIZE
        case 0x3023: value = 8; break; // EGL_GREEN_SIZE
        case 0x3024: value = 8; break; // EGL_RED_SIZE
        case 0x3025: value = 0; break; // EGL_DEPTH_SIZE
        case 0x3026: value = 0; break; // EGL_STENCIL_SIZE
        case 0x3028: value = 1; break; // EGL_CONFIG_ID
        case 0x3029: value = 0; break; // EGL_LEVEL
        case 0x302a: value = 0; break; // EGL_MAX_PBUFFER_HEIGHT
        case 0x302b: value = 0; break; // EGL_MAX_PBUFFER_PIXELS
        case 0x302c: value = 0; break; // EGL_MAX_PBUFFER_WIDTH
        case 0x302d: value = 0; break; // EGL_NATIVE_RENDERABLE
        case 0x302e: value = 1; break; // EGL_NATIVE_VISUAL_ID
        case 0x302f: value = 0; break; // EGL_NATIVE_VISUAL_TYPE
        case 0x3031: value = 0; break; // EGL_SAMPLES
        case 0x3032: value = 0; break; // EGL_SAMPLE_BUFFERS
        case 0x3033: value = kEglWindowBit; break; // EGL_SURFACE_TYPE
        case 0x3034: value = kEglNoneValue; break; // EGL_TRANSPARENT_TYPE
        case 0x303b: value = 0; break; // EGL_MIN_SWAP_INTERVAL
        case 0x303c: value = 1; break; // EGL_MAX_SWAP_INTERVAL
        case 0x303d: value = 0; break; // EGL_LUMINANCE_SIZE
        case 0x303e: value = 0; break; // EGL_ALPHA_MASK_SIZE
        case 0x303f: value = kEglRgbBuffer; break; // EGL_COLOR_BUFFER_TYPE
        case 0x3040: value = kEglOpenGles2Bit; break; // EGL_RENDERABLE_TYPE
        case 0x3042: value = kEglOpenGles2Bit; break; // EGL_CONFORMANT
        default: break;
    }
    if (!value.has_value()) {
        set_egl_error(kEglBadAttribute);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!memory_.write_u32(GuestAddress32{output}, *value)) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_create_window_surface(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto config = state.r[1];
    const auto native_window = state.r[2];
    const auto attributes = state.r[3];
    state.r[0] = 0;
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        return {};
    }
    if (!is_config(config)) {
        set_egl_error(kEglBadConfig);
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        return {};
    }
    if (!supported_surface_attributes(attributes)) {
        set_egl_error(kEglBadAttribute);
        return {};
    }
    const auto snapshot = windows_.snapshot_window(native_window);
    if (!snapshot.has_value() || snapshot->format != GuestAndroidWindowThunks::kRgba8888
        || snapshot->locked || snapshot->width == 0 || snapshot->height == 0) {
        set_egl_error(kEglBadNativeWindow);
        return {};
    }
    if (surfaces_.size() >= kMaxSurfaces
        || next_object_token_ == 0 || next_object_token_ == std::numeric_limits<std::uint64_t>::max()) {
        set_egl_error(kEglBadAlloc);
        return {};
    }
    if (!windows_.retain_headless_window(native_window)) {
        set_egl_error(kEglBadNativeWindow);
        return {};
    }
    const auto token = next_object_token_++;
    const auto handle = allocate_handle_cell(token);
    if (!handle.has_value()) {
        windows_.release_headless_window(native_window);
        set_egl_error(kEglBadAlloc);
        return {};
    }
    try {
        const auto [surface, inserted] = surfaces_.emplace(
            token, Surface{token, *handle, native_window, kConfigToken});
        (void)surface;
        if (!inserted) {
            windows_.release_headless_window(native_window);
            invalidate_handle(*handle);
            set_egl_error(kEglBadAlloc);
            return {};
        }
    } catch (...) {
        windows_.release_headless_window(native_window);
        invalidate_handle(*handle);
        set_egl_error(kEglBadAlloc);
        return {};
    }
    state.r[0] = *handle;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_create_context(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto config = state.r[1];
    const auto share_context = state.r[2];
    const auto attributes = state.r[3];
    state.r[0] = 0;
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        return {};
    }
    if (!is_config(config)) {
        set_egl_error(kEglBadConfig);
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        return {};
    }
    if (bound_api_ != kEglOpenGlesApi || share_context != 0) {
        set_egl_error(kEglBadMatch);
        return {};
    }
    if (!supported_context_attributes(attributes)) {
        set_egl_error(kEglBadAttribute);
        return {};
    }
    if (contexts_.size() >= kMaxContexts
        || next_object_token_ == 0 || next_object_token_ == std::numeric_limits<std::uint64_t>::max()) {
        set_egl_error(kEglBadAlloc);
        return {};
    }
    const auto token = next_object_token_++;
    const auto handle = allocate_handle_cell(token);
    if (!handle.has_value()) {
        set_egl_error(kEglBadAlloc);
        return {};
    }
    try {
        const auto [context, inserted] = contexts_.emplace(
            token, Context{token, *handle, kConfigToken});
        (void)context;
        if (!inserted) {
            invalidate_handle(*handle);
            set_egl_error(kEglBadAlloc);
            return {};
        }
    } catch (...) {
        invalidate_handle(*handle);
        set_egl_error(kEglBadAlloc);
        return {};
    }
    state.r[0] = *handle;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_make_current(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto draw_handle = state.r[1];
    const auto read_handle = state.r[2];
    const auto context_handle = state.r[3];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        state.r[0] = kEglFalse;
        return {};
    }
    if (draw_handle == 0 && read_handle == 0 && context_handle == 0) {
        current_context_token_ = 0;
        current_surface_token_ = 0;
        state.r[0] = kEglTrue;
        return {};
    }
    const auto context_token = resolve_token(context_handle);
    if (!context_token.has_value() || !contexts_.contains(*context_token)) {
        set_egl_error(kEglBadContext);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto draw_token = resolve_token(draw_handle);
    const auto read_token = resolve_token(read_handle);
    if (!draw_token.has_value() || !read_token.has_value()
        || !surfaces_.contains(*draw_token) || !surfaces_.contains(*read_token)) {
        set_egl_error(kEglBadSurface);
        state.r[0] = kEglFalse;
        return {};
    }
    if (draw_handle != read_handle
        || contexts_.at(*context_token).config_token != surfaces_.at(*draw_token).config_token) {
        set_egl_error(kEglBadMatch);
        state.r[0] = kEglFalse;
        return {};
    }
    current_context_token_ = *context_token;
    current_surface_token_ = *draw_token;
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_swap_buffers(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto surface_handle = state.r[1];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!initialized_) {
        set_egl_error(kEglNotInitialized);
        state.r[0] = kEglFalse;
        return {};
    }
    auto* surface = find_surface(surface_handle);
    if (surface == nullptr) {
        set_egl_error(kEglBadSurface);
        state.r[0] = kEglFalse;
        return {};
    }
    if (surface->token != current_surface_token_) {
        set_egl_error(kEglBadMatch);
        state.r[0] = kEglFalse;
        return {};
    }
    if (!windows_.post_headless_frame(surface->native_window)) {
        set_egl_error(kEglBadAccess);
        state.r[0] = kEglFalse;
        return {};
    }
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_destroy_surface(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto surface_handle = state.r[1];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto token = resolve_token(surface_handle);
    if (!token.has_value()) {
        set_egl_error(kEglBadSurface);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto found = surfaces_.find(*token);
    if (found == surfaces_.end()) {
        set_egl_error(kEglBadSurface);
        state.r[0] = kEglFalse;
        return {};
    }
    windows_.release_headless_window(found->second.native_window);
    if (current_surface_token_ == *token) {
        current_context_token_ = 0;
        current_surface_token_ = 0;
    }
    const auto handle = found->second.guest_handle;
    surfaces_.erase(found);
    invalidate_handle(handle);
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_destroy_context(GuestCpuState32& state) {
    const auto display = state.r[0];
    const auto context_handle = state.r[1];
    std::lock_guard lock(state_mutex_);
    if (!is_display(display)) {
        set_egl_error(kEglBadDisplay);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto token = resolve_token(context_handle);
    if (!token.has_value()) {
        set_egl_error(kEglBadContext);
        state.r[0] = kEglFalse;
        return {};
    }
    const auto found = contexts_.find(*token);
    if (found == contexts_.end()) {
        set_egl_error(kEglBadContext);
        state.r[0] = kEglFalse;
        return {};
    }
    if (current_context_token_ == *token) {
        current_context_token_ = 0;
        current_surface_token_ = 0;
    }
    const auto handle = found->second.guest_handle;
    contexts_.erase(found);
    invalidate_handle(handle);
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_bind_api(GuestCpuState32& state) {
    const auto api = state.r[0];
    std::lock_guard lock(state_mutex_);
    if (api != kEglOpenGlesApi) {
        set_egl_error(kEglBadParameter);
        state.r[0] = kEglFalse;
        return {};
    }
    bound_api_ = api;
    state.r[0] = kEglTrue;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_error(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    state.r[0] = egl_error_;
    egl_error_ = kEglSuccess;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_current_display(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    state.r[0] = current_context_token_ == 0 ? 0U : display_handle_;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_current_context(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto found = contexts_.find(current_context_token_);
    state.r[0] = found == contexts_.end() ? 0U : found->second.guest_handle;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::egl_get_current_surface(GuestCpuState32& state) {
    const auto which = state.r[0];
    std::lock_guard lock(state_mutex_);
    if (which != kEglDraw && which != kEglRead) {
        set_egl_error(kEglBadParameter);
        state.r[0] = 0;
        return {};
    }
    const auto found = surfaces_.find(current_surface_token_);
    state.r[0] = found == surfaces_.end() ? 0U : found->second.guest_handle;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_clear_color(GuestCpuState32& state) {
    const std::array<float, 4> color{
        std::bit_cast<float>(state.r[0]),
        std::bit_cast<float>(state.r[1]),
        std::bit_cast<float>(state.r[2]),
        std::bit_cast<float>(state.r[3]),
    };
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    if (!std::all_of(color.begin(), color.end(), [](float value) { return std::isfinite(value); })) {
        set_gl_error(context->second, kGlInvalidValue);
        return {};
    }
    for (std::size_t channel = 0; channel < color.size(); ++channel) {
        context->second.clear_color[channel] = std::clamp(color[channel], 0.0F, 1.0F);
    }
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_clear(GuestCpuState32& state) {
    const auto mask = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    constexpr auto valid_clear_mask = kGlColorBufferBit | kGlDepthBufferBit | kGlStencilBufferBit;
    if ((mask & ~valid_clear_mask) != 0) {
        set_gl_error(context->second, kGlInvalidValue);
        return {};
    }
    // This config has no depth or stencil attachment, so those valid clear bits are no-ops.
    if ((mask & kGlColorBufferBit) == 0) return {};
    const auto surface = surfaces_.find(current_surface_token_);
    if (surface == surfaces_.end()) {
        set_gl_error(context->second, kGlInvalidFramebufferOperation);
        return {};
    }
    const auto window = windows_.snapshot_window(surface->second.native_window);
    if (!window.has_value() || window->locked || window->format != GuestAndroidWindowThunks::kRgba8888
        || window->width == 0 || window->height == 0) {
        set_gl_error(context->second, kGlInvalidFramebufferOperation);
        return {};
    }

    const auto width = static_cast<std::int64_t>(window->width);
    const auto height = static_cast<std::int64_t>(window->height);
    std::int64_t left = 0;
    std::int64_t right = width;
    std::int64_t bottom = 0;
    std::int64_t top = height;
    if (context->second.scissor_enabled) {
        const auto scissor_left = static_cast<std::int64_t>(context->second.scissor[0]);
        const auto scissor_bottom = static_cast<std::int64_t>(context->second.scissor[1]);
        const auto scissor_right = scissor_left + context->second.scissor[2];
        const auto scissor_top = scissor_bottom + context->second.scissor[3];
        left = std::max<std::int64_t>(0, scissor_left);
        right = std::min(width, scissor_right);
        bottom = std::max<std::int64_t>(0, scissor_bottom);
        top = std::min(height, scissor_top);
    }
    if (left >= right || bottom >= top) return {};

    std::array<std::byte, 4> rgba{};
    for (std::size_t channel = 0; channel < rgba.size(); ++channel) {
        const auto quantized = std::lround(context->second.clear_color[channel] * 255.0F);
        rgba[channel] = static_cast<std::byte>(static_cast<std::uint8_t>(quantized));
    }
    const auto row_width = static_cast<std::size_t>(right - left);
    std::vector<std::byte> row;
    try {
        row.resize(row_width * rgba.size());
    } catch (const std::bad_alloc&) {
        set_gl_error(context->second, kGlOutOfMemory);
        return {};
    }
    for (std::size_t pixel = 0; pixel < row_width; ++pixel) {
        std::copy(rgba.begin(), rgba.end(), row.begin() + static_cast<std::ptrdiff_t>(pixel * rgba.size()));
    }
    const auto top_row = height - top;
    const auto bottom_row = height - bottom;
    for (auto row_index = top_row; row_index < bottom_row; ++row_index) {
        const auto pixel_index = static_cast<std::uint64_t>(row_index) * window->width
            + static_cast<std::uint64_t>(left);
        const auto byte_offset = pixel_index * rgba.size();
        const auto address = static_cast<std::uint64_t>(window->pixels.value()) + byte_offset;
        if (address > std::numeric_limits<std::uint32_t>::max()
            || !memory_.write(GuestAddress32{static_cast<std::uint32_t>(address)}, row)) {
            set_gl_error(context->second, kGlInvalidFramebufferOperation);
            return {};
        }
    }
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_viewport(GuestCpuState32& state) {
    const auto x = std::bit_cast<std::int32_t>(state.r[0]);
    const auto y = std::bit_cast<std::int32_t>(state.r[1]);
    const auto width = std::bit_cast<std::int32_t>(state.r[2]);
    const auto height = std::bit_cast<std::int32_t>(state.r[3]);
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    if (width < 0 || height < 0) {
        set_gl_error(context->second, kGlInvalidValue);
        return {};
    }
    context->second.viewport = {x, y, width, height};
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_scissor(GuestCpuState32& state) {
    const auto x = std::bit_cast<std::int32_t>(state.r[0]);
    const auto y = std::bit_cast<std::int32_t>(state.r[1]);
    const auto width = std::bit_cast<std::int32_t>(state.r[2]);
    const auto height = std::bit_cast<std::int32_t>(state.r[3]);
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    if (width < 0 || height < 0) {
        set_gl_error(context->second, kGlInvalidValue);
        return {};
    }
    context->second.scissor = {x, y, width, height};
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_enable(GuestCpuState32& state) {
    const auto capability = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    if (capability != kGlScissorTest) {
        set_gl_error(context->second, kGlInvalidEnum);
        return {};
    }
    context->second.scissor_enabled = true;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_disable(GuestCpuState32& state) {
    const auto capability = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) return {};
    if (capability != kGlScissorTest) {
        set_gl_error(context->second, kGlInvalidEnum);
        return {};
    }
    context->second.scissor_enabled = false;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_get_error(GuestCpuState32& state) {
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) {
        state.r[0] = kGlNoError;
        return {};
    }
    state.r[0] = context->second.error;
    context->second.error = kGlNoError;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_get_string(GuestCpuState32& state) {
    const auto name = state.r[0];
    std::lock_guard lock(state_mutex_);
    const auto context = contexts_.find(current_context_token_);
    if (context == contexts_.end()) {
        state.r[0] = 0;
        return {};
    }
    const auto string = gl_strings_.find(name);
    if (string == gl_strings_.end()) {
        set_gl_error(context->second, kGlInvalidEnum);
        state.r[0] = 0;
        return {};
    }
    state.r[0] = string->second.value();
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_flush(GuestCpuState32& state) {
    (void)state;
    return {};
}

GuestHookResult GuestHeadlessGlesEglThunks::gl_finish(GuestCpuState32& state) {
    (void)state;
    return {};
}

}  // namespace retrobridge::runtime
