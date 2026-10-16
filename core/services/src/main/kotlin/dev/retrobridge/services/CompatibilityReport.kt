package dev.retrobridge.services

/** A capability is reported independently from CPU ISA compatibility. */
enum class CapabilityStatus {
    AVAILABLE,
    PARTIAL,
    NOT_IMPLEMENTED,
    REQUIRES_PRIVILEGED_INTEGRATION,
}

data class Capability(
    val name: String,
    val status: CapabilityStatus,
    val explanation: String,
)

object CompatibilityReport {
    val capabilities: List<Capability> = listOf(
        Capability(
            name = "APK metadata import and native-library preflight",
            status = CapabilityStatus.PARTIAL,
            explanation = "A single APK can be copied and inspected. Bundled .so entries receive bounded ELF class, machine, ET_DYN, and PT_LOAD structural checks; passing does not establish linkability or loadability. Split APK installation is not implemented.",
        ),
        Capability(
            name = "Host-side ARM32 ELF loading and relocation",
            status = CapabilityStatus.PARTIAL,
            explanation = "The host-testable loader maps ELF32/EM_ARM PT_LOAD segments and applies a constrained ARM REL subset. RELA/RELR/Android packed relocations, dependency loading, full dynamic linking, and APK launch integration are unsupported.",
        ),
        Capability(
            name = "ARM32 / Thumb instruction execution",
            status = CapabilityStatus.PARTIAL,
            explanation = "A bounded A32/T16/T32 interpreter, SVC callbacks/trampolines, and selected scalar VFP operations are exercised by synthetic tests and NDK-built fixtures. This is not a complete ARM CPU/DBT; broad ISA, VFP, and NEON coverage is absent.",
        ),
        Capability(
            name = "Guest heap, VFS, and ARM EABI syscalls",
            status = CapabilityStatus.PARTIAL,
            explanation = "The host-testable guest heap, guarded app-private VFS, selected Linux EABI syscalls, and libc/libm/pthread thunks cover a narrow subset. Unknown calls fail explicitly; there is no guest scheduler, broad Bionic surface, or APK runtime wiring.",
        ),
        Capability(
            name = "JNI and JavaVM",
            status = CapabilityStatus.PARTIAL,
            explanation = "A synthetic 32-bit JNI/JavaVM table and selected handles, marshaling, exception, and native-registration operations are tested. This is not ART or general Java execution; the full JNI table, GC, callbacks, and APK integration are absent.",
        ),
        Capability(
            name = "NDK AAssetManager/AAsset subset",
            status = CapabilityStatus.PARTIAL,
            explanation = "A synthetic manager and read/getBuffer/seek/length/close thunks work with caller-registered bounded immutable blobs and generation-checked handles. APK assets, Java AssetManager conversion, asset directories, and APK launch integration are not connected.",
        ),
        Capability(
            name = "Headless ANativeWindow buffer subset",
            status = CapabilityStatus.PARTIAL,
            explanation = "Host-created headless surfaces provide separately mapped RGBA_8888 guest buffers (4 Mi pixels per surface, 4096 pixels per side, 16 MiB total), lock/unlock-and-post, geometry, and acquire/release thunks. Java Surface/ANativeWindow_fromSurface, synchronization fences, transforms, and device display integration are absent.",
        ),
        Capability(
            name = "Synthetic AInputQueue and ALooper subset",
            status = CapabilityStatus.PARTIAL,
            explanation = "A host-injected bounded key/motion queue exposes event accessors and a nonblocking per-runtime ALooper prepare/wake/timeout subset. There is no Android system input source, thread-local looper, input-to-looper attachment, callback dispatch, or file-descriptor polling.",
        ),
        Capability(
            name = "Headless EGL/GLES clear subset",
            status = CapabilityStatus.PARTIAL,
            explanation = "A synthetic EGL display/config/window-surface/context path renders bounded RGBA_8888 color clears and scissor rectangles into guest memory, with swap and basic error/string queries. It has one non-thread-local current context; there are no shaders, draw calls, textures, buffers, framebuffers, pbuffer surfaces, or Android display integration.",
        ),
        Capability(
            name = "OpenSL ES audio",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "No OpenSL ES object/interface or audio-output thunks are implemented.",
        ),
        Capability(
            name = "Guest IPC and Android framework virtualization",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "No end-to-end runtime IPC, Activity/Service proxy, PackageManager/Resources bridge, permission model, or guest lifecycle integration is implemented.",
        ),
        Capability(
            name = "Rootless app-private storage mapping",
            status = CapabilityStatus.PARTIAL,
            explanation = "A guarded path mapper and isolated directory layout exist; this is not a kernel mount namespace or an app sandbox substitute.",
        ),
        Capability(
            name = "Execution of arbitrary guest APKs",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "Launch and stop are not functional. Imported APK code is not started because the loader, translator, bridges, framework, IPC, and security boundary are incomplete.",
        ),
        Capability(
            name = "Host system ABI spoofing / privileged hooks",
            status = CapabilityStatus.REQUIRES_PRIVILEGED_INTEGRATION,
            explanation = "Changing system package visibility, linker behavior, or device-wide ABI support is outside a standard unprivileged app sandbox.",
        ),
    )
}
