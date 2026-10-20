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
            name = "ARM32 ELF loading and relocation",
            status = CapabilityStatus.PARTIAL,
            explanation = "The runtime maps app-private ELF32/EM_ARM ET_DYN libraries in DT_NEEDED order and applies a constrained ARM REL subset against loaded images and explicit thunks. RELA/RELR/Android packed relocations, broad linker namespaces, and many imports remain unsupported; ELF preflight is not proof that an APK will launch.",
        ),
        Capability(
            name = "ARM32 / Thumb instruction execution",
            status = CapabilityStatus.PARTIAL,
            explanation = "A bounded A32/T16/T32 interpreter, SVC callbacks/trampolines, and selected scalar VFP operations are exercised by synthetic tests and NDK-built fixtures. This is not a complete ARM CPU/DBT; broad ISA, VFP, and NEON coverage is absent.",
        ),
        Capability(
            name = "Guest heap, VFS, and ARM EABI syscalls",
            status = CapabilityStatus.PARTIAL,
            explanation = "The bounded runtime session wires a guest heap, guarded app-private VFS, selected Linux EABI syscalls, and partial libc/libm/pthread thunks plus guest-heap C++ new/delete and single-threaded static guards (up to 4,096 in progress). libstdc++.so is a virtual dependency backed only by explicit thunks; unresolved imports fail during relocation. There is no guest scheduler, exception unwinding, C++ atexit registry, or complete Bionic/C++ runtime surface.",
        ),
        Capability(
            name = "JNI and JavaVM",
            status = CapabilityStatus.PARTIAL,
            explanation = "A synthetic 32-bit JNI/JavaVM table and selected handles, marshaling, exception, and native-registration operations are wired into native-library sessions. This is not ART or general Java execution; most JNI entries, GC, host Java callbacks, and Activity integration are absent.",
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
            name = "OpenSL ES PCM buffer-queue subset",
            status = CapabilityStatus.PARTIAL,
            explanation = "Synthetic Android OpenSL ES 1.0.1-compatible objects expose guest vtables, Android interface IDs, the engine-interface query entrypoints, a shared reference-counted engine (32 live objects maximum), play state, and bounded PCM queues (32 buffers per player, 1 MiB per buffer, 8 MiB aggregate) with explicit host draining. The Android thread-safety/loss-of-control options are accepted as no-ops. There is no Android audio sink, real-time playback/recording, guest callback dispatch, volume/effects, or APK launch integration.",
        ),
        Capability(
            name = "Guest IPC and Android framework virtualization",
            status = CapabilityStatus.PARTIAL,
            explanation = "A private Messenger endpoint verifies the APK identity, extracts SHA-256-checked ARM32 libraries, and starts/stops an instruction-budgeted interpreter session with constructor, JNI_OnLoad, and selected exported-entrypoint reporting. It does not launch an Android Activity or virtualize Activity/Service, PackageManager/Resources, permissions, Java execution, or general guest lifecycle callbacks.",
        ),
        Capability(
            name = "Rootless app-private storage mapping",
            status = CapabilityStatus.PARTIAL,
            explanation = "A guarded path mapper and isolated directory layout exist; this is not a kernel mount namespace or an app sandbox substitute.",
        ),
        Capability(
            name = "Execution of arbitrary guest APKs",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "The UI can launch only selected ARM32 native libraries whose dependencies, relocations, imports, constructors, and supported entrypoints fit the implemented interpreter/thunk subset. APK Java bytecode, arbitrary application entrypoints, full Android framework behavior, and unsupported native APIs are not executed; this is not general APK compatibility or a security boundary for untrusted apps.",
        ),
        Capability(
            name = "Host system ABI spoofing / privileged hooks",
            status = CapabilityStatus.REQUIRES_PRIVILEGED_INTEGRATION,
            explanation = "Changing system package visibility, linker behavior, or device-wide ABI support is outside a standard unprivileged app sandbox.",
        ),
    )
}
