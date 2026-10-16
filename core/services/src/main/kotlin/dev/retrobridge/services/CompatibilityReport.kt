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
            name = "APK metadata import",
            status = CapabilityStatus.PARTIAL,
            explanation = "Single APKs can be copied into private storage and inspected; split APK installation is not implemented.",
        ),
        Capability(
            name = "ARM32 ELF metadata validation",
            status = CapabilityStatus.AVAILABLE,
            explanation = "The host-side validator checks ELF32/EM_ARM headers, load segments, and DT_NEEDED strings; it does not map or load code.",
        ),
        Capability(
            name = "ARM32 / Thumb instruction execution",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "No Dynarmic or other translator is integrated. ARM32 instructions are never executed by this prototype.",
        ),
        Capability(
            name = "ARM32 Android linker and Bionic",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "Relocations, guest libc, syscall translation, TLS, and loader execution are not implemented.",
        ),
        Capability(
            name = "JNI and Android framework virtualization",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "There is no synthetic 32-bit JNIEnv or complete Activity, Service, PackageManager, or Resources bridge.",
        ),
        Capability(
            name = "Rootless app-private storage mapping",
            status = CapabilityStatus.PARTIAL,
            explanation = "A guarded path mapper and isolated directory layout exist; this is not a kernel mount namespace or an app sandbox substitute.",
        ),
        Capability(
            name = "Execution of arbitrary guest APKs",
            status = CapabilityStatus.NOT_IMPLEMENTED,
            explanation = "Launch is deliberately disabled until the loader, translator, ABI-safe bridges, and security boundary are implemented and audited.",
        ),
        Capability(
            name = "Host system ABI spoofing / privileged hooks",
            status = CapabilityStatus.REQUIRES_PRIVILEGED_INTEGRATION,
            explanation = "Changing system package visibility, linker behavior, or device-wide ABI support is outside a standard unprivileged app sandbox.",
        ),
    )
}
