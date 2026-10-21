package dev.retrobridge.manager

import kotlinx.serialization.Serializable

@Serializable
enum class GuestAppState {
    IMPORTED,
    VALIDATING,
    READY,
    STARTING,
    RUNNING,
    PAUSED,
    STOPPING,
    STOPPED,
    CRASHED,
    UNSUPPORTED,
}

@Serializable
enum class AttachmentState {
    NOT_PROVIDED,
    IMPORTED,
    INVALID,
}

@Serializable
data class CompatibilityOverrides(
    val values: Map<String, String> = emptyMap(),
)

@Serializable
data class LaunchRecord(
    val startedAtEpochMs: Long,
    val endedAtEpochMs: Long? = null,
    val outcome: String,
    val diagnostic: String? = null,
)

@Serializable
data class GuestDiagnostic(
    val timestampEpochMs: Long,
    val severity: String,
    val component: String,
    val message: String,
    val detail: String? = null,
    val code: String = "UNCLASSIFIED",
    val category: String = "GENERAL",
    val operation: String = "UNKNOWN",
    val guestId: String? = null,
    val packageName: String? = null,
    val library: String? = null,
    val file: String? = null,
    val symbol: String? = null,
    val guestAddress: String? = null,
    val instruction: String? = null,
    val nextAction: String? = null,
    val occurrences: Int = 1,
    val lastOccurredAtEpochMs: Long? = null,
) {
    fun validate() {
        require(timestampEpochMs >= 0) { "Diagnostic timestamp cannot be negative" }
        require(severity.isNotBlank() && severity.length <= 16) { "Diagnostic severity is invalid" }
        require(component.isNotBlank() && component.length <= 128) { "Diagnostic component is invalid" }
        require(message.isNotBlank() && message.length <= 512) { "Diagnostic summary is invalid" }
        require(detail == null || detail.length <= 4_096) { "Diagnostic detail exceeds its bound" }
        require(CODE_PATTERN.matches(code) && CODE_PATTERN.matches(category) && CODE_PATTERN.matches(operation)) {
            "Diagnostic code/category/operation must use stable uppercase identifiers"
        }
        require(guestId == null || guestId.length <= 64) { "Diagnostic guest ID exceeds its bound" }
        require(packageName == null || packageName.length <= 255) { "Diagnostic package name exceeds its bound" }
        require(library == null || library.length <= 255) { "Diagnostic library name exceeds its bound" }
        require(file == null || file.length <= 1_024) { "Diagnostic file path exceeds its bound" }
        require(symbol == null || symbol.length <= 256) { "Diagnostic symbol exceeds its bound" }
        require(guestAddress == null || guestAddress.length <= 32) { "Diagnostic guest address exceeds its bound" }
        require(instruction == null || instruction.length <= 64) { "Diagnostic instruction exceeds its bound" }
        require(nextAction == null || nextAction.length <= 1_024) { "Diagnostic next action exceeds its bound" }
        require(occurrences in 1..1_000_000) { "Diagnostic occurrence count is outside its bound" }
        require(lastOccurredAtEpochMs == null || lastOccurredAtEpochMs >= timestampEpochMs) {
            "Last diagnostic occurrence cannot precede the first occurrence"
        }
    }

    companion object {
        private val CODE_PATTERN = Regex("[A-Z0-9_]{1,64}")
    }
}

/** Durable metadata for one imported guest. Paths are relative to RetroBridge's private root. */
@Serializable
data class GuestAppRecord(
    val id: String,
    val packageName: String,
    val displayName: String,
    val versionName: String? = null,
    val versionCode: Long = 0,
    val minSdk: Int? = null,
    val targetSdk: Int? = null,
    val originalApkPath: String,
    val sha256: String,
    val splitApkPaths: List<String> = emptyList(),
    val guestAbis: List<String> = emptyList(),
    val nativeLibraries: Map<String, List<String>> = emptyMap(),
    val isolatedRoot: String,
    val dataArchiveState: AttachmentState = AttachmentState.NOT_PROVIDED,
    val obbState: AttachmentState = AttachmentState.NOT_PROVIDED,
    val obbFiles: List<String> = emptyList(),
    val compatibilityOverrides: CompatibilityOverrides = CompatibilityOverrides(),
    val launchHistory: List<LaunchRecord> = emptyList(),
    val crashDumpPaths: List<String> = emptyList(),
    val diagnostics: List<GuestDiagnostic> = emptyList(),
    val state: GuestAppState = GuestAppState.IMPORTED,
    val createdAtEpochMs: Long,
    val updatedAtEpochMs: Long = createdAtEpochMs,
) {
    fun validate() {
        require(APP_ID_PATTERN.matches(id)) { "Invalid guest application ID" }
        require(PACKAGE_PATTERN.matches(packageName)) { "Invalid Android package name: $packageName" }
        require(displayName.isNotBlank()) { "Application display name cannot be blank" }
        require(SHA256_PATTERN.matches(sha256)) { "APK SHA-256 must be 64 hexadecimal characters" }
        require(minSdk == null || minSdk >= 1) { "minSdk must be positive when present" }
        require(targetSdk == null || targetSdk >= 1) { "targetSdk must be positive when present" }
        require(versionCode >= 0) { "versionCode cannot be negative" }
        requireRelativePath(originalApkPath, "originalApkPath")
        requireRelativePath(isolatedRoot, "isolatedRoot")
        splitApkPaths.forEach { requireRelativePath(it, "splitApkPath") }
        obbFiles.forEach { requireRelativePath(it, "obbFile") }
        crashDumpPaths.forEach { requireRelativePath(it, "crashDumpPath") }
        require(diagnostics.size <= MAX_DIAGNOSTICS_PER_GUEST) { "Guest diagnostic history exceeds its bound" }
        diagnostics.forEach(GuestDiagnostic::validate)
        require(guestAbis.distinct().size == guestAbis.size) { "guestAbis must not contain duplicates" }
        require(nativeLibraries.keys.all { it in guestAbis }) {
            "Native library catalog contains an ABI not listed in guestAbis"
        }
        require(createdAtEpochMs >= 0 && updatedAtEpochMs >= createdAtEpochMs) {
            "Invalid record timestamps"
        }
    }

    private fun requireRelativePath(value: String, label: String) {
        require(value.isNotBlank()) { "$label cannot be blank" }
        require(!value.startsWith('/') && !value.startsWith('\\')) { "$label must be relative" }
        require(!value.contains('\\')) { "$label must use normalized slash separators" }
        require(value.split('/').none { it.isBlank() || it == "." || it == ".." }) {
            "$label contains an unsafe path segment"
        }
    }

    companion object {
        private const val MAX_DIAGNOSTICS_PER_GUEST = 200
        private val APP_ID_PATTERN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
        private val PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
        private val SHA256_PATTERN = Regex("[0-9a-fA-F]{64}")
    }
}
