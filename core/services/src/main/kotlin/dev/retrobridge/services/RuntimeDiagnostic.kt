package dev.retrobridge.services

/** Stable, machine-readable diagnostic dimensions shared by the runtime boundary and UI. */
enum class DiagnosticSeverity { DEBUG, INFO, WARNING, ERROR, FATAL }

enum class DiagnosticCategory {
    APK_IMPORT,
    UNSUPPORTED_ABI,
    ELF_LOADING,
    MISSING_LIBRARY,
    UNRESOLVED_SYMBOL,
    UNSUPPORTED_INSTRUCTION,
    ABI_CONVERSION,
    NATIVE_RUNTIME,
    JNI,
    ANDROID_FRAMEWORK,
    FILESYSTEM,
    GRAPHICS_AUDIO,
    RESOURCE_EXHAUSTION,
    GUEST_CRASH,
    INTERNAL_DEFECT,
    GENERAL,
}

enum class DiagnosticOperation {
    APK_IMPORT,
    APK_PREFLIGHT,
    DATA_IMPORT,
    OBB_IMPORT,
    DATA_EXPORT,
    DATA_CLEAR,
    APP_REMOVE,
    DIAGNOSTIC_EXPORT,
    GUEST_CONTEXT_VALIDATION,
    NATIVE_LIBRARY_EXTRACTION,
    NATIVE_SESSION_INITIALIZATION,
    ELF_INSPECTION,
    DEPENDENCY_RESOLUTION,
    LIBRARY_MAPPING,
    NATIVE_EXECUTION,
    JNI_INITIALIZATION,
    SESSION_MANAGEMENT,
    RUNTIME_STOP,
    IPC,
    UNKNOWN,
}

data class RuntimeDiagnostic(
    val timestampEpochMs: Long,
    val severity: DiagnosticSeverity,
    val category: DiagnosticCategory,
    val code: String,
    val component: String,
    val operation: DiagnosticOperation,
    val summary: String,
    val detail: String? = null,
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
)

/** Converts existing runtime failure details into structured events without changing their cause. */
object RuntimeDiagnosticClassifier {
    private val missingLibrary = Regex(
        "(?i)(?:requires unavailable (?:library|dependency)|unavailable (?:library|dependency))\\s+([A-Za-z0-9_.+@-]+\\.so)",
    )
    private val unresolvedSymbol = Regex(
        "(?i)(?:undefined|unresolved)(?:\\s+ARM32)?\\s+symbol\\s*[:=]?\\s*['\"]?([A-Za-z_][A-Za-z0-9_@.$]*)",
    )
    private val fileInDetail = Regex("(?i)(?:file|path)=([^\\s,;:]+)")
    private val libraryInDetail = Regex("(?i)(?:file|library)=([^\\s,;]*[A-Za-z0-9_.+@-]+\\.so)")
    private val archiveEntryInDetail = Regex("(?i)(lib/[^\\s:]+\\.so)")
    private val dependencyImporterInDetail = Regex("(?i)([A-Za-z0-9_.+@-]+\\.so)\\s+requires unavailable")
    private val addressInDetail = Regex("(?i)guest address\\s+(?:0x([0-9a-f]+)|(\\d+))")
    private val instructionInDetail = Regex("(?i)\\((?:word|halfword)\\s+([^)]*)\\)")

    fun failure(
        operation: DiagnosticOperation,
        message: String,
        guestId: String? = null,
        packageName: String? = null,
        exceptionType: String? = null,
        timestampEpochMs: Long = System.currentTimeMillis(),
    ): RuntimeDiagnostic {
        val detail = message.trim().ifBlank { exceptionType ?: "Operation failed without a diagnostic message" }.take(MAX_DETAIL_LENGTH)
        val searchable = "$detail ${exceptionType.orEmpty()}".lowercase()
        val missing = missingLibrary.find(detail)?.groupValues?.getOrNull(1)
        val symbol = unresolvedSymbol.find(detail)?.groupValues?.getOrNull(1)
        val category: DiagnosticCategory
        val code: String
        val summary: String
        val nextAction: String
        val component: String

        when {
            missing != null -> {
                category = DiagnosticCategory.MISSING_LIBRARY
                code = "MISSING_NATIVE_LIBRARY"
                summary = "Required native library $missing is unavailable."
                nextAction = "Provide the matching ARM32 dependency in the APK or implement an explicit platform thunk."
                component = "Native dependency resolver"
            }
            symbol != null -> {
                category = DiagnosticCategory.UNRESOLVED_SYMBOL
                code = "UNRESOLVED_NATIVE_SYMBOL"
                summary = "Native symbol $symbol could not be resolved."
                nextAction = "Check the importing library, relocation, symbol version, and implemented runtime thunks."
                component = "ELF symbol resolver"
            }
            isUnsupportedInstruction(searchable, operation) -> {
                category = DiagnosticCategory.UNSUPPORTED_INSTRUCTION
                code = "UNSUPPORTED_ARM_INSTRUCTION"
                summary = "Guest code reached an ARM instruction this interpreter does not implement."
                nextAction = "Use the reported guest PC and opcode to add real instruction semantics and a regression fixture."
                component = "ARM32 interpreter"
            }
            "no armeabi" in searchable || "no arm32 native librar" in searchable || "unsupported abi" in searchable -> {
                category = DiagnosticCategory.UNSUPPORTED_ABI
                code = "ARM32_LIBRARY_NOT_FOUND"
                summary = "No supported ARM32 native library was found in this APK."
                nextAction = "This execution path requires an armeabi-v7a or compatible armeabi native library; ARM64 code is not converted to ARM32."
                component = "ABI selection"
            }
            isResourceFailure(searchable) -> {
                category = DiagnosticCategory.RESOURCE_EXHAUSTION
                code = "RUNTIME_RESOURCE_LIMIT"
                summary = "A runtime resource limit prevented this operation."
                nextAction = "Check the APK/data size and bounded instruction, extraction, and storage limits before retrying."
                component = "Runtime resource guard"
            }
            isInternalFailure(exceptionType) -> {
                category = DiagnosticCategory.INTERNAL_DEFECT
                code = "RUNTIME_INTERNAL_FAILURE"
                summary = "RetroBridge encountered an internal runtime error."
                nextAction = "Export this diagnostic with its detail and use it to create a regression test."
                component = "RetroBridge runtime"
            }
            "jni" in searchable || "java_vm" in searchable || "jvm" in searchable -> {
                category = DiagnosticCategory.JNI
                code = "JNI_OPERATION_FAILED"
                summary = "The selected JNI operation is unsupported or failed."
                nextAction = "Inspect the JNI method and signature; only explicitly implemented JNI operations are available."
                component = "JNI bridge"
            }
            listOf("egl", "gles", "opensl", "audio", "surface", "anativewindow").any(searchable::contains) -> {
                category = DiagnosticCategory.GRAPHICS_AUDIO
                code = "MEDIA_OR_GRAPHICS_OPERATION_FAILED"
                summary = "A graphics or audio operation is outside the implemented headless subset."
                nextAction = "Check the exact API and required device integration; no full Android graphics/audio stack is provided."
                component = "Graphics/audio thunks"
            }
            "android framework" in searchable || "activity" in searchable || "dex" in searchable || "java bytecode" in searchable -> {
                category = DiagnosticCategory.ANDROID_FRAMEWORK
                code = "ANDROID_FRAMEWORK_UNAVAILABLE"
                summary = "This operation requires Android framework or Java execution that RetroBridge does not provide."
                nextAction = "The current runtime executes selected native ARM32 code only; it does not run guest DEX or Activities."
                component = "Android framework boundary"
            }
            isFileOperation(operation) || listOf("zip", "obb", "permission denied", "path", "file not found", "storage").any(searchable::contains) -> {
                category = if (operation == DiagnosticOperation.APK_IMPORT || operation == DiagnosticOperation.APK_PREFLIGHT) {
                    DiagnosticCategory.APK_IMPORT
                } else {
                    DiagnosticCategory.FILESYSTEM
                }
                code = when (operation) {
                    DiagnosticOperation.APK_IMPORT -> "APK_IMPORT_FAILED"
                    DiagnosticOperation.APK_PREFLIGHT -> "APK_PREFLIGHT_FAILED"
                    DiagnosticOperation.DATA_IMPORT -> "DATA_ARCHIVE_IMPORT_FAILED"
                    DiagnosticOperation.OBB_IMPORT -> "OBB_IMPORT_FAILED"
                    DiagnosticOperation.DATA_EXPORT -> "DATA_EXPORT_FAILED"
                    DiagnosticOperation.DATA_CLEAR -> "GUEST_DATA_CLEAR_FAILED"
                    DiagnosticOperation.APP_REMOVE -> "GUEST_APP_REMOVE_FAILED"
                    DiagnosticOperation.DIAGNOSTIC_EXPORT -> "DIAGNOSTIC_EXPORT_FAILED"
                    else -> "GUEST_FILESYSTEM_OPERATION_FAILED"
                }
                summary = when (operation) {
                    DiagnosticOperation.APK_IMPORT -> "The APK could not be imported."
                    DiagnosticOperation.APK_PREFLIGHT -> "APK inspection could not be completed."
                    DiagnosticOperation.DATA_IMPORT -> "The app data archive could not be imported."
                    DiagnosticOperation.OBB_IMPORT -> "The OBB content could not be imported."
                    DiagnosticOperation.DATA_EXPORT -> "Guest data could not be exported."
                    DiagnosticOperation.DATA_CLEAR -> "Guest-owned data could not be cleared."
                    DiagnosticOperation.APP_REMOVE -> "The imported guest could not be removed."
                    DiagnosticOperation.DIAGNOSTIC_EXPORT -> "The diagnostic report could not be exported."
                    else -> "A guest-private storage operation failed."
                }
                nextAction = when (operation) {
                    DiagnosticOperation.DIAGNOSTIC_EXPORT -> "Choose a writable destination and retry; the event log remains in app-private storage."
                    DiagnosticOperation.DATA_CLEAR -> "Check the diagnostic detail; the operation preserves the imported APK and OBB files."
                    DiagnosticOperation.APP_REMOVE -> "Verify the guest identity and app-private storage; no other guest should be affected."
                    else -> "Verify the selected document, available private storage, and the requested guest-private path."
                }
                component = when {
                    category == DiagnosticCategory.APK_IMPORT -> "APK importer"
                    operation == DiagnosticOperation.DIAGNOSTIC_EXPORT -> "Diagnostic reporter"
                    operation == DiagnosticOperation.APP_REMOVE -> "Guest manager"
                    else -> "Guest storage"
                }
            }
            "elf" in searchable || "relocation" in searchable || "program header" in searchable || "dynamic symbol" in searchable -> {
                category = DiagnosticCategory.ELF_LOADING
                code = "ELF_LOAD_OR_RELOCATION_FAILED"
                summary = "The ARM32 ELF image could not be inspected or loaded."
                nextAction = "Inspect the ELF class, machine, segments, dynamic tables, relocations, and required linker behavior."
                component = "ELF32 loader"
            }
            operation == DiagnosticOperation.APK_IMPORT || operation == DiagnosticOperation.APK_PREFLIGHT -> {
                category = DiagnosticCategory.APK_IMPORT
                code = if (operation == DiagnosticOperation.APK_IMPORT) "APK_IMPORT_FAILED" else "APK_PREFLIGHT_FAILED"
                summary = if (operation == DiagnosticOperation.APK_IMPORT) "The APK could not be imported." else "APK inspection could not be completed."
                nextAction = "Verify that the selected document is a readable APK and retry; the original is left unchanged."
                component = "APK importer"
            }
            else -> {
                category = DiagnosticCategory.NATIVE_RUNTIME
                code = "NATIVE_RUNTIME_OPERATION_FAILED"
                summary = when (operation) {
                    DiagnosticOperation.NATIVE_LIBRARY_EXTRACTION -> "ARM32 native libraries could not be extracted safely."
                    DiagnosticOperation.NATIVE_SESSION_INITIALIZATION -> "The native runtime session could not be initialized."
                    DiagnosticOperation.ELF_INSPECTION -> "An ARM32 native library failed structural inspection."
                    DiagnosticOperation.DEPENDENCY_RESOLUTION -> "The ARM32 dependency graph could not be resolved."
                    DiagnosticOperation.LIBRARY_MAPPING -> "An ARM32 library could not be mapped."
                    DiagnosticOperation.NATIVE_EXECUTION -> "Selected ARM32 native execution failed."
                    DiagnosticOperation.GUEST_CONTEXT_VALIDATION -> "Guest identity or private storage validation failed."
                    DiagnosticOperation.RUNTIME_STOP -> "The runtime session could not be stopped cleanly."
                    DiagnosticOperation.JNI_INITIALIZATION -> "Native JNI initialization failed."
                    DiagnosticOperation.SESSION_MANAGEMENT -> "Runtime session management failed."
                    DiagnosticOperation.IPC -> "The private runtime service request failed."
                    else -> "The runtime operation failed."
                }
                nextAction = "Review the technical detail and compatibility inventory; unsupported behavior is reported rather than emulated."
                component = operation.componentName()
            }
        }

        val address = addressInDetail.find(detail)?.let { match ->
            match.groupValues.getOrNull(1)?.takeIf(String::isNotBlank)?.let { "0x${it.lowercase()}" }
                ?: match.groupValues.getOrNull(2)?.toLongOrNull()?.let { "0x${it.toString(16)}" }
        }
        val instruction = instructionInDetail.find(detail)?.groupValues?.getOrNull(1)?.trim()?.let(::normalizeInstruction)
        val file = fileInDetail.find(detail)?.groupValues?.getOrNull(1)
            ?: archiveEntryInDetail.find(detail)?.groupValues?.getOrNull(1)
            ?: dependencyImporterInDetail.find(detail)?.groupValues?.getOrNull(1)
        val library = missing
            ?: libraryInDetail.find(detail)?.groupValues?.getOrNull(1)?.substringAfterLast('/')
            ?: Regex("(?i)([A-Za-z0-9_.+@-]+\\.so)").find(detail)?.groupValues?.getOrNull(1)

        return RuntimeDiagnostic(
            timestampEpochMs = timestampEpochMs.coerceAtLeast(0L),
            severity = DiagnosticSeverity.ERROR,
            category = category,
            code = code,
            component = component,
            operation = operation,
            summary = summary,
            detail = detail,
            guestId = guestId?.take(64),
            packageName = packageName?.take(255),
            library = library,
            file = file?.take(1_024),
            symbol = symbol,
            guestAddress = address,
            instruction = instruction,
            nextAction = nextAction,
        )
    }

    fun sessionRunning(
        guestId: String,
        packageName: String,
        timestampEpochMs: Long,
        instructions: Long,
        libraries: List<String>,
    ) = RuntimeDiagnostic(
        timestampEpochMs = timestampEpochMs.coerceAtLeast(0L),
        severity = DiagnosticSeverity.INFO,
        category = DiagnosticCategory.NATIVE_RUNTIME,
        code = "RUNTIME_SESSION_RUNNING",
        component = "ARM32 interpreter",
        operation = DiagnosticOperation.NATIVE_EXECUTION,
        summary = "Selected ARM32 native entrypoints completed within budget; the runtime session remains active.",
        detail = "Guest instructions: $instructions; loaded libraries: ${libraries.joinToString().ifBlank { "none" }}".take(MAX_DETAIL_LENGTH),
        guestId = guestId,
        packageName = packageName,
        nextAction = "This verifies only the selected native execution path, not full APK or game compatibility.",
    )

    fun sessionNotFound(timestampEpochMs: Long) = RuntimeDiagnostic(
        timestampEpochMs = timestampEpochMs.coerceAtLeast(0L),
        severity = DiagnosticSeverity.WARNING,
        category = DiagnosticCategory.NATIVE_RUNTIME,
        code = "RUNTIME_SESSION_NOT_FOUND",
        component = "Runtime lifecycle",
        operation = DiagnosticOperation.RUNTIME_STOP,
        summary = "No active runtime session matched the stop request.",
        detail = "The session may already have stopped or the runtime service may have restarted.",
        nextAction = "Refresh the app state and retry only if a session is still reported as active.",
    )

    fun sessionStopped(
        guestId: String,
        packageName: String,
        timestampEpochMs: Long,
        detail: String,
    ) = RuntimeDiagnostic(
        timestampEpochMs = timestampEpochMs.coerceAtLeast(0L),
        severity = DiagnosticSeverity.INFO,
        category = DiagnosticCategory.NATIVE_RUNTIME,
        code = "RUNTIME_SESSION_STOPPED",
        component = "ARM32 interpreter",
        operation = DiagnosticOperation.RUNTIME_STOP,
        summary = "The ARM32 runtime session stopped.",
        detail = detail.take(MAX_DETAIL_LENGTH),
        guestId = guestId,
        packageName = packageName,
        nextAction = "A stopped session does not indicate general application compatibility.",
    )

    private fun isUnsupportedInstruction(message: String, operation: DiagnosticOperation): Boolean {
        if ("unsupported" !in message) return false
        if ("instruction" in message || "opcode" in message) return true
        if (operation != DiagnosticOperation.NATIVE_EXECUTION) return false
        return listOf(
            "a32", "t16", "t32", "ldm/stm", "mul/mla", "halfword/doubleword", "register-specified",
        ).any(message::contains)
    }

    private fun isResourceFailure(message: String) = listOf(
        "outofmemory", "out of memory", "resource limit", "session limit", "instruction budget", "extraction limit", "size limit",
    ).any(message::contains)

    private fun isInternalFailure(exceptionType: String?): Boolean {
        val simpleName = exceptionType?.substringAfterLast('.') ?: return false
        return simpleName in setOf(
            "NullPointerException", "IndexOutOfBoundsException", "ArrayIndexOutOfBoundsException", "AssertionError",
        )
    }

    private fun isFileOperation(operation: DiagnosticOperation) = operation in setOf(
        DiagnosticOperation.APK_IMPORT,
        DiagnosticOperation.APK_PREFLIGHT,
        DiagnosticOperation.DATA_IMPORT,
        DiagnosticOperation.OBB_IMPORT,
        DiagnosticOperation.DATA_EXPORT,
        DiagnosticOperation.DATA_CLEAR,
        DiagnosticOperation.APP_REMOVE,
        DiagnosticOperation.DIAGNOSTIC_EXPORT,
    )

    private fun DiagnosticOperation.componentName() = when (this) {
        DiagnosticOperation.APK_IMPORT, DiagnosticOperation.APK_PREFLIGHT -> "APK importer"
        DiagnosticOperation.DATA_IMPORT, DiagnosticOperation.OBB_IMPORT, DiagnosticOperation.DATA_EXPORT,
        DiagnosticOperation.DATA_CLEAR -> "Guest storage"
        DiagnosticOperation.APP_REMOVE -> "Guest manager"
        DiagnosticOperation.DIAGNOSTIC_EXPORT -> "Diagnostic reporter"
        DiagnosticOperation.GUEST_CONTEXT_VALIDATION -> "Guest context validator"
        DiagnosticOperation.NATIVE_LIBRARY_EXTRACTION -> "Native library extractor"
        DiagnosticOperation.NATIVE_SESSION_INITIALIZATION -> "Native session controller"
        DiagnosticOperation.ELF_INSPECTION -> "ELF32 inspector"
        DiagnosticOperation.DEPENDENCY_RESOLUTION -> "Native dependency resolver"
        DiagnosticOperation.LIBRARY_MAPPING -> "ELF32 loader"
        DiagnosticOperation.NATIVE_EXECUTION -> "ARM32 interpreter"
        DiagnosticOperation.JNI_INITIALIZATION -> "JNI bridge"
        DiagnosticOperation.SESSION_MANAGEMENT -> "Runtime session manager"
        DiagnosticOperation.RUNTIME_STOP -> "Runtime lifecycle"
        DiagnosticOperation.IPC -> "Runtime IPC"
        DiagnosticOperation.UNKNOWN -> "RetroBridge runtime"
    }

    private fun normalizeInstruction(value: String): String {
        val trimmed = value.trim()
        if (trimmed.startsWith("0x", ignoreCase = true)) return "0x${trimmed.substring(2).lowercase()}"
        return trimmed.toLongOrNull()?.let { "0x${it.toString(16)}" } ?: trimmed.take(64)
    }

    private const val MAX_DETAIL_LENGTH = 4_096
}
