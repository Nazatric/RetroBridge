package dev.retrobridge.runtime

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID

/** Immutable package metadata collected from the imported APK manifest. */
data class GuestPackageMetadata(
    val packageName: String,
    val applicationLabel: String,
    val versionName: String? = null,
    val versionCode: Long = 0,
    val minSdk: Int? = null,
    val targetSdk: Int? = null,
)

/**
 * App-private guest storage and identity passed to the interpreter-backed ARM32 runtime. It does
 * not itself wrap android.content.Context or expose host objects; it is not a virtual Android framework.
 */
class GuestRuntimeContext internal constructor(
    val guestId: String,
    val packageName: String,
    val apkSha256: String,
    val guestAbis: List<String>,
    val packageMetadata: GuestPackageMetadata,
    val appRoot: Path,
    val apkPath: Path,
    val internalRoot: Path,
    val externalDataRoot: Path,
    val obbRoot: Path,
) {
    val frameworkCapabilities: Set<GuestFrameworkCapability> = setOf(
        GuestFrameworkCapability.PACKAGE_IDENTITY,
        GuestFrameworkCapability.PACKAGE_METADATA_SNAPSHOT,
        GuestFrameworkCapability.APP_PRIVATE_PATH_MAPPING,
        GuestFrameworkCapability.GUEST_CONTEXT_STORAGE_FACADE,
        GuestFrameworkCapability.GUEST_SHARED_PREFERENCES,
        GuestFrameworkCapability.BOUNDED_APK_ASSET_READS,
    )

    val nativeExecutionLimitations: String =
        "Only supported ARM32 ELF code runs in the bounded interpreter; Java bytecode, Activities, and full Android framework virtualization are not provided."

    /** Resolve only the selected app's private /data and Android/data/obb guest paths. */
    fun resolveGuestPath(guestPath: String): Path {
        require(guestPath.startsWith('/')) { "Guest path must be absolute" }
        require('\u0000' !in guestPath) { "Guest path contains NUL" }
        require('\\' !in guestPath) { "Guest paths must use forward slashes" }

        val mappings = listOf(
            "/data/data/$packageName" to internalRoot,
            "/data/user/0/$packageName" to internalRoot,
            "/storage/emulated/0/Android/data/$packageName" to externalDataRoot,
            "/storage/emulated/0/Android/obb/$packageName" to obbRoot,
            "/sdcard/Android/data/$packageName" to externalDataRoot,
            "/sdcard/Android/obb/$packageName" to obbRoot,
        )
        val (prefix, destinationRoot) = mappings.firstOrNull { (candidate, _) ->
            guestPath == candidate || guestPath.startsWith("$candidate/")
        } ?: throw SecurityException("Guest path is outside supported app-private roots: $guestPath")

        val relative = guestPath.removePrefix(prefix).removePrefix("/")
        val segments = if (relative.isEmpty()) emptyList() else relative.split('/')
        if (segments.any { it.isBlank() || it == "." || it == ".." || it.contains(':') }) {
            throw SecurityException("Guest path contains an unsafe segment")
        }
        val target = segments.fold(destinationRoot) { path, segment -> path.resolve(segment) }.normalize()
        if (!target.startsWith(destinationRoot) || !target.startsWith(appRoot)) {
            throw SecurityException("Resolved guest path escaped its app-private root")
        }
        rejectSymlinksBetween(appRoot, target)
        return target
    }

    private fun rejectSymlinksBetween(base: Path, candidate: Path) {
        val normalizedBase = base.toAbsolutePath().normalize()
        val normalizedCandidate = candidate.toAbsolutePath().normalize()
        if (!normalizedCandidate.startsWith(normalizedBase)) {
            throw SecurityException("Path is outside its permitted guest root")
        }
        var current = normalizedBase
        rejectSymlink(current)
        for (segment in normalizedBase.relativize(normalizedCandidate)) {
            current = current.resolve(segment)
            rejectSymlink(current)
        }
    }

    private fun rejectSymlink(path: Path) {
        if (Files.isSymbolicLink(path)) throw SecurityException("Symbolic links are not allowed: $path")
    }
}

enum class GuestFrameworkCapability {
    PACKAGE_IDENTITY,
    PACKAGE_METADATA_SNAPSHOT,
    APP_PRIVATE_PATH_MAPPING,
    GUEST_CONTEXT_STORAGE_FACADE,
    GUEST_SHARED_PREFERENCES,
    BOUNDED_APK_ASSET_READS,
}

data class GuestRuntimeContextRequest(
    val guestId: String,
    val packageName: String,
    val apkSha256: String,
    val guestAbis: List<String>,
    val packageMetadata: GuestPackageMetadata = GuestPackageMetadata(
        packageName = packageName,
        applicationLabel = packageName,
    ),
)

/** Builds a context only from the one app-owned storage layout; callers cannot supply host paths. */
object GuestRuntimeContextFactory {
    private val packagePattern = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    private val sha256Pattern = Regex("[0-9a-fA-F]{64}")
    private val knownAbis = setOf("armeabi-v7a", "armeabi", "arm64-v8a", "x86", "x86_64", "riscv64")
    private const val MAX_APK_BYTES = 2L * 1024 * 1024 * 1024

    fun create(privateRoot: Path, request: GuestRuntimeContextRequest): GuestRuntimeContext {
        require(runCatching { UUID.fromString(request.guestId).toString() == request.guestId }.getOrDefault(false)) {
            "Invalid guest application ID"
        }
        require(packagePattern.matches(request.packageName)) { "Invalid Android package name" }
        require(sha256Pattern.matches(request.apkSha256)) { "Invalid APK SHA-256" }
        val packageMetadata = request.packageMetadata
        require(packageMetadata.packageName == request.packageName) { "Guest package metadata identity mismatch" }
        require(packageMetadata.applicationLabel.isNotBlank()
            && packageMetadata.applicationLabel.length <= 255
            && '\u0000' !in packageMetadata.applicationLabel) { "Invalid guest application label" }
        val versionName = packageMetadata.versionName
        require(versionName == null || (versionName.length <= 255 && '\u0000' !in versionName)) {
            "Invalid guest version name"
        }
        require(packageMetadata.versionCode >= 0) { "Invalid guest version code" }
        require(packageMetadata.minSdk == null || packageMetadata.minSdk >= 1) { "Invalid guest minSdk" }
        require(packageMetadata.targetSdk == null || packageMetadata.targetSdk >= 1) { "Invalid guest targetSdk" }
        require(request.guestAbis.size <= knownAbis.size && request.guestAbis.distinct().size == request.guestAbis.size) {
            "Invalid guest ABI list"
        }
        require(request.guestAbis.all { it in knownAbis }) { "Unknown guest ABI" }

        val root = privateRoot.toAbsolutePath().normalize()
        rejectSymlinksBetween(root, root)
        val appsRoot = root.resolve("apps")
        val appRoot = appsRoot.resolve(request.packageName).resolve(request.guestId).normalize()
        if (!appRoot.startsWith(appsRoot)) throw SecurityException("Guest application root escaped private storage")
        rejectSymlinksBetween(root, appRoot)
        if (!Files.isDirectory(appRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Guest application storage does not exist")
        }

        val apkPath = appRoot.resolve("app/base.apk")
        rejectSymlinksBetween(appRoot, apkPath)
        if (!Files.isRegularFile(apkPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Imported base APK is missing or not a regular file")
        }
        val apkBytes = Files.size(apkPath)
        if (apkBytes <= 0L || apkBytes > MAX_APK_BYTES) {
            throw IOException("Imported APK size is outside the inspection limit")
        }
        verifyApkDigest(apkPath, apkBytes, request.apkSha256)

        val internalRoot = appRoot.resolve("internal")
        val externalDataRoot = appRoot.resolve("external/data")
        val obbRoot = appRoot.resolve("obb")
        listOf(internalRoot, externalDataRoot, obbRoot).forEach { path ->
            rejectSymlinksBetween(appRoot, path)
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                throw IOException("Guest app-private storage is incomplete")
            }
        }
        return GuestRuntimeContext(
            guestId = request.guestId,
            packageName = request.packageName,
            apkSha256 = request.apkSha256.lowercase(),
            guestAbis = request.guestAbis.toList(),
            packageMetadata = request.packageMetadata,
            appRoot = appRoot,
            apkPath = apkPath,
            internalRoot = internalRoot,
            externalDataRoot = externalDataRoot,
            obbRoot = obbRoot,
        )
    }

    private fun verifyApkDigest(path: Path, expectedSize: Long, expectedSha256: String) {
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) {
                    val value = input.read()
                    if (value < 0) break
                    if (total >= MAX_APK_BYTES) throw IOException("Imported APK exceeded the inspection byte limit")
                    digest.update(value.toByte())
                    total += 1
                    continue
                }
                if (total > MAX_APK_BYTES - count) throw IOException("Imported APK exceeded the inspection byte limit")
                digest.update(buffer, 0, count)
                total += count
            }
        }
        if (total != expectedSize) throw IOException("Imported APK changed during runtime-context validation")
        val actual = digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        if (!actual.equals(expectedSha256, ignoreCase = true)) {
            throw SecurityException("Imported APK SHA-256 does not match its registry identity")
        }
    }

    private fun rejectSymlinksBetween(base: Path, candidate: Path) {
        val normalizedBase = base.toAbsolutePath().normalize()
        val normalizedCandidate = candidate.toAbsolutePath().normalize()
        if (!normalizedCandidate.startsWith(normalizedBase)) throw SecurityException("Path is outside private storage")
        var current = normalizedBase
        rejectSymlink(current)
        for (segment in normalizedBase.relativize(normalizedCandidate)) {
            current = current.resolve(segment)
            rejectSymlink(current)
        }
    }

    private fun rejectSymlink(path: Path) {
        if (Files.isSymbolicLink(path)) throw SecurityException("Symbolic links are not allowed: $path")
    }
}

enum class GuestRuntimeSessionState {
    RUNNING,
    STOPPED,
    NOT_RUNNING,
    FAILED,
    UNSUPPORTED,
    REJECTED,
}

data class GuestRuntimeSessionResult(
    val sessionId: String?,
    val guestId: String,
    val packageName: String,
    val state: GuestRuntimeSessionState,
    val guestCodeStarted: Boolean,
    val startedAtEpochMs: Long,
    val diagnostic: String,
    val guestInstructions: Long = 0,
    val relocationCount: Int = 0,
    val jniOnLoadVersion: Int = -1,
    val registeredNativeCount: Int = 0,
    val loadedLibraries: List<String> = emptyList(),
    val entrypointResults: List<String> = emptyList(),
)

/** Owns bounded interpreter sessions in the private runtime process. */
class GuestRuntimeSessionSupervisor(
    privateRoot: Path,
    private val clock: () -> Long = System::currentTimeMillis,
    private val nativeController: NativeRuntimeController = JniNativeRuntimeController,
) {
    private data class Session(
        val context: GuestRuntimeContext,
        val nativeSessionId: Long,
        val startedAtEpochMs: Long,
        val report: NativeExecutionReport,
    )

    private val privateRoot = privateRoot.toAbsolutePath().normalize()
    private val sessions = linkedMapOf<String, Session>()

    @Synchronized
    fun startGuestRuntimeSession(request: GuestRuntimeContextRequest): GuestRuntimeSessionResult {
        val context = try {
            GuestRuntimeContextFactory.create(privateRoot, request)
        } catch (failure: Exception) {
            return failureResult(request, failure)
        }
        val existing = sessions.entries.firstOrNull { it.value.context.guestId == context.guestId }
        if (existing != null) {
            if (existing.value.context.apkSha256 != context.apkSha256) {
                return failureResult(request, SecurityException("A different APK identity is already running for this guest"))
            }
            return result(existing.key, existing.value, GuestRuntimeSessionState.RUNNING,
                "ARM32 guest runtime is already active. ${summarize(existing.value.report)}")
        }
        if (sessions.size >= MAX_ACTIVE_SESSIONS) {
            return failureResult(request, java.io.IOException("Runtime session limit reached"))
        }

        var nativeSessionId = 0L
        try {
            val extraction = NativeLibraryExtractor.extract(context)
            nativeSessionId = nativeController.createSession(context)
            if (nativeSessionId <= 0L) throw IllegalStateException("Native interpreter returned an invalid session handle")

            val inspected = linkedMapOf<Path, NativeLibraryMetadata>()
            for (library in extraction.libraries) {
                val metadata = nativeController.inspectLibrary(nativeSessionId, library.path.toString())
                if (!metadata.valid) {
                    throw IllegalArgumentException(metadata.diagnostic.ifBlank { "Invalid ARM32 library ${library.fileName}" })
                }
                inspected[library.path] = metadata
            }
            val loadOrder = NativeLibraryExtractor.dependencyOrder(extraction.libraries, inspected)
            for (library in loadOrder) {
                NativeLibraryExtractor.verifyExtractedFile(library.path, library.sha256, library.size)
                val loaded = nativeController.loadLibrary(nativeSessionId, library.path.toString(), library.sha256)
                if (!loaded.loaded) {
                    throw IllegalStateException(loaded.diagnostic.ifBlank { "Unable to map ${library.fileName}" })
                }
            }

            val report = nativeController.execute(nativeSessionId, MAX_GUEST_INSTRUCTIONS)
            if (!report.success || report.guestInstructions <= 0L) {
                val diagnostic = report.diagnostics.joinToString("; ").ifBlank {
                    "No supported ARM32 guest code completed under the instruction budget"
                }
                throw NativeExecutionFailure(diagnostic, report)
            }
            val session = Session(context, nativeSessionId, clock().coerceAtLeast(0L), report)
            val sessionId = UUID.randomUUID().toString()
            sessions[sessionId] = session
            return result(sessionId, session, GuestRuntimeSessionState.RUNNING,
                "Interpreter-backed ARM32 native execution completed within budget. ${summarize(report)}")
        } catch (failure: Exception) {
            if (nativeSessionId > 0L) runCatching { nativeController.destroySession(nativeSessionId) }
            return failureResult(request, failure)
        }
    }

    @Synchronized
    fun stopSession(sessionId: String): GuestRuntimeSessionResult {
        val session = sessions.remove(sessionId)
            ?: return GuestRuntimeSessionResult(
                sessionId = null,
                guestId = "",
                packageName = "",
                state = GuestRuntimeSessionState.NOT_RUNNING,
                guestCodeStarted = false,
                startedAtEpochMs = 0,
                diagnostic = "No active ARM32 runtime session matches that ID.",
            )
        val teardownDiagnostic = runCatching { nativeController.destroySession(session.nativeSessionId) }
            .exceptionOrNull()?.let { "; native teardown diagnostic: ${it.message ?: it.javaClass.simpleName}" }.orEmpty()
        return result(sessionId, session, GuestRuntimeSessionState.STOPPED,
            "ARM32 interpreter session stopped; bounded guest destructors were requested.$teardownDiagnostic")
    }

    @Synchronized
    fun activeSessionCount(): Int = sessions.size

    @Synchronized
    fun stopAll() {
        sessions.values.forEach { session ->
            runCatching { nativeController.destroySession(session.nativeSessionId) }
        }
        sessions.clear()
    }

    private fun failureResult(request: GuestRuntimeContextRequest, failure: Exception): GuestRuntimeSessionResult {
        val unsupported = failure is java.io.IOException &&
            (failure.message.orEmpty().contains("no armeabi", ignoreCase = true)
                || failure.message.orEmpty().contains("no ARM32", ignoreCase = true))
        return GuestRuntimeSessionResult(
            sessionId = null,
            guestId = request.guestId.take(64),
            packageName = request.packageName.take(256),
            state = if (unsupported) GuestRuntimeSessionState.UNSUPPORTED else GuestRuntimeSessionState.FAILED,
            guestCodeStarted = (failure as? NativeExecutionFailure)?.report?.guestInstructions?.let { it > 0L } ?: false,
            startedAtEpochMs = 0,
            diagnostic = (failure.message ?: failure.javaClass.simpleName).take(MAX_DIAGNOSTIC_LENGTH),
            guestInstructions = (failure as? NativeExecutionFailure)?.report?.guestInstructions ?: 0L,
            relocationCount = (failure as? NativeExecutionFailure)?.report?.relocationCount ?: 0,
            jniOnLoadVersion = (failure as? NativeExecutionFailure)?.report?.jniOnLoadVersion ?: -1,
            registeredNativeCount = (failure as? NativeExecutionFailure)?.report?.registeredNativeCount ?: 0,
            loadedLibraries = (failure as? NativeExecutionFailure)?.report?.loadedLibraries?.toList().orEmpty(),
            entrypointResults = (failure as? NativeExecutionFailure)?.report?.entrypointResults?.toList().orEmpty(),
        )
    }

    private fun summarize(report: NativeExecutionReport): String = buildString {
        append("instructions=").append(report.guestInstructions)
        append(", relocations=").append(report.relocationCount)
        append(", libraries=").append(report.loadedLibraries.joinToString().ifBlank { "none" })
        if (report.jniOnLoadVersion >= 0) append(", JNI_OnLoad=0x").append(report.jniOnLoadVersion.toUInt().toString(16))
        if (report.registeredNativeCount > 0) append(", registered JNI natives=").append(report.registeredNativeCount)
        if (report.entrypointResults.isNotEmpty()) append(", entrypoints=").append(report.entrypointResults.joinToString())
    }.take(MAX_DIAGNOSTIC_LENGTH)

    private fun result(
        sessionId: String,
        session: Session,
        state: GuestRuntimeSessionState,
        diagnostic: String,
    ) = GuestRuntimeSessionResult(
        sessionId = sessionId,
        guestId = session.context.guestId,
        packageName = session.context.packageName,
        state = state,
        guestCodeStarted = session.report.guestInstructions > 0L,
        startedAtEpochMs = session.startedAtEpochMs,
        diagnostic = diagnostic.take(MAX_DIAGNOSTIC_LENGTH),
        guestInstructions = session.report.guestInstructions,
        relocationCount = session.report.relocationCount,
        jniOnLoadVersion = session.report.jniOnLoadVersion,
        registeredNativeCount = session.report.registeredNativeCount,
        loadedLibraries = session.report.loadedLibraries.toList(),
        entrypointResults = session.report.entrypointResults.toList(),
    )

    private class NativeExecutionFailure(
        message: String,
        val report: NativeExecutionReport,
    ) : IllegalStateException(message)

    companion object {
        private const val MAX_ACTIVE_SESSIONS = 2
        private const val MAX_GUEST_INSTRUCTIONS = 8_000_000L
        private const val MAX_DIAGNOSTIC_LENGTH = 512
    }
}
