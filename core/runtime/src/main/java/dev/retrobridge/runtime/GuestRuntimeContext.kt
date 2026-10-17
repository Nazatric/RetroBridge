package dev.retrobridge.runtime

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID

/**
 * Metadata-only guest context used by the isolated runtime process. It deliberately does not wrap
 * android.content.Context or expose host objects to guest code. The current context can resolve
 * app-private path roots, but it cannot load or execute the imported APK.
 */
class GuestRuntimeContext internal constructor(
    val guestId: String,
    val packageName: String,
    val apkSha256: String,
    val guestAbis: List<String>,
    val appRoot: Path,
    val apkPath: Path,
    val internalRoot: Path,
    val externalDataRoot: Path,
    val obbRoot: Path,
) {
    val guestCodeExecutionEnabled: Boolean = false
    val frameworkCapabilities: Set<GuestFrameworkCapability> = setOf(
        GuestFrameworkCapability.PACKAGE_IDENTITY,
        GuestFrameworkCapability.APP_PRIVATE_PATH_MAPPING,
    )

    val executionUnavailableReason: String =
        "APK code, Java framework classes, and Android lifecycle callbacks are not loaded or executed."

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
    APP_PRIVATE_PATH_MAPPING,
}

data class GuestRuntimeContextRequest(
    val guestId: String,
    val packageName: String,
    val apkSha256: String,
    val guestAbis: List<String>,
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
    INSPECTION_ONLY,
    STOPPED,
    NOT_RUNNING,
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
)

/** A bounded, in-process supervisor for inspect-only contexts; no guest executable is loaded. */
class GuestRuntimeSessionSupervisor(
    privateRoot: Path,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Session(val context: GuestRuntimeContext, val startedAtEpochMs: Long)

    private val privateRoot = privateRoot.toAbsolutePath().normalize()
    private val sessions = linkedMapOf<String, Session>()

    @Synchronized
    fun startInspectionSession(request: GuestRuntimeContextRequest): GuestRuntimeSessionResult {
        val context = GuestRuntimeContextFactory.create(privateRoot, request)
        val existing = sessions.entries.firstOrNull { it.value.context.guestId == context.guestId }
        if (existing != null) {
            if (existing.value.context.apkSha256 != context.apkSha256) {
                throw SecurityException("A different APK identity is already associated with this guest session")
            }
            return result(existing.key, existing.value, GuestRuntimeSessionState.INSPECTION_ONLY,
                "Inspection-only runtime context is already active; guest code was not loaded or executed.")
        }
        if (sessions.size >= MAX_ACTIVE_SESSIONS) throw IOException("Runtime inspection-session limit reached")
        val session = Session(context, clock().coerceAtLeast(0))
        val sessionId = UUID.randomUUID().toString()
        sessions[sessionId] = session
        return result(sessionId, session, GuestRuntimeSessionState.INSPECTION_ONLY,
            "Inspection-only runtime context is active; APK bytecode and native code were not loaded or executed.")
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
                diagnostic = "No active inspection session matches that ID.",
            )
        return result(sessionId, session, GuestRuntimeSessionState.STOPPED,
            "Inspection-only context was stopped; no guest code had been executed.")
    }

    @Synchronized
    fun activeSessionCount(): Int = sessions.size

    @Synchronized
    fun stopAll() {
        sessions.clear()
    }

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
        guestCodeStarted = false,
        startedAtEpochMs = session.startedAtEpochMs,
        diagnostic = diagnostic,
    )

    companion object {
        private const val MAX_ACTIVE_SESSIONS = 8
    }
}
