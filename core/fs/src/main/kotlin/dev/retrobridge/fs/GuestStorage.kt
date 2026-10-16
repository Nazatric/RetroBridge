package dev.retrobridge.fs

import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes

/** Stable paths for one imported application. The application ID prevents version/import collisions. */
data class GuestStorageLayout(
    val app: Path,
    val internalFiles: Path,
    val internalCache: Path,
    val databases: Path,
    val sharedPreferences: Path,
    val externalFiles: Path,
    val externalCache: Path,
    val externalData: Path,
    val obb: Path,
    val shared: Path,
)

data class StorageBreakdown(
    val apkAndMetadataBytes: Long,
    val internalBytes: Long,
    val externalBytes: Long,
    val obbBytes: Long,
    val sharedBytes: Long,
) {
    val totalBytes: Long
        get() = apkAndMetadataBytes + internalBytes + externalBytes + obbBytes + sharedBytes
}

/**
 * Resolves only the guest-owned Android data roots into a private per-app directory.
 * It is a path mapper, not a mount namespace or a complete Android filesystem.
 */
class GuestStorage(
    private val privateRoot: Path,
    val packageName: String,
    val applicationId: String,
) {
    val appRoot: Path = privateRoot.toAbsolutePath().normalize()
        .resolve("apps")
        .resolve(packageName)
        .resolve(applicationId)
        .normalize()

    val layout: GuestStorageLayout = GuestStorageLayout(
        app = appRoot.resolve("app"),
        internalFiles = appRoot.resolve("internal/files"),
        internalCache = appRoot.resolve("internal/cache"),
        databases = appRoot.resolve("internal/databases"),
        sharedPreferences = appRoot.resolve("internal/shared_prefs"),
        externalFiles = appRoot.resolve("external/files"),
        externalCache = appRoot.resolve("external/cache"),
        externalData = appRoot.resolve("external/data"),
        obb = appRoot.resolve("obb"),
        shared = appRoot.resolve("shared"),
    )

    init {
        require(PACKAGE_PATTERN.matches(packageName)) { "Invalid Android package name" }
        require(APP_ID_PATTERN.matches(applicationId)) { "Invalid application ID" }
        require(appRoot.startsWith(privateRoot.toAbsolutePath().normalize().resolve("apps"))) {
            "Guest root escaped private storage"
        }
    }

    fun initialize(): GuestStorageLayout {
        val normalizedRoot = privateRoot.toAbsolutePath().normalize()
        rejectSymlink(normalizedRoot)
        Files.createDirectories(normalizedRoot)
        rejectSymlink(normalizedRoot)
        val appsRoot = normalizedRoot.resolve("apps")
        val packageRoot = appsRoot.resolve(packageName)
        listOf(appsRoot, packageRoot, appRoot).forEach { directory ->
            rejectSymlink(directory)
            Files.createDirectories(directory)
            rejectSymlink(directory)
        }
        listOf(
            layout.app,
            layout.internalFiles,
            layout.internalCache,
            layout.databases,
            layout.sharedPreferences,
            layout.externalFiles,
            layout.externalCache,
            layout.externalData,
            layout.obb,
            layout.shared,
        ).forEach { directory ->
            requireOwnedPath(directory)
            Files.createDirectories(directory)
            rejectSymlink(directory)
        }
        return layout
    }

    /**
     * Map the supported guest-private paths. All other absolute paths, including /system and
     * arbitrary external-storage locations, are rejected instead of falling through to the host.
     */
    fun resolveGuestPath(guestPath: String): Path {
        require(guestPath.startsWith('/')) { "Guest path must be absolute" }
        require('\u0000' !in guestPath) { "Guest path contains NUL" }
        require('\\' !in guestPath) { "Guest paths must use forward slashes" }

        val mappings = listOf(
            "/data/data/$packageName" to appRoot.resolve("internal"),
            "/data/user/0/$packageName" to appRoot.resolve("internal"),
            "/storage/emulated/0/Android/data/$packageName" to layout.externalData,
            "/storage/emulated/0/Android/obb/$packageName" to layout.obb,
            "/sdcard/Android/data/$packageName" to layout.externalData,
            "/sdcard/Android/obb/$packageName" to layout.obb,
        )
        val (guestPrefix, destinationRoot) = mappings.firstOrNull { (prefix, _) ->
            guestPath == prefix || guestPath.startsWith("$prefix/")
        } ?: throw SecurityException("Guest path is outside supported app-private roots: $guestPath")

        val relative = guestPath.removePrefix(guestPrefix).removePrefix("/")
        val segments = if (relative.isEmpty()) emptyList() else relative.split('/')
        if (segments.any { it.isBlank() || it == "." || it == ".." }) {
            throw SecurityException("Guest path contains an unsafe segment")
        }

        var candidate = destinationRoot
        segments.forEach { segment -> candidate = candidate.resolve(segment) }
        candidate = candidate.normalize()
        if (!candidate.startsWith(destinationRoot.normalize()) || !candidate.startsWith(appRoot)) {
            throw SecurityException("Resolved guest path escaped its application root")
        }
        rejectSymlinksBetween(privateRoot.toAbsolutePath().normalize(), candidate)
        return candidate
    }

    /** Removes app-owned mutable files while retaining the imported APK and OBB expansion data. */
    fun clearGuestData() {
        initialize()
        listOf(
            appRoot.resolve("internal"),
            layout.externalFiles,
            layout.externalCache,
            layout.externalData,
        ).forEach(::deleteTree)
        initialize()
    }

    /** Removes only this app's directory and never follows symbolic links. */
    fun removeGuest() {
        val appsRoot = privateRoot.toAbsolutePath().normalize().resolve("apps")
        if (!appRoot.startsWith(appsRoot) || appRoot == appsRoot) {
            throw SecurityException("Refusing to remove a path outside the apps directory")
        }
        rejectSymlinksBetween(privateRoot.toAbsolutePath().normalize(), appRoot)
        deleteTree(appRoot)
    }

    fun storageBreakdown(): StorageBreakdown {
        if (!Files.exists(appRoot, LinkOption.NOFOLLOW_LINKS)) return StorageBreakdown(0, 0, 0, 0, 0)
        rejectSymlinksBetween(privateRoot.toAbsolutePath().normalize(), appRoot)
        return StorageBreakdown(
            apkAndMetadataBytes = directoryBytes(layout.app),
            internalBytes = directoryBytes(appRoot.resolve("internal")),
            externalBytes = directoryBytes(appRoot.resolve("external")),
            obbBytes = directoryBytes(layout.obb),
            sharedBytes = directoryBytes(layout.shared),
        )
    }

    private fun directoryBytes(directory: Path): Long {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) return 0
        rejectSymlink(directory)
        var total = 0L
        Files.walkFileTree(directory, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (attrs.isRegularFile && !attrs.isSymbolicLink) {
                    total = Math.addExact(total, attrs.size())
                }
                return FileVisitResult.CONTINUE
            }
        })
        return total
    }

    private fun requireOwnedPath(path: Path) {
        val normalized = path.toAbsolutePath().normalize()
        if (!normalized.startsWith(appRoot)) {
            throw SecurityException("Path is outside the guest application root")
        }
        rejectSymlinksBetween(privateRoot.toAbsolutePath().normalize(), normalized)
    }

    private fun rejectSymlinksBetween(base: Path, candidate: Path) {
        val normalizedBase = base.toAbsolutePath().normalize()
        val normalizedCandidate = candidate.toAbsolutePath().normalize()
        if (!normalizedCandidate.startsWith(normalizedBase)) {
            throw SecurityException("Path is outside its permitted root")
        }
        rejectSymlink(normalizedBase)
        var current = normalizedBase
        for (segment in normalizedBase.relativize(normalizedCandidate)) {
            current = current.resolve(segment)
            rejectSymlink(current)
        }
    }

    private fun rejectSymlink(path: Path) {
        if (Files.isSymbolicLink(path)) {
            throw SecurityException("Symbolic links are not allowed in guest storage: $path")
        }
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        Files.walkFileTree(path, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                Files.delete(file)
                return FileVisitResult.CONTINUE
            }

            override fun postVisitDirectory(directory: Path, failure: IOException?): FileVisitResult {
                if (failure != null) throw failure
                Files.delete(directory)
                return FileVisitResult.CONTINUE
            }
        })
    }

    companion object {
        private val PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
        private val APP_ID_PATTERN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
    }
}
