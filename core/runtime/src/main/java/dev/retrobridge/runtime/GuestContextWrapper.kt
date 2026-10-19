package dev.retrobridge.runtime

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.DirectoryStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.CRC32
import java.util.zip.ZipFile

/**
 * Host-side storage and asset facade for one imported guest. It deliberately does not extend
 * android.content.ContextWrapper and does not make Java/Activity APIs callable by guest code.
 */
class GuestContextWrapper(private val context: GuestRuntimeContext) {
    private val preferences = ConcurrentHashMap<String, GuestPreferences>()

    val packageName: String get() = context.packageName
    val packageManager: GuestPackageManager = GuestPackageManager(context)

    val dataDir: Path get() = ensureDirectory(context.internalRoot)
    val filesDir: Path get() = ensureDirectory(context.internalRoot.resolve("files"))
    val cacheDir: Path get() = ensureDirectory(context.internalRoot.resolve("cache"))
    val noBackupFilesDir: Path get() = ensureDirectory(context.internalRoot.resolve("no_backup"))
    val codeCacheDir: Path get() = ensureDirectory(context.internalRoot.resolve("code_cache"))
    val externalDataDir: Path get() = ensureDirectory(context.externalDataRoot)
    val externalCacheDir: Path get() = ensureDirectory(context.externalDataRoot.resolve("cache"))
    val obbDir: Path get() = ensureDirectory(context.obbRoot)
    val sharedPreferencesDir: Path get() = ensureDirectory(context.internalRoot.resolve("shared_prefs"))

    fun externalFilesDir(type: String? = null): Path {
        val base = ensureDirectory(context.externalDataRoot.resolve("files"))
        if (type == null) return base
        validateSinglePathComponent(type, "external files type")
        return ensureDirectory(base.resolve(type))
    }

    /** Creates the standard private directories before a native session starts. */
    fun prepareStorageDirectories() {
        dataDir
        filesDir
        cacheDir
        noBackupFilesDir
        codeCacheDir
        externalDataDir
        externalFilesDir()
        externalCacheDir
        obbDir
        sharedPreferencesDir
    }

    fun getSharedPreferences(name: String): GuestPreferences {
        validateSinglePathComponent(name, "preferences name")
        return preferences.computeIfAbsent(name) {
            val parent = sharedPreferencesDir
            val file = checkedPath(parent.resolve("$name.guestprefs"))
            GuestPreferences(file)
        }
    }

    fun openFileInput(name: String): InputStream {
        val file = resolvePrivateFile(name)
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Guest private file is missing or is not a regular file")
        }
        return Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)
    }

    fun openFileOutput(name: String, append: Boolean = false): OutputStream {
        val file = resolvePrivateFile(name)
        if (Files.isSymbolicLink(file)) throw SecurityException("Guest private files cannot be symbolic links")
        return if (append) {
            Files.newOutputStream(
                file,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND,
                LinkOption.NOFOLLOW_LINKS,
            )
        } else {
            Files.newOutputStream(
                file,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS,
            )
        }
    }

    fun deleteFile(name: String): Boolean {
        val file = resolvePrivateFile(name)
        if (Files.isSymbolicLink(file)) throw SecurityException("Guest private files cannot be symbolic links")
        return Files.deleteIfExists(file)
    }

    fun fileList(): List<String> {
        val directory = filesDir
        val names = ArrayList<String>()
        Files.newDirectoryStream(directory).use { entries: DirectoryStream<Path> ->
            for (entry in entries) {
                checkedPath(entry)
                if (Files.isSymbolicLink(entry)) throw SecurityException("Guest private files cannot be symbolic links")
                if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) names += entry.fileName.toString()
            }
        }
        return names.sorted()
    }

    /** Reads one exact `assets/` ZIP entry, bounded to 64 MiB, without extracting it to disk. */
    fun readAsset(name: String, maximumBytes: Int = MAX_ASSET_BYTES): ByteArray {
        validateAssetName(name)
        require(maximumBytes in 0..MAX_ASSET_BYTES) { "Asset read limit is outside the supported range" }
        val targetName = "assets/$name"
        return ZipFile(context.apkPath.toFile()).use { archive ->
            var entryCount = 0
            var target: java.util.zip.ZipEntry? = null
            val entries = archive.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entryCount++
                if (entryCount > MAX_APK_ENTRIES) throw IOException("APK entry count exceeds the asset-read limit")
                if (entry.name == targetName) {
                    if (target != null) throw IOException("APK contains duplicate asset entry: $name")
                    target = entry
                }
            }
            val entry = target ?: throw java.io.FileNotFoundException("Guest APK asset was not found: $name")
            if (entry.isDirectory) throw IOException("Guest APK asset is a directory: $name")
            if (entry.size > maximumBytes.toLong()) throw IOException("Guest APK asset exceeds the read limit: $name")
            val output = ByteArrayOutputStream(entry.size.takeIf { it >= 0 }?.coerceAtMost(64 * 1024L)?.toInt() ?: 0)
            val crc = CRC32()
            archive.getInputStream(entry).use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) {
                        val value = input.read()
                        if (value < 0) break
                        if (total >= maximumBytes) throw IOException("Guest APK asset expanded beyond the read limit: $name")
                        output.write(value)
                        crc.update(value)
                        total++
                        continue
                    }
                    if (count > maximumBytes - total) throw IOException("Guest APK asset expanded beyond the read limit: $name")
                    output.write(buffer, 0, count)
                    crc.update(buffer, 0, count)
                    total += count
                }
                if ((entry.size >= 0 && total.toLong() != entry.size) || (entry.crc >= 0L && crc.value != entry.crc)) {
                    throw IOException("Guest APK asset size or CRC changed while reading: $name")
                }
            }
            output.toByteArray()
        }
    }

    private fun resolvePrivateFile(name: String): Path {
        validateSinglePathComponent(name, "guest file name")
        val directory = filesDir
        val file = checkedPath(directory.resolve(name))
        if (file.parent != directory) throw SecurityException("Guest private file escaped its directory")
        return file
    }

    private fun ensureDirectory(path: Path): Path {
        val checked = checkedPath(path)
        Files.createDirectories(checked)
        val verified = checkedPath(checked)
        if (!Files.isDirectory(verified, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Guest storage path is not a directory: $verified")
        }
        return verified
    }

    private fun checkedPath(path: Path): Path {
        val normalized = path.toAbsolutePath().normalize()
        val storageMappings = listOf(
            context.internalRoot to "/data/user/0/${context.packageName}",
            context.externalDataRoot to "/storage/emulated/0/Android/data/${context.packageName}",
            context.obbRoot to "/storage/emulated/0/Android/obb/${context.packageName}",
        )
        val (root, guestPrefix) = storageMappings.firstOrNull { (candidate, _) ->
            normalized.startsWith(candidate.toAbsolutePath().normalize())
        } ?: throw SecurityException("Guest storage path is outside the selected package roots")
        val normalizedRoot = root.toAbsolutePath().normalize()
        val relative = normalizedRoot.relativize(normalized)
        val suffix = relative.joinToString("/") { it.toString() }
        val guestPath = guestPrefix + if (suffix.isEmpty()) "" else "/$suffix"
        val resolved = context.resolveGuestPath(guestPath).toAbsolutePath().normalize()
        if (resolved != normalized) throw SecurityException("Guest storage path does not match its validated mapping")
        return resolved
    }

    private fun validateSinglePathComponent(value: String, label: String) {
        require(value.isNotBlank() && value.length <= MAX_PATH_COMPONENT_LENGTH
            && value != "." && value != ".."
            && '/' !in value && '\\' !in value && '\u0000' !in value && ':' !in value) {
            "Invalid $label"
        }
    }

    private fun validateAssetName(name: String) {
        require(name.isNotBlank() && name.length <= MAX_ASSET_PATH_LENGTH
            && !name.startsWith('/') && '\\' !in name && '\u0000' !in name) { "Invalid APK asset path" }
        val segments = name.split('/')
        require(segments.all { it.isNotBlank() && it != "." && it != ".." && ':' !in it }) {
            "APK asset path contains an unsafe segment"
        }
    }

    private companion object {
        const val MAX_PATH_COMPONENT_LENGTH = 255
        const val MAX_ASSET_PATH_LENGTH = 4096
        const val MAX_ASSET_BYTES = 64 * 1024 * 1024
        const val MAX_APK_ENTRIES = 100_000
    }
}

/**
 * Metadata projection for exactly one imported guest. It is not Android's system PackageManager
 * and cannot enumerate host or other guest packages.
 */
class GuestPackageManager internal constructor(private val context: GuestRuntimeContext) {
    fun getPackageInfo(packageName: String): GuestPackageInfo? {
        if (packageName != context.packageName) return null
        val metadata = context.packageMetadata
        return GuestPackageInfo(
            packageName = metadata.packageName,
            applicationLabel = metadata.applicationLabel,
            versionName = metadata.versionName,
            versionCode = metadata.versionCode,
            minSdk = metadata.minSdk,
            targetSdk = metadata.targetSdk,
            apkSha256 = context.apkSha256,
            guestAbis = context.guestAbis.toList(),
        )
    }
}

data class GuestPackageInfo(
    val packageName: String,
    val applicationLabel: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val apkSha256: String,
    val guestAbis: List<String>,
)
