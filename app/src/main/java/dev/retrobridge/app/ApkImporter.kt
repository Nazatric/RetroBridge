package dev.retrobridge.app

import android.content.Context
import android.content.pm.PackageInfo
import android.net.Uri
import android.os.Build
import dev.retrobridge.fs.ArchiveImportResult
import dev.retrobridge.fs.GuestExportResult
import dev.retrobridge.fs.GuestStorage
import dev.retrobridge.fs.ObbImportResult
import dev.retrobridge.manager.AttachmentState
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.manager.GuestAppRepository
import dev.retrobridge.manager.GuestAppState
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

/** Copies a selected APK into private storage; it does not install or execute the package. */
class ApkImporter(
    context: Context,
    private val privateRoot: Path,
    private val repository: GuestAppRepository,
) {
    private val applicationContext = context.applicationContext

    fun importApk(uri: Uri): GuestAppRecord {
        val temporaryDirectory = privateRoot.resolve("tmp")
        Files.createDirectories(temporaryDirectory)
        val temporaryApk = Files.createTempFile(temporaryDirectory, "apk-import-", ".part")
        var finalStorage: GuestStorage? = null
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val byteCount = copyAndDigest(uri, temporaryApk, digest)
            if (byteCount == 0L) throw IllegalArgumentException("The selected APK is empty")

            val packageInfo = readPackageInfo(temporaryApk.toFile())
            val appInfo = packageInfo.applicationInfo
                ?: throw IllegalArgumentException("APK does not contain Android application metadata")
            appInfo.sourceDir = temporaryApk.toString()
            appInfo.publicSourceDir = temporaryApk.toString()
            val packageName = packageInfo.packageName
                ?: throw IllegalArgumentException("APK manifest has no package name")
            val displayName = applicationContext.packageManager.getApplicationLabel(appInfo)
                .toString().takeIf(String::isNotBlank) ?: packageName
            val nativeLibraries = inspectNativeLibraries(temporaryApk)
            @Suppress("DEPRECATION")
            val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                packageInfo.versionCode.toLong()
            }
            val applicationId = UUID.randomUUID().toString()
            val storage = GuestStorage(privateRoot, packageName, applicationId)
            finalStorage = storage
            storage.initialize()

            val destination = storage.layout.app.resolve("base.apk")
            try {
                Files.move(temporaryApk, destination, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temporaryApk, destination, StandardCopyOption.REPLACE_EXISTING)
            }

            val relativeRoot = privateRoot.toAbsolutePath().normalize().relativize(storage.appRoot).toPortableString()
            val relativeApk = privateRoot.toAbsolutePath().normalize().relativize(destination.toAbsolutePath().normalize()).toPortableString()
            val now = System.currentTimeMillis()
            val record = GuestAppRecord(
                id = applicationId,
                packageName = packageName,
                displayName = displayName,
                versionName = packageInfo.versionName,
                versionCode = versionCode,
                minSdk = appInfo.minSdkVersion.takeIf { it > 0 },
                targetSdk = appInfo.targetSdkVersion.takeIf { it > 0 },
                originalApkPath = relativeApk,
                sha256 = digest.digest().toHexString(),
                guestAbis = nativeLibraries.keys.sorted(),
                nativeLibraries = nativeLibraries,
                isolatedRoot = relativeRoot,
                dataArchiveState = AttachmentState.NOT_PROVIDED,
                obbState = AttachmentState.NOT_PROVIDED,
                state = GuestAppState.IMPORTED,
                createdAtEpochMs = now,
                updatedAtEpochMs = now,
            )
            record.validate()
            repository.upsert(record)
            return record
        } catch (failure: Exception) {
            finalStorage?.removeGuest()
            throw failure
        } finally {
            Files.deleteIfExists(temporaryApk)
        }
    }

    fun clearData(record: GuestAppRecord) {
        storageFor(record).clearGuestData()
    }

    fun importDataArchive(record: GuestAppRecord, input: java.io.InputStream): Pair<GuestAppRecord, ArchiveImportResult> {
        val current = requireCurrentRecord(record)
        val imported = storageFor(current).importAndroidDataArchive(input)
        val updated = repository.update(current.id) { latest ->
            latest.copy(
                dataArchiveState = AttachmentState.IMPORTED,
                updatedAtEpochMs = maxOf(System.currentTimeMillis(), latest.updatedAtEpochMs),
            )
        }
        return updated to imported
    }

    fun importObbFile(
        record: GuestAppRecord,
        filename: String,
        input: java.io.InputStream,
    ): Pair<GuestAppRecord, ObbImportResult> {
        val current = requireCurrentRecord(record)
        val imported = storageFor(current).importObbFile(input, filename)
        return updateObbManifest(current.id, imported)
    }

    fun importObbBundle(record: GuestAppRecord, input: java.io.InputStream): Pair<GuestAppRecord, ObbImportResult> {
        val current = requireCurrentRecord(record)
        val imported = storageFor(current).importObbBundle(input)
        return updateObbManifest(current.id, imported)
    }

    fun exportGuestData(record: GuestAppRecord, output: java.io.OutputStream): GuestExportResult =
        storageFor(requireCurrentRecord(record)).exportGuestData(output)

    fun remove(record: GuestAppRecord) {
        val stored = repository.get(record.id) ?: return
        require(stored.packageName == record.packageName) { "Application identity mismatch" }
        storageFor(stored).removeGuest()
        repository.remove(stored.id)
    }

    fun storageBreakdown(record: GuestAppRecord) = storageFor(record).storageBreakdown()

    private fun requireCurrentRecord(record: GuestAppRecord): GuestAppRecord {
        val current = repository.get(record.id) ?: throw NoSuchElementException("Application was removed")
        require(current.packageName == record.packageName) { "Application identity mismatch" }
        return current
    }

    private fun updateObbManifest(id: String, imported: ObbImportResult): Pair<GuestAppRecord, ObbImportResult> {
        val updated = repository.update(id) { latest ->
            latest.copy(
                obbState = AttachmentState.IMPORTED,
                obbFiles = (latest.obbFiles + imported.paths).distinct().sorted(),
                updatedAtEpochMs = maxOf(System.currentTimeMillis(), latest.updatedAtEpochMs),
            )
        }
        return updated to imported
    }

    private fun storageFor(record: GuestAppRecord): GuestStorage {
        val expectedRoot = privateRoot.toAbsolutePath().normalize()
            .resolve("apps")
            .resolve(record.packageName)
            .resolve(record.id)
            .normalize()
        require(record.isolatedRoot == privateRoot.toAbsolutePath().normalize().relativize(expectedRoot).toPortableString()) {
            "Registry root does not match the guest's validated identity"
        }
        return GuestStorage(privateRoot, record.packageName, record.id)
    }

    private fun copyAndDigest(uri: Uri, destination: Path, digest: MessageDigest): Long {
        val input = applicationContext.contentResolver.openInputStream(uri)
            ?: throw IOException("Unable to read the selected document")
        var total = 0L
        input.use { source ->
            Files.newOutputStream(destination).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = source.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    if (total > MAX_APK_BYTES - count) {
                        throw IllegalArgumentException("APK exceeds the $MAX_APK_BYTES byte import limit")
                    }
                    digest.update(buffer, 0, count)
                    output.write(buffer, 0, count)
                    total += count
                }
            }
        }
        return total
    }

    @Suppress("DEPRECATION")
    private fun readPackageInfo(apk: File): PackageInfo {
        return applicationContext.packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
            ?: throw IllegalArgumentException("Selected document is not a readable Android APK")
    }

    private fun inspectNativeLibraries(apk: Path): Map<String, List<String>> {
        val knownAbis = setOf("armeabi-v7a", "armeabi", "arm64-v8a", "x86", "x86_64", "riscv64")
        val libraries = mutableMapOf<String, MutableSet<String>>()
        ZipFile(apk.toFile()).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                val components = entry.name.split('/')
                if (components.size >= 3 && components[0] == "lib" && components[1] in knownAbis
                    && components.last().endsWith(".so")
                ) {
                    libraries.getOrPut(components[1]) { linkedSetOf() }.add(components.last())
                }
            }
        }
        return libraries.mapValues { (_, names) -> names.sorted() }.toSortedMap()
    }

    private fun Path.toPortableString(): String = toString().replace(File.separatorChar, '/')

    private fun ByteArray.toHexString(): String = joinToString(separator = "") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    companion object {
        private const val MAX_APK_BYTES = 2L * 1024 * 1024 * 1024
    }
}
