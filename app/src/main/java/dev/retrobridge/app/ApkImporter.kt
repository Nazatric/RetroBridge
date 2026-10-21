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
import dev.retrobridge.manager.GuestDiagnostic
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

private data class NativeLibraryInspection(
    val libraries: Map<String, List<String>>,
    val diagnostics: List<GuestDiagnostic>,
)

internal fun copyBoundedAndDigest(
    source: InputStream,
    destination: OutputStream,
    maximumBytes: Long,
    digest: MessageDigest,
): Long {
    require(maximumBytes >= 0) { "Byte limit cannot be negative" }
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    var total = 0L
    while (true) {
        val count = source.read(buffer)
        if (count < 0) break
        val bytesRead: Int
        if (count == 0) {
            val next = source.read()
            if (next < 0) break
            buffer[0] = next.toByte()
            bytesRead = 1
        } else {
            bytesRead = count
        }
        if (total > maximumBytes - bytesRead.toLong()) {
            throw IllegalArgumentException("Import exceeds the $maximumBytes byte limit")
        }
        digest.update(buffer, 0, bytesRead)
        destination.write(buffer, 0, bytesRead)
        total += bytesRead
    }
    return total
}

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
            val nativeLibraryInspection = inspectNativeLibraries(temporaryApk)
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
                guestAbis = nativeLibraryInspection.libraries.keys.sorted(),
                nativeLibraries = nativeLibraryInspection.libraries,
                diagnostics = nativeLibraryInspection.diagnostics.map { diagnostic ->
                    diagnostic.copy(guestId = applicationId, packageName = packageName)
                },
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
        return input.use { source ->
            Files.newOutputStream(destination).use { output ->
                copyBoundedAndDigest(source, output, MAX_APK_BYTES, digest)
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun readPackageInfo(apk: File): PackageInfo {
        return applicationContext.packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
            ?: throw IllegalArgumentException("Selected document is not a readable Android APK")
    }

    private fun inspectNativeLibraries(apk: Path): NativeLibraryInspection {
        val knownAbis = setOf("armeabi-v7a", "armeabi", "arm64-v8a", "x86", "x86_64", "riscv64")
        val libraries = mutableMapOf<String, MutableSet<String>>()
        val diagnostics = mutableListOf(
            GuestDiagnostic(
                timestampEpochMs = System.currentTimeMillis(),
                severity = "INFO",
                component = "APK native preflight",
                message = "ELF header checks do not establish library loadability",
                detail = "Passing this bounded structural preflight does not validate dependencies, relocations, symbols, or guest APK launch support.",
                code = "ELF_PREFLIGHT_NOT_LOADABILITY_TEST",
                category = "ELF_LOADING",
                operation = "APK_PREFLIGHT",
                nextAction = "Attempt the selected native runtime path to inspect dependencies and relocations; that still will not verify guest Java or Activity behavior.",
            ),
        )
        var scannedEntries = 0
        var scannedLibraries = 0
        var preflightedLibraries = 0
        var preflightLimitReported = false
        var omittedDiagnostics = 0
        val timestamp = System.currentTimeMillis()
        fun report(message: String, detail: String? = null) {
            if (diagnostics.size < MAX_NATIVE_PREFLIGHT_DIAGNOSTICS) {
                diagnostics += GuestDiagnostic(
                    timestampEpochMs = timestamp,
                    severity = "WARNING",
                    component = "APK native preflight",
                    message = message,
                    detail = detail?.take(1024),
                    code = when {
                        message.contains("limit", ignoreCase = true) -> "PREFLIGHT_RESOURCE_LIMIT"
                        message.contains("path", ignoreCase = true) -> "UNSUPPORTED_NATIVE_ARCHIVE_PATH"
                        else -> "NATIVE_ELF_PREFLIGHT_WARNING"
                    },
                    category = if (detail.orEmpty().contains(".so", ignoreCase = true)) "ELF_LOADING" else "APK_IMPORT",
                    operation = "APK_PREFLIGHT",
                    library = detail?.substringBefore(':')?.substringAfterLast('/')
                        ?.takeIf { it.endsWith(".so", ignoreCase = true) }?.take(255),
                    nextAction = "Review the technical detail; APK preflight is structural only and does not prove runtime loadability.",
                )
            } else {
                omittedDiagnostics++
            }
        }

        ZipFile(apk.toFile()).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                if (++scannedEntries > MAX_APK_ZIP_ENTRIES) {
                    report("APK contains more ZIP entries than the preflight limit", "Remaining entries were not scanned")
                    break
                }
                val entry = entries.nextElement()
                if (entry.isDirectory || !entry.name.endsWith(".so")) continue
                val components = entry.name.split('/')
                if (components.firstOrNull() != "lib") continue
                if (++scannedLibraries > MAX_NATIVE_LIBRARY_ENTRIES) {
                    report("APK contains more native libraries than the preflight limit", "Remaining libraries were not scanned")
                    break
                }
                if (entry.name.length > 4_096 || components.size != 3 || components[1] !in knownAbis
                    || components[2].length <= 3 || components[2].length > 256
                ) {
                    report("Native library has an unsupported archive path", entry.name)
                    continue
                }

                val abi = components[1]
                val name = components[2]
                libraries.getOrPut(abi) { linkedSetOf() }.add(name)
                if (preflightedLibraries >= MAX_NATIVE_LIBRARY_PREFLIGHTS) {
                    if (!preflightLimitReported) {
                        report("Native ELF preflight byte-work limit reached", "Additional native libraries were cataloged by filename only")
                        preflightLimitReported = true
                    }
                    continue
                }
                preflightedLibraries++
                val result = try {
                    zip.getInputStream(entry).use { stream ->
                        NativeElfPreflight.inspect(abi, entry.name.take(1024), entry.size, stream)
                    }
                } catch (failure: Exception) {
                    report("Native library preflight could not read the ELF entry", "${entry.name}: ${failure.message ?: failure.javaClass.simpleName}")
                    continue
                }
                result.diagnostic?.let { reason ->
                    report("Native library did not pass the bounded ELF preflight", "${entry.name}: $reason")
                }
            }
        }
        if (omittedDiagnostics > 0) {
            diagnostics += GuestDiagnostic(
                timestampEpochMs = timestamp,
                severity = "WARNING",
                component = "APK native preflight",
                message = "Additional native preflight diagnostics were omitted",
                detail = "$omittedDiagnostics diagnostic(s) omitted to bound registry size",
                code = "PREFLIGHT_DIAGNOSTIC_COUNT_LIMIT",
                category = "APK_IMPORT",
                operation = "APK_PREFLIGHT",
                nextAction = "Use the exported diagnostic report; only a bounded subset of native entries was inspected.",
            )
        }
        return NativeLibraryInspection(
            libraries = libraries.mapValues { (_, names) -> names.sorted() }.toSortedMap(),
            diagnostics = diagnostics,
        )
    }

    private fun Path.toPortableString(): String = toString().replace(File.separatorChar, '/')

    private fun ByteArray.toHexString(): String = joinToString(separator = "") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    companion object {
        private const val MAX_APK_BYTES = 2L * 1024 * 1024 * 1024
        private const val MAX_APK_ZIP_ENTRIES = 100_000
        private const val MAX_NATIVE_LIBRARY_ENTRIES = 8_192
        private const val MAX_NATIVE_LIBRARY_PREFLIGHTS = 256
        private const val MAX_NATIVE_PREFLIGHT_DIAGNOSTICS = 64
    }
}
