package dev.retrobridge.fs

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

data class ArchiveImportResult(val filesImported: Int, val uncompressedBytes: Long)
data class ObbImportResult(val paths: List<String>, val bytesImported: Long)
data class GuestExportResult(val filesExported: Int, val bytesExported: Long, val obbFiles: List<String>)

/** Streaming, quota-bounded archive operations for one private GuestStorage root. */
internal class GuestArchiveOperations(private val storage: GuestStorage) {
    private val appRoot = storage.appRoot
    private val privateRoot: Path = appRoot.parent.parent.parent
    private val dataPrefix = "/storage/emulated/0/Android/data/${storage.packageName}"
    private val obbPrefix = "/storage/emulated/0/Android/obb/${storage.packageName}"

    fun importAndroidDataArchive(input: InputStream): ArchiveImportResult {
        storage.initialize()
        val transaction = Files.createTempDirectory(appRoot, ".data-import-")
        try {
            val archive = transaction.resolve("upload.zip")
            val compressedBytes = copyLimited(input, archive, DATA_ARCHIVE_MAX_COMPRESSED_BYTES)
            if (compressedBytes == 0L) throw ZipException("Android/data archive is empty")
            val payload = transaction.resolve("payload")
            Files.createDirectories(payload)
            val symlinks = ZipUnixMetadata.symlinkEntries(archive)
            val seenFiles = mutableSetOf<String>()
            val stagedFiles = mutableListOf<StagedFile>()
            var totalBytes = 0L
            var entryCount = 0

            ZipFile(archive.toFile(), Charset.forName("CP437")).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    entryCount += 1
                    if (entryCount > DATA_ARCHIVE_MAX_ENTRIES) {
                        throw IOException("Android/data archive exceeds the $DATA_ARCHIVE_MAX_ENTRIES entry limit")
                    }
                    if (entry.name in symlinks) {
                        throw SecurityException("Symbolic-link ZIP entries are not accepted: ${entry.name}")
                    }
                    val relative = normalizeDataEntry(entry.name) ?: continue
                    val target = safeResolve(payload, relative)
                    if (entry.isDirectory) {
                        Files.createDirectories(target)
                        continue
                    }
                    if (!seenFiles.add(relative)) {
                        throw IOException("Archive contains duplicate normalized file path: $relative")
                    }
                    if (entry.size > DATA_ARCHIVE_MAX_FILE_BYTES) {
                        throw IOException("Archive entry exceeds per-file limit: $relative")
                    }
                    Files.createDirectories(target.parent)
                    val count = zip.getInputStream(entry).use { source ->
                        copyLimited(source, target, DATA_ARCHIVE_MAX_FILE_BYTES, DATA_ARCHIVE_MAX_BYTES - totalBytes)
                    }
                    totalBytes = Math.addExact(totalBytes, count)
                    stagedFiles += StagedFile(relative, target)
                }
            }

            commitFiles(
                transaction = transaction,
                destinationRoot = storage.layout.externalData,
                guestPrefix = dataPrefix,
                stagedFiles = stagedFiles,
            )
            return ArchiveImportResult(stagedFiles.size, totalBytes)
        } finally {
            deleteTree(transaction)
        }
    }

    fun importObbFile(input: InputStream, filename: String): ObbImportResult {
        storage.initialize()
        validateObbName(filename)
        val transaction = Files.createTempDirectory(appRoot, ".obb-import-")
        try {
            val staged = transaction.resolve(filename)
            val bytes = copyLimited(input, staged, OBB_MAX_FILE_BYTES)
            if (bytes == 0L) throw IOException("OBB file is empty: $filename")
            commitFiles(
                transaction = transaction,
                destinationRoot = storage.layout.obb,
                guestPrefix = obbPrefix,
                stagedFiles = listOf(StagedFile(filename, staged)),
            )
            return ObbImportResult(listOf(relativeToPrivateRoot(storage.layout.obb.resolve(filename))), bytes)
        } finally {
            deleteTree(transaction)
        }
    }

    fun importObbBundle(input: InputStream): ObbImportResult {
        storage.initialize()
        val transaction = Files.createTempDirectory(appRoot, ".obb-bundle-import-")
        try {
            val archive = transaction.resolve("bundle.zip")
            val compressedBytes = copyLimited(input, archive, OBB_BUNDLE_MAX_COMPRESSED_BYTES)
            if (compressedBytes == 0L) throw ZipException("OBB archive is empty")
            val payload = transaction.resolve("payload")
            Files.createDirectories(payload)
            val symlinks = ZipUnixMetadata.symlinkEntries(archive)
            val names = mutableSetOf<String>()
            val stagedFiles = mutableListOf<StagedFile>()
            var uncompressedBytes = 0L
            var entries = 0

            ZipFile(archive.toFile(), Charset.forName("CP437")).use { zip ->
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry = enumeration.nextElement()
                    entries += 1
                    if (entries > OBB_BUNDLE_MAX_ENTRIES) {
                        throw IOException("OBB archive exceeds the $OBB_BUNDLE_MAX_ENTRIES entry limit")
                    }
                    if (entry.name in symlinks) {
                        throw SecurityException("Symbolic-link ZIP entries are not accepted: ${entry.name}")
                    }
                    if (entry.isDirectory) {
                        validateObbArchivePrefix(validateArchivePath(entry.name, allowTrailingSlash = true))
                        continue
                    }
                    val components = validateArchivePath(entry.name, allowTrailingSlash = false)
                    validateObbArchivePrefix(components)
                    val filename = components.last()
                    validateObbName(filename)
                    if (!names.add(filename)) throw IOException("Duplicate OBB filename in bundle: $filename")
                    if (entry.size > OBB_MAX_FILE_BYTES) throw IOException("OBB entry exceeds file-size limit: $filename")
                    val staged = safeResolve(payload, filename)
                    val count = zip.getInputStream(entry).use { source ->
                        copyLimited(source, staged, OBB_MAX_FILE_BYTES, OBB_BUNDLE_MAX_UNCOMPRESSED_BYTES - uncompressedBytes)
                    }
                    if (count == 0L) throw IOException("OBB entry is empty: $filename")
                    uncompressedBytes = Math.addExact(uncompressedBytes, count)
                    stagedFiles += StagedFile(filename, staged)
                }
            }
            if (stagedFiles.isEmpty()) throw IOException("OBB bundle contains no associated .obb files")
            commitFiles(
                transaction = transaction,
                destinationRoot = storage.layout.obb,
                guestPrefix = obbPrefix,
                stagedFiles = stagedFiles,
            )
            val paths = stagedFiles.map { relativeToPrivateRoot(storage.layout.obb.resolve(it.relativePath)) }
            return ObbImportResult(paths, uncompressedBytes)
        } finally {
            deleteTree(transaction)
        }
    }

    fun exportGuestData(output: OutputStream): GuestExportResult {
        storage.initialize()
        val includedRoots = listOf(
            appRoot.resolve("internal"),
            appRoot.resolve("external"),
            appRoot.resolve("obb"),
        )
        val files = mutableListOf<Path>()
        includedRoots.forEach { root ->
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return@forEach
            rejectSymlink(root)
            Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (attrs.isSymbolicLink) throw SecurityException("Cannot export a symbolic link: $file")
                    if (attrs.isRegularFile) files.add(file)
                    return FileVisitResult.CONTINUE
                }
            })
        }
        val orderedFiles = files.sortedBy { appRoot.relativize(it).toPortablePath() }
        val total = orderedFiles.fold(0L) { acc, file -> Math.addExact(acc, Files.size(file)) }
        if (total > EXPORT_MAX_BYTES) throw IOException("Guest data exceeds the export quota")
        val obbFiles = orderedFiles
            .map { appRoot.relativize(it).toPortablePath() }
            .filter { it.startsWith("obb/") }
        val manifest = buildManifest(orderedFiles, obbFiles)

        ZipOutputStream(output, StandardCharsets.UTF_8).use { zip ->
            val manifestEntry = ZipEntry("manifest.json").apply { time = 0L }
            zip.putNextEntry(manifestEntry)
            zip.write(manifest.toByteArray(StandardCharsets.UTF_8))
            zip.closeEntry()
            orderedFiles.forEach { file ->
                rejectSymlink(file)
                rejectSymlinkComponents(appRoot, file)
                val entryName = appRoot.relativize(file).toPortablePath()
                zip.putNextEntry(ZipEntry(entryName).apply { time = 0L })
                Files.newInputStream(file).use { source -> source.copyTo(zip, DEFAULT_BUFFER_SIZE) }
                zip.closeEntry()
            }
        }
        return GuestExportResult(orderedFiles.size, total, obbFiles)
    }

    private fun buildManifest(files: List<Path>, obbFiles: List<String>): String {
        val inventory = files.joinToString(",") { file ->
            val path = appRoot.relativize(file).toPortablePath()
            "{\"path\":${jsonString(path)},\"size\":${Files.size(file)}}"
        }
        val obb = obbFiles.joinToString(",") { jsonString(it) }
        return "{\"format\":1,\"packageName\":${jsonString(storage.packageName)}," +
            "\"applicationId\":${jsonString(storage.applicationId)},\"obbFiles\":[${obb}],\"files\":[${inventory}]}"
    }

    private fun commitFiles(
        transaction: Path,
        destinationRoot: Path,
        guestPrefix: String,
        stagedFiles: List<StagedFile>,
    ) {
        val backupRoot = transaction.resolve("rollback")
        val replacements = mutableListOf<Replacement>()
        try {
            stagedFiles.forEachIndexed { index, item ->
                val destination = destinationRoot.resolve(item.relativePath).normalize()
                if (!destination.startsWith(destinationRoot.normalize())) {
                    throw SecurityException("Archive path escaped destination root")
                }
                val guestPath = "$guestPrefix/${item.relativePath}"
                val validated = storage.resolveGuestPath(guestPath)
                if (validated != destination) throw SecurityException("Guest path mapping mismatch")
                Files.createDirectories(destination.parent)
                rejectSymlinkComponents(destinationRoot, destination)
                var backup: Path? = null
                if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.isRegularFile(destination, LinkOption.NOFOLLOW_LINKS)) {
                        throw IOException("Refusing to replace a non-file guest path: $destination")
                    }
                    Files.createDirectories(backupRoot)
                    backup = backupRoot.resolve(index.toString())
                    move(destination, backup)
                }
                try {
                    move(item.stagedPath, destination)
                    replacements += Replacement(destination, backup)
                } catch (failure: Exception) {
                    if (backup != null && Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) move(backup, destination)
                    throw failure
                }
            }
        } catch (failure: Exception) {
            replacements.asReversed().forEach { replacement ->
                runCatching {
                    Files.deleteIfExists(replacement.destination)
                    replacement.backup?.takeIf { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }
                        ?.let { move(it, replacement.destination) }
                }
            }
            throw failure
        }
    }

    private fun normalizeDataEntry(raw: String): String? {
        val components = validateArchivePath(raw, allowTrailingSlash = true).toMutableList()
        if (components.isEmpty()) return null
        if (components.size >= 2 && components[0] == "Android" && components[1] == "data") {
            if (components.size < 3 || components[2] != storage.packageName) {
                throw SecurityException("Android/data archive path does not match package ${storage.packageName}")
            }
            repeat(3) { components.removeAt(0) }
        } else if (components.firstOrNull()?.matches(PACKAGE_COMPONENT_PATTERN) == true) {
            if (components[0] != storage.packageName) {
                throw SecurityException("Archive path does not match package ${storage.packageName}")
            }
            components.removeAt(0)
        }
        if (components.isEmpty()) return null
        return components.joinToString("/")
    }

    private fun validateObbArchivePrefix(components: List<String>) {
        if (components.size >= 2 && components[0] == "Android" && components[1] == "obb") {
            if (components.size < 3 || components[2] != storage.packageName) {
                throw SecurityException("OBB bundle path does not match package ${storage.packageName}")
            }
        } else if (components.firstOrNull()?.matches(PACKAGE_COMPONENT_PATTERN) == true) {
            if (components[0] != storage.packageName) {
                throw SecurityException("OBB bundle path does not match package ${storage.packageName}")
            }
        }
    }

    private fun validateArchivePath(raw: String, allowTrailingSlash: Boolean): List<String> {
        if (raw.isEmpty() || raw.startsWith('/') || raw.startsWith('\\') || '\u0000' in raw || '\\' in raw) {
            throw SecurityException("Unsafe ZIP entry path: $raw")
        }
        val path = if (allowTrailingSlash) raw.removeSuffix("/") else raw
        if (path.isEmpty()) return emptyList()
        val components = path.split('/')
        if (components.any { it.isBlank() || it == "." || it == ".." || it.contains(':') }) {
            throw SecurityException("ZIP entry contains an unsafe path segment: $raw")
        }
        return components
    }

    private fun validateObbName(filename: String) {
        if (filename.contains('/') || filename.contains('\\') || filename.contains('\u0000')) {
            throw SecurityException("OBB filename must be a single path component")
        }
        val pattern = Regex("^(main|patch)\\.([1-9][0-9]*)\\.${Regex.escape(storage.packageName)}\\.obb$")
        if (!pattern.matches(filename)) {
            throw IllegalArgumentException("OBB name must be main.<version>.${storage.packageName}.obb or patch.<version>.${storage.packageName}.obb")
        }
    }

    private fun safeResolve(base: Path, relative: String): Path {
        val target = relative.split('/').fold(base) { current, part -> current.resolve(part) }.normalize()
        if (!target.startsWith(base.normalize())) throw SecurityException("Archive entry escaped staging root")
        rejectSymlinkComponents(base, target)
        return target
    }

    private fun copyLimited(
        input: InputStream,
        destination: Path,
        perFileLimit: Long,
        remainingTotalLimit: Long = perFileLimit,
    ): Long {
        if (remainingTotalLimit < 0) throw IOException("Archive exceeds decompressed-size quota")
        var copied = 0L
        Files.newOutputStream(destination).use { output ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                val amount = count.toLong()
                if (copied > perFileLimit - amount || copied > remainingTotalLimit - amount) {
                    throw IOException("Archive exceeds configured decompression quota")
                }
                output.write(buffer, 0, count)
                copied += amount
            }
        }
        return copied
    }

    private fun relativeToPrivateRoot(path: Path): String {
        val normalizedRoot = privateRoot.toAbsolutePath().normalize()
        val normalizedPath = path.toAbsolutePath().normalize()
        if (!normalizedPath.startsWith(normalizedRoot)) throw SecurityException("OBB path escaped app-private storage")
        return normalizedRoot.relativize(normalizedPath).toPortablePath()
    }

    private fun rejectSymlinkComponents(base: Path, target: Path) {
        val normalizedBase = base.toAbsolutePath().normalize()
        val normalizedTarget = target.toAbsolutePath().normalize()
        if (!normalizedTarget.startsWith(normalizedBase)) throw SecurityException("Path is outside permitted root")
        var current = normalizedBase
        if (Files.isSymbolicLink(current)) throw SecurityException("Symbolic-link component: $current")
        for (part in normalizedBase.relativize(normalizedTarget)) {
            current = current.resolve(part)
            if (Files.isSymbolicLink(current)) throw SecurityException("Symbolic-link component: $current")
        }
    }

    private fun rejectSymlink(path: Path) {
        if (Files.isSymbolicLink(path)) throw SecurityException("Symbolic links are not accepted: $path")
    }

    private fun move(source: Path, destination: Path) {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        Files.walkFileTree(path, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                Files.delete(file)
                return FileVisitResult.CONTINUE
            }

            override fun postVisitDirectory(dir: Path, error: IOException?): FileVisitResult {
                if (error != null) throw error
                Files.delete(dir)
                return FileVisitResult.CONTINUE
            }
        })
    }

    private fun jsonString(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }

    private fun Path.toPortablePath(): String = toString().replace(java.io.File.separatorChar, '/')

    private data class StagedFile(val relativePath: String, val stagedPath: Path)
    private data class Replacement(val destination: Path, val backup: Path?)

    companion object {
        private val PACKAGE_COMPONENT_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
        private const val DATA_ARCHIVE_MAX_COMPRESSED_BYTES = 1024L * 1024 * 1024
        private const val DATA_ARCHIVE_MAX_BYTES = 2L * 1024 * 1024 * 1024
        private const val DATA_ARCHIVE_MAX_FILE_BYTES = 512L * 1024 * 1024
        private const val DATA_ARCHIVE_MAX_ENTRIES = 50_000
        private const val OBB_MAX_FILE_BYTES = 8L * 1024 * 1024 * 1024
        private const val OBB_BUNDLE_MAX_COMPRESSED_BYTES = 2L * 1024 * 1024 * 1024
        private const val OBB_BUNDLE_MAX_UNCOMPRESSED_BYTES = 16L * 1024 * 1024 * 1024
        private const val OBB_BUNDLE_MAX_ENTRIES = 256
        private const val EXPORT_MAX_BYTES = 16L * 1024 * 1024 * 1024
    }
}

/** Reads Unix file-type bits from ZIP central-directory records without extracting entries. */
private object ZipUnixMetadata {
    private const val EOCD_SIGNATURE = 0x06054b50L
    private const val CENTRAL_SIGNATURE = 0x02014b50L
    private const val MAX_EOCD_SEARCH = 22 + 65_535

    fun symlinkEntries(path: Path): Set<String> = RandomAccessFile(path.toFile(), "r").use { file ->
        val length = file.length()
        if (length < 22) throw ZipException("ZIP end record is missing")
        val searchLength = minOf(length, MAX_EOCD_SEARCH.toLong()).toInt()
        val tail = ByteArray(searchLength)
        file.seek(length - searchLength)
        file.readFully(tail)
        var eocdIndex = -1
        for (index in tail.size - 22 downTo 0) {
            if (u32(tail, index) == EOCD_SIGNATURE) {
                val commentLength = u16(tail, index + 20)
                if (index + 22 + commentLength == tail.size) {
                    eocdIndex = index
                    break
                }
            }
        }
        if (eocdIndex < 0) throw ZipException("ZIP end record is invalid or unsupported")
        val disk = u16(tail, eocdIndex + 4)
        val centralDisk = u16(tail, eocdIndex + 6)
        val diskEntries = u16(tail, eocdIndex + 8)
        val totalEntries = u16(tail, eocdIndex + 10)
        val centralSize = u32(tail, eocdIndex + 12)
        val centralOffset = u32(tail, eocdIndex + 16)
        if (disk != 0 || centralDisk != 0 || diskEntries != totalEntries) {
            throw ZipException("Multi-disk ZIP files are not supported")
        }
        if (totalEntries == 0xffff || centralSize == 0xffffffffL || centralOffset == 0xffffffffL) {
            throw ZipException("ZIP64 central directories are not accepted by this importer")
        }
        if (centralOffset + centralSize > length) throw ZipException("ZIP central directory is out of bounds")

        val result = mutableSetOf<String>()
        file.seek(centralOffset)
        repeat(totalEntries) {
            val header = ByteArray(46)
            file.readFully(header)
            if (u32(header, 0) != CENTRAL_SIGNATURE) throw ZipException("Malformed ZIP central directory")
            val madeBy = u16(header, 4)
            val flags = u16(header, 8)
            val nameLength = u16(header, 28)
            val extraLength = u16(header, 30)
            val commentLength = u16(header, 32)
            val externalAttributes = u32(header, 38)
            val nameBytes = ByteArray(nameLength)
            file.readFully(nameBytes)
            val charset = if ((flags and (1 shl 11)) != 0) StandardCharsets.UTF_8 else Charset.forName("CP437")
            val name = String(nameBytes, charset)
            val unixSystem = (madeBy ushr 8) == 3
            val unixMode = (externalAttributes ushr 16).toInt()
            if (unixSystem && (unixMode and 0xf000) == 0xa000) result += name
            file.seek(file.filePointer + extraLength + commentLength)
        }
        result
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun u32(bytes: ByteArray, offset: Int): Long =
        (u16(bytes, offset).toLong() and 0xffffL) or ((u16(bytes, offset + 2).toLong() and 0xffffL) shl 16)
}
