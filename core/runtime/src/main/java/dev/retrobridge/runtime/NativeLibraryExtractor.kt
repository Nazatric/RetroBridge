package dev.retrobridge.runtime

import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/** One immutable ARM32 library extracted from an APK and verified before native loading. */
data class ExtractedNativeLibrary(
    val abi: String,
    val fileName: String,
    val path: Path,
    val sha256: String,
    val size: Long,
)

data class NativeLibraryExtraction(
    val abi: String,
    val nativeLibraryRoot: Path,
    val libraries: List<ExtractedNativeLibrary>,
)

/**
 * Bounded APK native-library extractor. It writes regular files only, rejects duplicate names,
 * hashes every extracted object, and never materializes paths supplied by ZIP entry text.
 */
object NativeLibraryExtractor {
    private val libraryPathPattern = Regex("^lib/(armeabi-v7a|armeabi)/([A-Za-z0-9_.+-]+\\.so)$")
    private val sha256Pattern = Regex("[0-9a-fA-F]{64}")
    private const val MAX_APK_ENTRIES = 100_000
    private const val MAX_LIBRARY_COUNT = 32
    private const val MAX_LIBRARY_BYTES = 64L * 1024 * 1024
    private const val MAX_TOTAL_LIBRARY_BYTES = 192L * 1024 * 1024
    private const val MAX_SUSPICIOUS_COMPRESSION_RATIO = 200L

    // Virtual dependency names only: unresolved symbols still fail during relocation; no host DSO is loaded.
    private val platformLibraryNames = setOf(
        "libc.so",
        "libstdc++.so",
        "libm.so",
        "libdl.so",
        "liblog.so",
        "libandroid.so",
        "libEGL.so",
        "libGLESv1_CM.so",
        "libGLESv2.so",
        "libGLESv3.so",
        "libOpenSLES.so",
        "libjnigraphics.so",
    )

    @Throws(IOException::class)
    fun extract(context: GuestRuntimeContext): NativeLibraryExtraction {
        require(sha256Pattern.matches(context.apkSha256)) { "Invalid APK SHA-256" }
        val nativeRoot = context.appRoot.resolve("runtime/native").toAbsolutePath().normalize()
        require(nativeRoot.startsWith(context.appRoot.toAbsolutePath().normalize())) {
            "Native library directory escaped app-private storage"
        }
        Files.createDirectories(nativeRoot)
        rejectSymlinksBetween(context.appRoot, nativeRoot)

        val entriesByAbi = linkedMapOf("armeabi-v7a" to mutableListOf<ZipEntry>(), "armeabi" to mutableListOf<ZipEntry>())
        val seenEntryPaths = HashSet<String>()
        ZipFile(context.apkPath.toFile()).use { archive ->
            val entries = archive.entries()
            var entryCount = 0
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entryCount++
                if (entryCount > MAX_APK_ENTRIES) throw IOException("APK entry count exceeds the native extraction limit")
                val match = libraryPathPattern.matchEntire(entry.name) ?: continue
                if (entry.isDirectory) throw IOException("Native library ZIP entry is unexpectedly a directory")
                if (!seenEntryPaths.add(entry.name)) throw IOException("APK contains a duplicate native library path: ${entry.name}")
                entriesByAbi.getValue(match.groupValues[1]).add(entry)
            }

            val selectedAbi = listOf("armeabi-v7a", "armeabi").firstOrNull { abi ->
                abi in context.guestAbis && entriesByAbi.getValue(abi).isNotEmpty()
            } ?: throw IOException(
                "APK has no armeabi-v7a or armeabi native libraries supported by the interpreter",
            )
            val selectedEntries = entriesByAbi.getValue(selectedAbi).sortedBy { it.name }
            if (selectedEntries.size > MAX_LIBRARY_COUNT) throw IOException("APK contains more than 32 ARM32 native libraries")

            val versionRoot = nativeRoot.resolve(context.apkSha256.lowercase())
            rejectExistingSymlink(nativeRoot, versionRoot)
            val stagingRoot = nativeRoot.resolve(".staging-${UUID.randomUUID()}")
            Files.createDirectory(stagingRoot)
            var totalBytes = 0L
            try {
                val stagingAbiRoot = stagingRoot.resolve(selectedAbi)
                Files.createDirectory(stagingAbiRoot)
                val extracted = ArrayList<ExtractedNativeLibrary>(selectedEntries.size)
                for (entry in selectedEntries) {
                    val fileName = entry.name.substringAfterLast('/')
                    val entrySize = entry.size
                    if (entrySize <= 0L || entrySize > MAX_LIBRARY_BYTES) {
                        throw IOException("Native library size is unknown, empty, or exceeds 64 MiB: $fileName")
                    }
                    if (entry.compressedSize < 0L) throw IOException("Native library compressed size is unavailable: $fileName")
                    if (entrySize > 1024 * 1024 && entry.compressedSize > 0L &&
                        entrySize / entry.compressedSize.coerceAtLeast(1L) > MAX_SUSPICIOUS_COMPRESSION_RATIO
                    ) {
                        throw IOException("Native library compression ratio exceeds the safety limit: $fileName")
                    }
                    if (totalBytes > MAX_TOTAL_LIBRARY_BYTES - entrySize) {
                        throw IOException("Extracted ARM32 native libraries exceed the 192 MiB limit")
                    }
                    val destination = stagingAbiRoot.resolve(fileName)
                    val (size, digest) = archive.getInputStream(entry).use { input ->
                        Files.newOutputStream(destination).use { output ->
                            val hash = MessageDigest.getInstance("SHA-256")
                            val crc = CRC32()
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            var copied = 0L
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                if (count == 0) {
                                    val value = input.read()
                                    if (value < 0) break
                                    if (copied >= MAX_LIBRARY_BYTES || totalBytes + copied >= MAX_TOTAL_LIBRARY_BYTES) {
                                        throw IOException("Native library expanded beyond the configured size limit")
                                    }
                                    val oneByte = value.toByte()
                                    output.write(value)
                                    hash.update(oneByte)
                                    crc.update(value)
                                    copied++
                                    continue
                                }
                                if (copied > MAX_LIBRARY_BYTES - count || totalBytes > MAX_TOTAL_LIBRARY_BYTES - copied - count) {
                                    throw IOException("Native library expanded beyond the configured size limit")
                                }
                                output.write(buffer, 0, count)
                                hash.update(buffer, 0, count)
                                crc.update(buffer, 0, count)
                                copied += count
                            }
                            if (copied != entrySize || (entry.crc >= 0L && crc.value != entry.crc)) {
                                throw IOException("Native library size or CRC changed during APK extraction: $fileName")
                            }
                            copied to hash.digest().toHexString()
                        }
                    }
                    totalBytes += size
                    extracted += ExtractedNativeLibrary(selectedAbi, fileName, destination, digest, size)
                }

                val finalAbiRoot = versionRoot.resolve(selectedAbi)
                if (Files.exists(versionRoot, LinkOption.NOFOLLOW_LINKS)) deleteTreeWithoutFollowingLinks(versionRoot)
                try {
                    Files.move(stagingRoot, versionRoot, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                    Files.move(stagingRoot, versionRoot)
                }
                rejectSymlinksBetween(context.appRoot, finalAbiRoot)
                val finalLibraries = extracted.map { item ->
                    val finalPath = finalAbiRoot.resolve(item.fileName)
                    verifyExtractedFile(finalPath, item.sha256, item.size)
                    item.copy(path = finalPath)
                }
                return NativeLibraryExtraction(selectedAbi, nativeRoot, finalLibraries)
            } catch (failure: Exception) {
                runCatching { deleteTreeWithoutFollowingLinks(stagingRoot) }
                throw failure
            }
        }
    }

    /** Re-hashes the exact app-private file immediately before passing it across JNI. */
    @Throws(IOException::class)
    fun verifyExtractedFile(path: Path, expectedSha256: String, expectedSize: Long) {
        if (!sha256Pattern.matches(expectedSha256)) throw SecurityException("Invalid extracted library SHA-256")
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw SecurityException("Extracted native library is not a regular private file")
        }
        if (Files.size(path) != expectedSize) throw IOException("Extracted native library changed size before loading")
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (total > expectedSize - count) throw IOException("Extracted native library grew while hashing")
                digest.update(buffer, 0, count)
                total += count
            }
            if (total != expectedSize) throw IOException("Extracted native library changed while hashing")
        }
        val actual = digest.digest().toHexString()
        if (!actual.equals(expectedSha256, ignoreCase = true)) {
            throw SecurityException("Extracted native library SHA-256 mismatch")
        }
    }

    /** Topological DT_NEEDED order; platform names not in the extracted APK are resolved by thunks. */
    fun dependencyOrder(
        libraries: List<ExtractedNativeLibrary>,
        metadata: Map<Path, NativeLibraryMetadata>,
    ): List<ExtractedNativeLibrary> {
        require(libraries.isNotEmpty()) { "APK contains no ARM32 native libraries" }
        val byName = linkedMapOf<String, ExtractedNativeLibrary>()
        for (library in libraries) {
            val details = metadata[library.path] ?: error("Missing ELF inspection result for ${library.fileName}")
            require(details.valid) { details.diagnostic.ifBlank { "Invalid ELF library ${library.fileName}" } }
            val aliases = setOf(library.fileName, details.soname)
            for (alias in aliases) {
                val previous = byName.putIfAbsent(alias, library)
                require(previous == null || previous.path == library.path) { "Duplicate ARM32 library SONAME: $alias" }
            }
        }
        val marks = HashMap<Path, Int>()
        val ordered = ArrayList<ExtractedNativeLibrary>(libraries.size)
        fun visit(library: ExtractedNativeLibrary) {
            when (marks[library.path]) {
                2 -> return
                1 -> throw IllegalArgumentException("Circular DT_NEEDED dependency involving ${library.fileName}")
            }
            marks[library.path] = 1
            val details = metadata.getValue(library.path)
            for (dependency in details.neededLibraries) {
                val local = byName[dependency]
                if (local != null) {
                    visit(local)
                } else if (dependency !in platformLibraryNames) {
                    throw IllegalArgumentException("${library.fileName} requires unavailable dependency $dependency")
                }
            }
            marks[library.path] = 2
            ordered += library
        }
        for (library in libraries.sortedBy { it.fileName }) visit(library)
        return ordered
    }

    private fun rejectSymlinksBetween(base: Path, candidate: Path) {
        val root = base.toAbsolutePath().normalize()
        val target = candidate.toAbsolutePath().normalize()
        if (!target.startsWith(root)) throw SecurityException("Native extraction path escaped private storage")
        var current = root
        rejectExistingSymlink(root, root)
        for (segment in root.relativize(target)) {
            current = current.resolve(segment)
            rejectExistingSymlink(root, current)
        }
    }

    private fun rejectExistingSymlink(root: Path, path: Path) {
        if (!path.toAbsolutePath().normalize().startsWith(root.toAbsolutePath().normalize())) {
            throw SecurityException("Native extraction path escaped private storage")
        }
        if (Files.isSymbolicLink(path)) throw SecurityException("Symbolic links are not allowed in native library storage")
    }

    private fun deleteTreeWithoutFollowingLinks(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isSymbolicLink(path)) throw SecurityException("Refusing to remove a symlink from native library storage")
        Files.walkFileTree(path, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (attrs.isSymbolicLink || Files.isSymbolicLink(file)) {
                    throw SecurityException("Refusing to traverse a symlink in native library storage")
                }
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

    private fun ByteArray.toHexString(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
