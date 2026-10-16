package dev.retrobridge.fs

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class GuestArchiveOperationsTest {
    @Test
    fun streamsDataArchivesAndStripsRedundantPackagePrefixes() {
        val storage = newStorage("org.example.archive")
        val archive = zipOf(
            "org.example.archive/saves/slot.dat" to "slot".toByteArray(),
            "Android/data/org.example.archive/files/config.ini" to "mode=1".toByteArray(),
        )

        val result = storage.importAndroidDataArchive(ByteArrayInputStream(archive))

        assertEquals(2, result.filesImported)
        assertEquals(10L, result.uncompressedBytes)
        assertEquals("slot", Files.readString(storage.layout.externalData.resolve("saves/slot.dat")))
        assertEquals("mode=1", Files.readString(storage.layout.externalData.resolve("files/config.ini")))
    }

    @Test
    fun rejectsZipSlipAndUnixSymlinkEntriesBeforeCommit() {
        val traversalStorage = newStorage("org.example.traversal")
        val traversal = zipOf(
            "safe.txt" to "must-not-commit".toByteArray(),
            "../escape.txt" to "outside".toByteArray(),
        )
        assertThrows(SecurityException::class.java) {
            traversalStorage.importAndroidDataArchive(ByteArrayInputStream(traversal))
        }
        assertFalse(Files.exists(traversalStorage.layout.externalData.resolve("safe.txt")))

        val packageStorage = newStorage("org.example.expected")
        val wrongPackage = zipOf("Android/data/org.example.other/save.dat" to byteArrayOf(1))
        assertThrows(SecurityException::class.java) {
            packageStorage.importAndroidDataArchive(ByteArrayInputStream(wrongPackage))
        }
        assertFalse(Files.exists(packageStorage.layout.externalData.resolve("save.dat")))

        val symlinkStorage = newStorage("org.example.symlinkarchive")
        val symlink = unixSymlinkZip("escape" to "../../outside".toByteArray())
        assertThrows(SecurityException::class.java) {
            symlinkStorage.importAndroidDataArchive(ByteArrayInputStream(symlink))
        }
        assertFalse(Files.exists(symlinkStorage.layout.externalData.resolve("escape")))
    }

    @Test
    fun importsAssociatedObbFilesAndZipBundles() {
        val storage = newStorage("org.example.expansion")
        assertThrows(IllegalArgumentException::class.java) {
            storage.importObbFile(ByteArrayInputStream(byteArrayOf(1)), "main.1.org.other.expansion.obb")
        }

        val mainBytes = byteArrayOf(1, 2, 3)
        val rawResult = storage.importObbFile(
            ByteArrayInputStream(mainBytes),
            "main.42.org.example.expansion.obb",
        )
        assertEquals(3L, rawResult.bytesImported)
        assertArrayEquals(mainBytes, Files.readAllBytes(storage.layout.obb.resolve("main.42.org.example.expansion.obb")))

        val patchBytes = byteArrayOf(9, 8)
        val bundle = zipOf("Android/obb/org.example.expansion/patch.7.org.example.expansion.obb" to patchBytes)
        val bundleResult = storage.importObbBundle(ByteArrayInputStream(bundle))
        assertEquals(2L, bundleResult.bytesImported)
        assertEquals(1, bundleResult.paths.size)
        assertArrayEquals(patchBytes, Files.readAllBytes(storage.layout.obb.resolve("patch.7.org.example.expansion.obb")))

        val wrongPackageBundle = zipOf("Android/obb/org.example.other/main.8.org.example.expansion.obb" to byteArrayOf(4))
        assertThrows(SecurityException::class.java) {
            storage.importObbBundle(ByteArrayInputStream(wrongPackageBundle))
        }
        assertFalse(Files.exists(storage.layout.obb.resolve("main.8.org.example.expansion.obb")))
    }

    @Test
    fun exportsInternalExternalAndObbFilesWithManifest() {
        val storage = newStorage("org.example.export")
        storage.initialize()
        Files.writeString(storage.layout.internalFiles.resolve("save.dat"), "state")
        Files.writeString(storage.layout.externalData.resolve("files/user.txt"), "user")
        Files.writeString(storage.layout.obb.resolve("main.1.org.example.export.obb"), "obb")
        val archive = ByteArrayOutputStream()

        val result = storage.exportGuestData(archive)
        val names = mutableSetOf<String>()
        val contents = mutableMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(archive.toByteArray())).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                names += entry.name
                contents[entry.name] = zip.readBytes()
            }
        }

        assertEquals(3, result.filesExported)
        assertEquals(12L, result.bytesExported)
        assertTrue("manifest.json" in names)
        assertTrue("internal/files/save.dat" in names)
        assertTrue("external/data/files/user.txt" in names)
        assertTrue("obb/main.1.org.example.export.obb" in names)
        assertTrue(result.obbFiles.single().endsWith("/obb/main.1.org.example.export.obb"))
        assertTrue(String(contents.getValue("manifest.json")).contains("\"packageName\":\"org.example.export\""))
        assertEquals("state", String(contents.getValue("internal/files/save.dat")))
    }

    private fun newStorage(packageName: String): GuestStorage {
        val storage = GuestStorage(
            Files.createTempDirectory("retrobridge-archive-test"),
            packageName,
            "123e4567-e89b-42d3-a456-426614174000",
        )
        storage.initialize()
        return storage
    }

    private fun zipOf(vararg files: Pair<String, ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            files.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    private fun unixSymlinkZip(file: Pair<String, ByteArray>): ByteArray {
        val bytes = zipOf(file).toMutableList()
        val signature = byteArrayOf(0x50, 0x4b, 0x01, 0x02)
        val header = (0..bytes.size - 46).first { index ->
            signature.indices.all { bytes[index + it] == signature[it] }
        }
        bytes[header + 4] = 0x14
        bytes[header + 5] = 0x03 // Unix creator system in version-made-by.
        val mode = 0xa1ff0000L // S_IFLNK | 0777 in the high 16 bits.
        repeat(4) { index -> bytes[header + 38 + index] = ((mode ushr (8 * index)) and 0xff).toByte() }
        return bytes.toByteArray()
    }
}
