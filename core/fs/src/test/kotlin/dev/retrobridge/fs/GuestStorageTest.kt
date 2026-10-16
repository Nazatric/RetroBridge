package dev.retrobridge.fs

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class GuestStorageTest {
    @Test
    fun createsAnIsolatedLayoutAndMapsOnlyTheOwnedPaths() {
        val root = Files.createTempDirectory("retrobridge-files-test")
        val first = GuestStorage(root, "org.example.one", "123e4567-e89b-42d3-a456-426614174000")
        val second = GuestStorage(root, "org.example.two", "223e4567-e89b-42d3-a456-426614174000")
        first.initialize()
        second.initialize()

        val mapped = first.resolveGuestPath("/data/data/org.example.one/files/save.bin")
        assertEquals(first.layout.internalFiles.resolve("save.bin"), mapped)
        assertTrue(mapped.startsWith(first.appRoot))
        assertTrue(!mapped.startsWith(second.appRoot))
        assertEquals(first.layout.externalData.resolve("cache/item"), first.resolveGuestPath(
            "/storage/emulated/0/Android/data/org.example.one/cache/item",
        ))
    }

    @Test
    fun rejectsTraversalUnknownRootsAndOtherApps() {
        val storage = GuestStorage(
            Files.createTempDirectory("retrobridge-path-test"),
            "org.example.safe",
            "323e4567-e89b-42d3-a456-426614174000",
        )
        storage.initialize()

        assertThrows(SecurityException::class.java) {
            storage.resolveGuestPath("/data/data/org.example.safe/files/../../other/secret")
        }
        assertThrows(SecurityException::class.java) {
            storage.resolveGuestPath("/data/data/org.example.other/files/secret")
        }
        assertThrows(SecurityException::class.java) {
            storage.resolveGuestPath("/system/lib/libc.so")
        }
        assertThrows(IllegalArgumentException::class.java) {
            storage.resolveGuestPath("/data/data/org.example.safe/files\\secret")
        }
    }

    @Test
    fun rejectsSymlinkComponentsInsteadOfFollowingThem() {
        val root = Files.createTempDirectory("retrobridge-symlink-test")
        val storage = GuestStorage(root, "org.example.links", "623e4567-e89b-42d3-a456-426614174000")
        storage.initialize()
        val outside = Files.createTempDirectory("retrobridge-outside-test")
        val link = storage.layout.internalFiles.resolve("escape")
        try {
            Files.createSymbolicLink(link, outside)
        } catch (_: UnsupportedOperationException) {
            return
        } catch (_: java.io.IOException) {
            return
        } catch (_: SecurityException) {
            return
        }

        assertThrows(SecurityException::class.java) {
            storage.resolveGuestPath("/data/data/org.example.links/files/escape/secret")
        }
    }

    @Test
    fun clearAndRemoveStayWithinOneGuestRoot() {
        val root = Files.createTempDirectory("retrobridge-clean-test")
        val first = GuestStorage(root, "org.example.first", "423e4567-e89b-42d3-a456-426614174000")
        val second = GuestStorage(root, "org.example.second", "523e4567-e89b-42d3-a456-426614174000")
        first.initialize()
        second.initialize()
        Files.writeString(first.layout.internalFiles.resolve("secret"), "one")
        Files.writeString(first.layout.app.resolve("base.apk"), "apk")
        Files.writeString(second.layout.internalFiles.resolve("secret"), "two")

        first.clearGuestData()
        assertTrue(!Files.exists(first.layout.internalFiles.resolve("secret")))
        assertTrue(Files.exists(first.layout.app.resolve("base.apk")))
        assertTrue(Files.exists(second.layout.internalFiles.resolve("secret")))

        first.removeGuest()
        assertTrue(!Files.exists(first.appRoot))
        assertTrue(Files.exists(second.appRoot))
    }
}
