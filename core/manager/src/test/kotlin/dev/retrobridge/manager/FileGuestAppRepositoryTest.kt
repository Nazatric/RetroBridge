package dev.retrobridge.manager

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.file.Files

class FileGuestAppRepositoryTest {
    @Test
    fun persistsUpdatesAndRemovesOnlyTheRequestedGuest() {
        val directory = Files.createTempDirectory("retrobridge-registry-test")
        val file = directory.resolve("registry.json")
        val first = sampleRecord("org.example.first", "123e4567-e89b-42d3-a456-426614174000")
        val second = sampleRecord("org.example.second", "223e4567-e89b-42d3-a456-426614174000")

        FileGuestAppRepository(file).apply {
            upsert(first)
            upsert(second)
            update(first.id) { it.copy(displayName = "Updated first") }
        }

        val reloaded = FileGuestAppRepository(file)
        assertEquals("Updated first", reloaded.get(first.id)?.displayName)
        assertNotNull(reloaded.get(second.id))
        assertEquals("Updated first", reloaded.remove(first.id)?.displayName)
        assertNull(reloaded.get(first.id))
        assertNotNull(reloaded.get(second.id))
        assertEquals(1, reloaded.list().size)
    }

    @Test
    fun rejectsUnsafePathsAndDoesNotChangeRecordId() {
        val repository = FileGuestAppRepository(Files.createTempDirectory("retrobridge-invalid-test").resolve("registry.json"))
        val record = sampleRecord("org.example.guest", "323e4567-e89b-42d3-a456-426614174000")

        assertThrows(IllegalArgumentException::class.java) {
            repository.upsert(record.copy(originalApkPath = "apps/../../outside.apk"))
        }
        repository.upsert(record)
        assertThrows(IllegalArgumentException::class.java) {
            repository.update(record.id) { it.copy(id = "423e4567-e89b-42d3-a456-426614174000") }
        }
        assertEquals(record, repository.get(record.id))
    }

    private fun sampleRecord(packageName: String, id: String) = GuestAppRecord(
        id = id,
        packageName = packageName,
        displayName = packageName,
        originalApkPath = "apps/$packageName/$id/app/base.apk",
        sha256 = "b".repeat(64),
        isolatedRoot = "apps/$packageName/$id",
        createdAtEpochMs = 20,
    )
}
