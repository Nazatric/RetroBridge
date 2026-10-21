package dev.retrobridge.manager

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import java.nio.file.Files

class FileGuestDiagnosticRepositoryTest {
    @Test
    fun appendsReloadsAndCoalescesRepeatedEventsWithoutLosingCounts() {
        val file = Files.createTempDirectory("retrobridge-diagnostics").resolve("diagnostics.json")
        val repository = FileGuestDiagnosticRepository(file)
        val first = diagnostic(timestamp = 1_000L)
        val repeated = diagnostic(timestamp = 1_500L, detail = "updated detail")

        assertEquals(1, repository.append(first).size)
        val grouped = repository.append(repeated)

        assertEquals(1, grouped.size)
        assertEquals(2, grouped.single().occurrences)
        assertEquals(1_500L, grouped.single().lastOccurredAtEpochMs)
        assertEquals("updated detail", grouped.single().detail)
        assertEquals(grouped, FileGuestDiagnosticRepository(file).list())
        assertTrue(repository.exportJson().contains("MISSING_NATIVE_LIBRARY"))
    }

    @Test
    fun appendsPendingEventsAsOneDurableBatch() {
        val file = Files.createTempDirectory("retrobridge-diagnostics-batch").resolve("diagnostics.json")
        val repository = FileGuestDiagnosticRepository(file)

        val saved = repository.appendAll(
            listOf(
                diagnostic(timestamp = 100L),
                diagnostic(timestamp = 200L, detail = "most recent detail"),
            ),
        )

        assertEquals(1, saved.size)
        assertEquals(2, saved.single().occurrences)
        assertEquals("most recent detail", saved.single().detail)
        assertEquals(saved, FileGuestDiagnosticRepository(file).list())
    }

    @Test
    fun coalescingKeepsDifferentGuestFilesAndInstructionEncodingsSeparate() {
        val file = Files.createTempDirectory("retrobridge-diagnostics-identity").resolve("diagnostics.json")
        val repository = FileGuestDiagnosticRepository(file)
        val base = diagnostic(timestamp = 10L).copy(file = "lib/one.so", guestAddress = "0x1000", instruction = "0xe1a00000")

        repository.append(base)
        repository.append(base.copy(timestampEpochMs = 11L, file = "lib/two.so"))
        val grouped = repository.append(base.copy(timestampEpochMs = 12L, instruction = "0xe3a00000"))

        assertEquals(3, grouped.size)
        assertEquals(listOf("lib/one.so", "lib/two.so", "lib/one.so"), grouped.map(GuestDiagnostic::file))
        assertEquals(listOf("0xe1a00000", "0xe1a00000", "0xe3a00000"), grouped.map(GuestDiagnostic::instruction))
    }

    @Test
    fun retentionBoundKeepsNewestDistinctEvents() {
        val file = Files.createTempDirectory("retrobridge-diagnostics-bound").resolve("diagnostics.json")
        val repository = FileGuestDiagnosticRepository(file, maximumEvents = 2, coalesceWindowMs = 0)

        repository.append(diagnostic(timestamp = 1L, code = "FIRST"))
        repository.append(diagnostic(timestamp = 2L, code = "SECOND"))
        val bounded = repository.append(diagnostic(timestamp = 3L, code = "THIRD"))

        assertEquals(listOf("SECOND", "THIRD"), bounded.map(GuestDiagnostic::code))
    }

    @Test
    fun malformedHistoryIsReportedWithoutOverwritingOriginalBytes() {
        val file = Files.createTempDirectory("retrobridge-diagnostics-malformed").resolve("diagnostics.json")
        val original = "not valid JSON".toByteArray(Charsets.UTF_8)
        Files.write(file, original)

        assertFailsWith<IllegalStateException> { FileGuestDiagnosticRepository(file) }
        assertTrue(original.contentEquals(Files.readAllBytes(file)))
    }

    @Test
    fun filePathIsBoundedAndSurvivesJsonRoundTrip() {
        val event = diagnostic(timestamp = 10L).copy(file = "f".repeat(1_024))
        val encoded = GuestDiagnosticJson.encode(listOf(event))

        assertEquals(event, GuestDiagnosticJson.decode(encoded).single())
        assertFailsWith<IllegalArgumentException> {
            event.copy(file = "f".repeat(1_025)).validate()
        }
    }

    @Test
    fun olderRegistryShapeGetsDefaultsForNewStructuredFields() {
        val decoded = GuestDiagnosticJson.decode(
            """[{"timestampEpochMs":1,"severity":"WARNING","component":"APK preflight","message":"ELF headers only"}]""",
        ).single()

        assertEquals("UNCLASSIFIED", decoded.code)
        assertEquals("GENERAL", decoded.category)
        assertEquals("UNKNOWN", decoded.operation)
        assertEquals(1, decoded.occurrences)
    }

    private fun diagnostic(
        timestamp: Long,
        code: String = "MISSING_NATIVE_LIBRARY",
        detail: String = "libfoo.so requires libbar.so",
    ) = GuestDiagnostic(
        timestampEpochMs = timestamp,
        severity = "ERROR",
        component = "Dependency resolver",
        message = "Required native library libbar.so is unavailable.",
        detail = detail,
        code = code,
        category = "MISSING_LIBRARY",
        operation = "DEPENDENCY_RESOLUTION",
        guestId = "guest-1",
        packageName = "org.example.game",
        library = "libbar.so",
        nextAction = "Provide an ARM32 dependency.",
    )
}
