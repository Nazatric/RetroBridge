package dev.retrobridge.services

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RuntimeDiagnosticClassifierTest {
    @Test
    fun missingDependencyHasStableCodeLibraryAndNextAction() {
        val event = RuntimeDiagnosticClassifier.failure(
            operation = DiagnosticOperation.DEPENDENCY_RESOLUTION,
            message = "libAmazonGamesJni.so requires unavailable library libstdc++.so",
            guestId = "guest-123",
            packageName = "org.example.game",
            timestampEpochMs = 123L,
        )

        assertEquals(DiagnosticCategory.MISSING_LIBRARY, event.category)
        assertEquals("MISSING_NATIVE_LIBRARY", event.code)
        assertEquals("libstdc++.so", event.library)
        assertEquals("libAmazonGamesJni.so", event.file)
        assertEquals("guest-123", event.guestId)
        assertEquals("org.example.game", event.packageName)
        assertTrue(event.summary.contains("libstdc++.so"))
        assertTrue(event.nextAction.orEmpty().contains("explicit platform thunk"))
        assertEquals("libAmazonGamesJni.so requires unavailable library libstdc++.so", event.detail)
    }

    @Test
    fun unsupportedInstructionPreservesGuestPcAndOpcode() {
        val event = RuntimeDiagnosticClassifier.failure(
            operation = DiagnosticOperation.NATIVE_EXECUTION,
            message = "unsupported A32 instruction at guest address 4096 (word 4026531840)",
        )

        assertEquals(DiagnosticCategory.UNSUPPORTED_INSTRUCTION, event.category)
        assertEquals("UNSUPPORTED_ARM_INSTRUCTION", event.code)
        assertEquals("0x1000", event.guestAddress)
        assertEquals("0xf0000000", event.instruction)
        assertTrue(event.nextAction.orEmpty().contains("regression fixture"))
    }

    @Test
    fun unresolvedSymbolIsNotReportedAsSuccessfulOrGenericFailure() {
        val event = RuntimeDiagnosticClassifier.failure(
            operation = DiagnosticOperation.ELF_INSPECTION,
            message = "ELF validation failed file=lib/armeabi-v7a/libgame.so: undefined ARM32 symbol Java_com_example_Native_start",
        )

        assertEquals(DiagnosticCategory.UNRESOLVED_SYMBOL, event.category)
        assertEquals("UNRESOLVED_NATIVE_SYMBOL", event.code)
        assertEquals("Java_com_example_Native_start", event.symbol)
        assertEquals("lib/armeabi-v7a/libgame.so", event.file)
        assertEquals("libgame.so", event.library)
        assertNotNull(event.nextAction)
    }

    @Test
    fun importAndResourceFailuresHaveActionableStableCategories() {
        val import = RuntimeDiagnosticClassifier.failure(
            DiagnosticOperation.APK_IMPORT,
            "Selected document is not a readable Android APK",
        )
        val resource = RuntimeDiagnosticClassifier.failure(
            DiagnosticOperation.NATIVE_EXECUTION,
            "Guest exceeded the instruction budget",
        )
        val clear = RuntimeDiagnosticClassifier.failure(
            DiagnosticOperation.DATA_CLEAR,
            "Permission denied while clearing guest data",
        )
        val remove = RuntimeDiagnosticClassifier.failure(
            DiagnosticOperation.APP_REMOVE,
            "Registry update failed",
        )
        val internal = RuntimeDiagnosticClassifier.failure(
            DiagnosticOperation.APK_IMPORT,
            "An internal indexing failure occurred",
            exceptionType = "java.lang.IndexOutOfBoundsException",
        )

        assertEquals(DiagnosticCategory.APK_IMPORT, import.category)
        assertEquals("APK_IMPORT_FAILED", import.code)
        assertEquals(DiagnosticCategory.RESOURCE_EXHAUSTION, resource.category)
        assertEquals("RUNTIME_RESOURCE_LIMIT", resource.code)
        assertEquals(DiagnosticCategory.FILESYSTEM, clear.category)
        assertEquals("GUEST_DATA_CLEAR_FAILED", clear.code)
        assertEquals(DiagnosticCategory.FILESYSTEM, remove.category)
        assertEquals("GUEST_APP_REMOVE_FAILED", remove.code)
        assertEquals("Guest manager", remove.component)
        assertEquals(DiagnosticCategory.INTERNAL_DEFECT, internal.category)
        assertEquals("RUNTIME_INTERNAL_FAILURE", internal.code)
    }
}
