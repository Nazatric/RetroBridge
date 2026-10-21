package dev.retrobridge.app

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.manager.GuestDiagnostic
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DiagnosticsScreenInstrumentedTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun componentFilterAndExpandedTechnicalFieldsWorkWithoutHidingOccurrenceCounts() {
        val guestId = "123e4567-e89b-42d3-a456-426614174000"
        val app = GuestAppRecord(
            id = guestId,
            packageName = "org.example.game",
            displayName = "Example Game",
            originalApkPath = "apps/org.example.game/$guestId/app/base.apk",
            sha256 = "0".repeat(64),
            isolatedRoot = "apps/org.example.game/$guestId",
            createdAtEpochMs = 1L,
        )
        val missingLibrary = GuestDiagnostic(
            timestampEpochMs = 10L,
            severity = "ERROR",
            component = "Native dependency resolver",
            message = "Required native library libfoo.so is unavailable.",
            detail = "libgame.so requires unavailable library libfoo.so",
            code = "MISSING_NATIVE_LIBRARY",
            category = "MISSING_LIBRARY",
            operation = "DEPENDENCY_RESOLUTION",
            guestId = guestId,
            packageName = app.packageName,
            library = "libfoo.so",
            file = "lib/armeabi-v7a/libgame.so",
            guestAddress = "0x1020",
            instruction = "0xe12fff1e",
            nextAction = "Provide the matching ARM32 library.",
            occurrences = 3,
            lastOccurredAtEpochMs = 30L,
        )
        val runtimeEvent = missingLibrary.copy(
            timestampEpochMs = 40L,
            severity = "INFO",
            component = "ARM32 interpreter",
            message = "Selected native entrypoints completed.",
            code = "RUNTIME_SESSION_RUNNING",
            category = "NATIVE_RUNTIME",
            operation = "NATIVE_EXECUTION",
            detail = "instructions=12",
            occurrences = 1,
            lastOccurredAtEpochMs = null,
        )
        val exportedCount = mutableIntStateOf(-1)

        composeRule.setContent {
            MaterialTheme {
                DiagnosticsScreen(
                    events = listOf(missingLibrary, runtimeEvent),
                    apps = listOf(app),
                    onBack = {},
                    onExport = { exportedCount.intValue = it.size },
                )
            }
        }

        composeRule.onNodeWithText("Required native library libfoo.so is unavailable.")
            .performScrollTo()
            .assertIsDisplayed()
        composeRule.onNodeWithText("Repeated 3 times").performScrollTo().assertIsDisplayed()

        composeRule.onNodeWithText("Component: All").performScrollTo().performClick()
        composeRule.onNodeWithText("Native dependency resolver").performClick()
        composeRule.onAllNodesWithText("Selected native entrypoints completed.").assertCountEquals(0)
        composeRule.onNodeWithText("Required native library libfoo.so is unavailable.").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("Technical detail").performScrollTo().performClick()
        composeRule.onNodeWithText("lib/armeabi-v7a/libgame.so").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("0xe12fff1e").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("Export JSON").performScrollTo().performClick()
        composeRule.runOnIdle { assertEquals(1, exportedCount.intValue) }
    }
}
