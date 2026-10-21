package dev.retrobridge.app

import dev.retrobridge.runtime.GuestRuntimeProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class GuestRuntimeStorageGuardTest {
    @Test
    fun skipsStopRequestWhenThereIsNoActiveSession() = runBlocking {
        var stopRequested = false

        val result = stopRuntimeSessionForStorageChange(null, GuestRuntimeProtocol.STATE_FAILED) {
            stopRequested = true
            reply(GuestRuntimeProtocol.STATE_STOPPED)
        }

        assertFalse(stopRequested)
        assertNull(result)
    }

    @Test
    fun blocksStorageChangesWhenRuntimeReportsActiveWithoutASessionId() {
        val failure = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                stopRuntimeSessionForStorageChange(null, GuestRuntimeProtocol.STATE_RUNNING) {
                    throw AssertionError("A missing session ID must not send a stop request")
                }
            }
        }

        assertEquals("Runtime reports an active session without a stoppable session ID", failure.message)
    }

    @Test
    fun acceptsConfirmedStoppedAndAlreadyStoppedSessions() = runBlocking {
        listOf(GuestRuntimeProtocol.STATE_STOPPED, GuestRuntimeProtocol.STATE_NOT_RUNNING).forEach { state ->
            val result = stopRuntimeSessionForStorageChange("session-1", GuestRuntimeProtocol.STATE_RUNNING) { reply(state) }
            assertEquals(state, result?.state)
        }
    }

    @Test
    fun blocksStorageChangesWhenRuntimeDoesNotConfirmStop() {
        val failure = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                stopRuntimeSessionForStorageChange("session-1", GuestRuntimeProtocol.STATE_RUNNING) {
                    reply(GuestRuntimeProtocol.STATE_RUNNING, "Runtime is still active")
                }
            }
        }

        assertEquals("Runtime is still active", failure.message)
    }

    @Test
    fun propagatesStopRequestFailures() {
        val failure = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                stopRuntimeSessionForStorageChange("session-1", GuestRuntimeProtocol.STATE_RUNNING) {
                    throw IllegalStateException("Service disconnected")
                }
            }
        }

        assertEquals("Service disconnected", failure.message)
    }

    private fun reply(state: String, diagnostic: String = "") = GuestRuntimeSessionReply(
        sessionId = "session-1",
        guestId = "guest-1",
        packageName = "org.example.guest",
        state = state,
        guestCodeStarted = true,
        startedAtEpochMs = 1L,
        diagnostic = diagnostic,
        guestInstructions = 1L,
        relocationCount = 0,
        jniOnLoadVersion = -1,
        registeredNativeCount = 0,
        loadedLibraries = emptyList(),
        entrypointResults = emptyList(),
    )
}
