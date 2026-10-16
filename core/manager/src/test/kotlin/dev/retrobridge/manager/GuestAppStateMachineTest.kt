package dev.retrobridge.manager

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GuestAppStateMachineTest {
    @Test
    fun allowsOnlyDocumentedTransitions() {
        val imported = sampleRecord()
        val validating = GuestAppStateMachine.transition(imported, GuestAppState.VALIDATING, 11)
        val ready = GuestAppStateMachine.transition(validating, GuestAppState.READY, 12)
        val starting = GuestAppStateMachine.transition(ready, GuestAppState.STARTING, 13)

        assertEquals(GuestAppState.STARTING, starting.state)
        assertEquals(13L, starting.updatedAtEpochMs)
        assertTrue(GuestAppStateMachine.canTransition(GuestAppState.RUNNING, GuestAppState.PAUSED))
        assertFalse(GuestAppStateMachine.canTransition(GuestAppState.IMPORTED, GuestAppState.RUNNING))
    }

    @Test
    fun rejectsIllegalTransitionAndNonMonotonicTimestamp() {
        val imported = sampleRecord()

        assertThrows(IllegalStateException::class.java) {
            GuestAppStateMachine.transition(imported, GuestAppState.RUNNING, 11)
        }
        assertThrows(IllegalArgumentException::class.java) {
            GuestAppStateMachine.transition(imported, GuestAppState.VALIDATING, 9)
        }
    }

    private fun sampleRecord() = GuestAppRecord(
        id = "123e4567-e89b-42d3-a456-426614174000",
        packageName = "org.example.legacy",
        displayName = "Legacy",
        originalApkPath = "apps/org.example.legacy/123e4567-e89b-42d3-a456-426614174000/app/base.apk",
        sha256 = "a".repeat(64),
        isolatedRoot = "apps/org.example.legacy/123e4567-e89b-42d3-a456-426614174000",
        createdAtEpochMs = 10,
    )
}
