package dev.retrobridge.manager

/** Enforces the documented lifecycle. Runtime actions are not implied by changing this state. */
object GuestAppStateMachine {
    private val allowedTransitions = mapOf(
        GuestAppState.IMPORTED to setOf(GuestAppState.VALIDATING, GuestAppState.UNSUPPORTED),
        GuestAppState.VALIDATING to setOf(GuestAppState.READY, GuestAppState.UNSUPPORTED, GuestAppState.IMPORTED),
        GuestAppState.READY to setOf(GuestAppState.STARTING, GuestAppState.VALIDATING, GuestAppState.UNSUPPORTED),
        GuestAppState.STARTING to setOf(GuestAppState.RUNNING, GuestAppState.STOPPED, GuestAppState.CRASHED, GuestAppState.UNSUPPORTED),
        GuestAppState.RUNNING to setOf(GuestAppState.PAUSED, GuestAppState.STOPPING, GuestAppState.CRASHED),
        GuestAppState.PAUSED to setOf(GuestAppState.RUNNING, GuestAppState.STOPPING, GuestAppState.CRASHED),
        GuestAppState.STOPPING to setOf(GuestAppState.STOPPED, GuestAppState.CRASHED),
        GuestAppState.STOPPED to setOf(GuestAppState.STARTING, GuestAppState.VALIDATING, GuestAppState.UNSUPPORTED),
        GuestAppState.CRASHED to setOf(GuestAppState.VALIDATING, GuestAppState.STOPPED, GuestAppState.UNSUPPORTED),
        GuestAppState.UNSUPPORTED to setOf(GuestAppState.VALIDATING),
    )

    fun canTransition(from: GuestAppState, to: GuestAppState): Boolean =
        to in allowedTransitions.getValue(from)

    fun transition(
        record: GuestAppRecord,
        to: GuestAppState,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): GuestAppRecord {
        require(nowEpochMs >= record.updatedAtEpochMs) { "Lifecycle timestamps must be monotonic" }
        check(canTransition(record.state, to)) {
            "Illegal guest lifecycle transition: ${record.state} -> $to for ${record.packageName}"
        }
        return record.copy(state = to, updatedAtEpochMs = nowEpochMs).also(GuestAppRecord::validate)
    }
}
