package dev.retrobridge.runtime

/** Primitive-only Messenger contract between the app UI process and the private runtime process. */
object GuestRuntimeProtocol {
    const val ACTION_BIND = "dev.retrobridge.runtime.BIND"

    const val MESSAGE_START_INSPECTION = 1
    const val MESSAGE_STOP_SESSION = 2
    const val MESSAGE_RESPONSE = 100

    const val KEY_REQUEST_ID = "request_id"
    const val KEY_GUEST_ID = "guest_id"
    const val KEY_PACKAGE_NAME = "package_name"
    const val KEY_APK_SHA256 = "apk_sha256"
    const val KEY_GUEST_ABIS = "guest_abis"
    const val KEY_SESSION_ID = "session_id"
    const val KEY_SESSION_STATE = "session_state"
    const val KEY_GUEST_CODE_STARTED = "guest_code_started"
    const val KEY_STARTED_AT_EPOCH_MS = "started_at_epoch_ms"
    const val KEY_DIAGNOSTIC = "diagnostic"

    const val STATE_INSPECTION_ONLY = "INSPECTION_ONLY"
    const val STATE_STOPPED = "STOPPED"
    const val STATE_NOT_RUNNING = "NOT_RUNNING"
    const val STATE_REJECTED = "REJECTED"
}
