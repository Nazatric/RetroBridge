package dev.retrobridge.runtime

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.RemoteException

/** Private-process endpoint for bounded ARM32 library loading and interpreter execution. */
class GuestRuntimeService : Service() {
    private lateinit var handlerThread: HandlerThread
    private lateinit var requestMessenger: Messenger
    private lateinit var supervisor: GuestRuntimeSessionSupervisor

    override fun onCreate() {
        super.onCreate()
        supervisor = GuestRuntimeSessionSupervisor(filesDir.toPath().resolve("RetroBridge"))
        handlerThread = HandlerThread("RetroBridgeRuntimeIpc").apply { start() }
        requestMessenger = Messenger(Handler(handlerThread.looper) { message ->
            handleRequest(message)
            true
        })
    }

    override fun onBind(intent: Intent?): IBinder? =
        if (intent?.action == GuestRuntimeProtocol.ACTION_BIND) requestMessenger.binder else null

    override fun onDestroy() {
        supervisor.stopAll()
        handlerThread.quitSafely()
        super.onDestroy()
    }

    private fun handleRequest(message: Message) {
        val replyTo = message.replyTo ?: return
        val data = message.data
        val requestId = data.getString(GuestRuntimeProtocol.KEY_REQUEST_ID)
            ?.takeIf { it.isNotBlank() && it.length <= MAX_REQUEST_ID_LENGTH }
        if (requestId == null) {
            sendResponse(replyTo, Bundle().apply {
                putString(GuestRuntimeProtocol.KEY_SESSION_STATE, GuestRuntimeProtocol.STATE_REJECTED)
                putBoolean(GuestRuntimeProtocol.KEY_GUEST_CODE_STARTED, false)
                putString(GuestRuntimeProtocol.KEY_DIAGNOSTIC, "Missing or invalid runtime IPC request ID.")
            })
            return
        }

        val response = Bundle().apply { putString(GuestRuntimeProtocol.KEY_REQUEST_ID, requestId) }
        try {
            when (message.what) {
                GuestRuntimeProtocol.MESSAGE_LAUNCH_GUEST_RUNTIME -> launchGuestRuntime(data, response)
                GuestRuntimeProtocol.MESSAGE_STOP_SESSION -> stopSession(data, response)
                else -> throw IllegalArgumentException("Unsupported runtime IPC operation")
            }
        } catch (failure: Exception) {
            response.putString(GuestRuntimeProtocol.KEY_GUEST_ID,
                data.getString(GuestRuntimeProtocol.KEY_GUEST_ID).orEmpty().take(MAX_GUEST_ID_LENGTH))
            response.putString(GuestRuntimeProtocol.KEY_PACKAGE_NAME,
                data.getString(GuestRuntimeProtocol.KEY_PACKAGE_NAME).orEmpty().take(MAX_PACKAGE_NAME_LENGTH))
            response.putString(GuestRuntimeProtocol.KEY_SESSION_STATE, GuestRuntimeProtocol.STATE_REJECTED)
            response.putBoolean(GuestRuntimeProtocol.KEY_GUEST_CODE_STARTED, false)
            response.putLong(GuestRuntimeProtocol.KEY_STARTED_AT_EPOCH_MS, 0)
            response.putString(
                GuestRuntimeProtocol.KEY_DIAGNOSTIC,
                (failure.message ?: failure.javaClass.simpleName).take(MAX_DIAGNOSTIC_LENGTH),
            )
        }
        sendResponse(replyTo, response)
    }

    private fun launchGuestRuntime(data: Bundle, response: Bundle) {
        val guestId = data.getString(GuestRuntimeProtocol.KEY_GUEST_ID).orEmpty()
        val packageName = data.getString(GuestRuntimeProtocol.KEY_PACKAGE_NAME).orEmpty()
        val apkSha256 = data.getString(GuestRuntimeProtocol.KEY_APK_SHA256).orEmpty()
        val abis = data.getStringArray(GuestRuntimeProtocol.KEY_GUEST_ABIS).orEmpty()
        if (guestId.length > MAX_GUEST_ID_LENGTH || packageName.length > MAX_PACKAGE_NAME_LENGTH ||
            apkSha256.length > MAX_SHA256_LENGTH || abis.size > MAX_ABIS_PER_GUEST ||
            abis.any { it.length > MAX_ABI_NAME_LENGTH }
        ) {
            throw IllegalArgumentException("Runtime context request exceeds an IPC field limit")
        }
        val result = supervisor.startGuestRuntimeSession(
            GuestRuntimeContextRequest(
                guestId = guestId,
                packageName = packageName,
                apkSha256 = apkSha256,
                guestAbis = abis.toList(),
            ),
        )
        putResult(response, result)
    }

    private fun stopSession(data: Bundle, response: Bundle) {
        val sessionId = data.getString(GuestRuntimeProtocol.KEY_SESSION_ID).orEmpty()
        if (sessionId.length > MAX_REQUEST_ID_LENGTH) throw IllegalArgumentException("Invalid runtime session ID")
        putResult(response, supervisor.stopSession(sessionId))
    }

    private fun putResult(response: Bundle, result: GuestRuntimeSessionResult) {
        response.putString(GuestRuntimeProtocol.KEY_GUEST_ID, result.guestId)
        response.putString(GuestRuntimeProtocol.KEY_PACKAGE_NAME, result.packageName)
        response.putString(GuestRuntimeProtocol.KEY_SESSION_ID, result.sessionId)
        response.putString(GuestRuntimeProtocol.KEY_SESSION_STATE, result.state.name)
        response.putBoolean(GuestRuntimeProtocol.KEY_GUEST_CODE_STARTED, result.guestCodeStarted)
        response.putLong(GuestRuntimeProtocol.KEY_STARTED_AT_EPOCH_MS, result.startedAtEpochMs)
        response.putString(GuestRuntimeProtocol.KEY_DIAGNOSTIC, result.diagnostic.take(MAX_DIAGNOSTIC_LENGTH))
        response.putLong(GuestRuntimeProtocol.KEY_GUEST_INSTRUCTIONS, result.guestInstructions)
        response.putInt(GuestRuntimeProtocol.KEY_RELOCATION_COUNT, result.relocationCount)
        response.putInt(GuestRuntimeProtocol.KEY_JNI_ON_LOAD_VERSION, result.jniOnLoadVersion)
        response.putInt(GuestRuntimeProtocol.KEY_REGISTERED_NATIVE_COUNT, result.registeredNativeCount)
        response.putStringArray(GuestRuntimeProtocol.KEY_LOADED_LIBRARIES, result.loadedLibraries.take(MAX_REPORTED_ITEMS).toTypedArray())
        response.putStringArray(GuestRuntimeProtocol.KEY_ENTRYPOINT_RESULTS, result.entrypointResults.take(MAX_REPORTED_ITEMS).toTypedArray())
    }

    private fun sendResponse(replyTo: Messenger, response: Bundle) {
        val reply = Message.obtain(null, GuestRuntimeProtocol.MESSAGE_RESPONSE).apply { data = response }
        try {
            replyTo.send(reply)
        } catch (_: RemoteException) {
            // The caller may have left while a bounded runtime operation was in progress.
        }
    }

    companion object {
        private const val MAX_REQUEST_ID_LENGTH = 64
        private const val MAX_GUEST_ID_LENGTH = 36
        private const val MAX_PACKAGE_NAME_LENGTH = 255
        private const val MAX_SHA256_LENGTH = 64
        private const val MAX_ABI_NAME_LENGTH = 32
        private const val MAX_ABIS_PER_GUEST = 6
        private const val MAX_DIAGNOSTIC_LENGTH = 512
        private const val MAX_REPORTED_ITEMS = 64
    }
}
