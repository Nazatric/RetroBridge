package dev.retrobridge.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import dev.retrobridge.manager.GuestAppRecord
import dev.retrobridge.runtime.GuestRuntimeProtocol
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout

/** Messenger client for the non-exported service in :guest_runtime. */
class GuestRuntimeClient(context: Context) : Closeable {
    private val applicationContext = context.applicationContext
    private val lock = Any()
    private val pending = ConcurrentHashMap<String, CompletableDeferred<Bundle>>()
    private var remoteMessenger: Messenger? = null
    private var binding: CompletableDeferred<Messenger>? = null
    private var serviceConnection: ServiceConnection? = null
    private var bound = false
    private var closed = false

    private val replyMessenger = Messenger(Handler(Looper.getMainLooper()) { message ->
        if (message.what == GuestRuntimeProtocol.MESSAGE_RESPONSE) {
            val requestId = message.data.getString(GuestRuntimeProtocol.KEY_REQUEST_ID)
            if (requestId != null) pending.remove(requestId)?.complete(message.data)
        }
        true
    })

    suspend fun startInspectionSession(record: GuestAppRecord): GuestRuntimeSessionReply {
        val request = Bundle().apply {
            putString(GuestRuntimeProtocol.KEY_GUEST_ID, record.id)
            putString(GuestRuntimeProtocol.KEY_PACKAGE_NAME, record.packageName)
            putString(GuestRuntimeProtocol.KEY_APK_SHA256, record.sha256)
            putStringArray(GuestRuntimeProtocol.KEY_GUEST_ABIS, record.guestAbis.toTypedArray())
        }
        return decode(request(GuestRuntimeProtocol.MESSAGE_START_INSPECTION, request))
    }

    suspend fun stopSession(sessionId: String): GuestRuntimeSessionReply {
        val request = Bundle().apply { putString(GuestRuntimeProtocol.KEY_SESSION_ID, sessionId) }
        return decode(request(GuestRuntimeProtocol.MESSAGE_STOP_SESSION, request))
    }

    private suspend fun request(operation: Int, payload: Bundle): Bundle {
        val remote = connect()
        val requestId = UUID.randomUUID().toString()
        val response = CompletableDeferred<Bundle>()
        pending[requestId] = response
        val message = Message.obtain().apply {
            what = operation
            data = Bundle(payload).apply { putString(GuestRuntimeProtocol.KEY_REQUEST_ID, requestId) }
            replyTo = replyMessenger
        }
        try {
            remote.send(message)
            return withTimeout(IPC_TIMEOUT_MS) { response.await() }
        } finally {
            pending.remove(requestId)
        }
    }

    private suspend fun connect(): Messenger {
        val waiting = synchronized(lock) {
            check(!closed) { "Runtime client is closed" }
            remoteMessenger?.let { return it }
            binding?.let { return@synchronized it }

            val deferred = CompletableDeferred<Messenger>()
            binding = deferred
            val connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                    if (service == null) {
                        failBinding(IllegalStateException("Runtime service returned no binder"))
                        return
                    }
                    val messenger = Messenger(service)
                    synchronized(lock) {
                        if (closed) {
                            deferred.completeExceptionally(IllegalStateException("Runtime client is closed"))
                        } else {
                            remoteMessenger = messenger
                            deferred.complete(messenger)
                        }
                        if (binding === deferred) binding = null
                    }
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    failBinding(IllegalStateException("Runtime service process disconnected"))
                }

                override fun onBindingDied(name: ComponentName?) {
                    failBinding(IllegalStateException("Runtime service binding died"))
                }

                override fun onNullBinding(name: ComponentName?) {
                    failBinding(IllegalStateException("Runtime service rejected the binding"))
                }

                private fun failBinding(failure: Exception) {
                    val shouldUnbind = synchronized(lock) {
                        remoteMessenger = null
                        if (binding === deferred) binding = null
                        deferred.completeExceptionally(failure)
                        val release = serviceConnection === this && bound
                        if (release) {
                            serviceConnection = null
                            bound = false
                        }
                        release
                    }
                    if (shouldUnbind) runCatching { applicationContext.unbindService(this) }
                    pending.values.forEach { it.completeExceptionally(failure) }
                }
            }
            serviceConnection = connection
            val intent = Intent(applicationContext, dev.retrobridge.runtime.GuestRuntimeService::class.java)
                .setAction(GuestRuntimeProtocol.ACTION_BIND)
            try {
                bound = applicationContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
                if (!bound) {
                    binding = null
                    deferred.completeExceptionally(IllegalStateException("Unable to bind the runtime service"))
                }
            } catch (failure: Exception) {
                binding = null
                deferred.completeExceptionally(failure)
            }
            deferred
        }
        return waiting.await()
    }

    private fun decode(bundle: Bundle): GuestRuntimeSessionReply = GuestRuntimeSessionReply(
        sessionId = bundle.getString(GuestRuntimeProtocol.KEY_SESSION_ID),
        guestId = bundle.getString(GuestRuntimeProtocol.KEY_GUEST_ID).orEmpty(),
        packageName = bundle.getString(GuestRuntimeProtocol.KEY_PACKAGE_NAME).orEmpty(),
        state = bundle.getString(GuestRuntimeProtocol.KEY_SESSION_STATE) ?: GuestRuntimeProtocol.STATE_REJECTED,
        guestCodeStarted = bundle.getBoolean(GuestRuntimeProtocol.KEY_GUEST_CODE_STARTED, false),
        startedAtEpochMs = bundle.getLong(GuestRuntimeProtocol.KEY_STARTED_AT_EPOCH_MS, 0),
        diagnostic = bundle.getString(GuestRuntimeProtocol.KEY_DIAGNOSTIC).orEmpty(),
    )

    override fun close() {
        val pendingFailure = IllegalStateException("Runtime client was closed")
        val toUnbind = synchronized(lock) {
            if (closed) return
            closed = true
            val connection = serviceConnection.takeIf { bound }
            bound = false
            serviceConnection = null
            remoteMessenger = null
            binding?.completeExceptionally(pendingFailure)
            binding = null
            connection
        }
        pending.values.forEach { it.completeExceptionally(pendingFailure) }
        pending.clear()
        if (toUnbind != null) runCatching { applicationContext.unbindService(toUnbind) }
    }

    companion object {
        private const val IPC_TIMEOUT_MS = 5 * 60_000L
    }
}

data class GuestRuntimeSessionReply(
    val sessionId: String?,
    val guestId: String,
    val packageName: String,
    val state: String,
    val guestCodeStarted: Boolean,
    val startedAtEpochMs: Long,
    val diagnostic: String,
)
