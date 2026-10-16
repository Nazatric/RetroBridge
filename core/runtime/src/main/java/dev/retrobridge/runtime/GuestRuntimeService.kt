package dev.retrobridge.runtime

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Process-boundary placeholder only. It intentionally performs no guest loading or execution;
 * until the runtime passes its security and ABI milestones, every start request is rejected.
 */
class GuestRuntimeService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopSelfResult(startId)
        return START_NOT_STICKY
    }
}
