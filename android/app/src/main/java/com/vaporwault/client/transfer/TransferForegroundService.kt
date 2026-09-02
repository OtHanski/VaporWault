package com.vaporwault.client.transfer

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlin.concurrent.thread

/**
 * Pre-API-34 fallback execution path for [TransferManager] — a
 * `dataSync`-typed foreground service with a persistent notification,
 * running the same work closure a UIDT job would run on 34+. Declared
 * with `foregroundServiceType="dataSync"` in the manifest (Android 14+
 * requires this even though the app's own minSdk is 26, since a device
 * running this fallback path could itself be on any OS version up to but
 * excluding 34).
 *
 * Only one transfer's work runs per service start; [TransferManager] is
 * responsible for not starting a second transfer while one is already in
 * flight if it wants to avoid two concurrent foreground-service
 * notifications (not yet enforced here — a TASK-229 UI concern).
 */
class TransferForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val workId = intent?.getIntExtra(EXTRA_WORK_ID, -1) ?: -1
        val work = if (workId >= 0) PendingWork.take(workId) else null

        ensureChannel()
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VaporWault")
            .setContentText("Transferring…")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)

        thread {
            try {
                work?.invoke()
            } finally {
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    private fun ensureChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Transfers", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    companion object {
        private const val CHANNEL_ID = "vw_transfers"
        private const val NOTIFICATION_ID = 1001
        private const val EXTRA_WORK_ID = "work_id"

        fun start(context: Context, workId: Int, work: () -> Unit) {
            PendingWork.put(workId, work)
            val intent = Intent(context, TransferForegroundService::class.java)
                .putExtra(EXTRA_WORK_ID, workId)
            context.startForegroundService(intent)
        }
    }
}
