package com.vaporwault.client.transfer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.job.JobParameters
import android.app.job.JobService
import android.os.Build
import androidx.annotation.RequiresApi
import kotlin.concurrent.thread

/**
 * User-Initiated Data Transfer execution path (API 34+) for
 * [TransferManager]. A UIDT job must promote itself to a user-visible
 * notification quickly — [onStartJob] does that before doing any actual
 * work, via the API-34 `setNotification()`/`JOB_END_NOTIFICATION_POLICY_DETACH`
 * pair, then runs the work closure on a plain background thread (no
 * coroutines dependency pulled in for this — matches the rest of the app).
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class TransferJobService : JobService() {

    override fun onStartJob(params: JobParameters): Boolean {
        val work = PendingWork.take(params.jobId) ?: return false

        ensureChannel()
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("VaporWault")
            .setContentText("Transferring…")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .build()
        setNotification(params, params.jobId, notification, JOB_END_NOTIFICATION_POLICY_DETACH)

        thread {
            try {
                work()
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = false

    private fun ensureChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Transfers", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    companion object {
        const val CHANNEL_ID = "vw_transfers"
    }
}
