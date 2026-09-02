package com.vaporwault.client.transfer

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.Uri
import android.os.Build
import com.vaporwault.client.VwClient
import java.util.concurrent.atomic.AtomicInteger

/**
 * Entry point for on-demand transfers (TASK-228). Picks a User-Initiated
 * Data Transfer job ([TransferJobService], API 34+) when available,
 * falling back to [TransferForegroundService] pre-34 — both wrap the same
 * [FileTransferer] core logic and report through the same [TransferBus]
 * hook, so TASK-229's UI never needs to know which execution path
 * actually ran for a given transfer.
 *
 * Each call returns a `transferId` immediately; the actual transfer runs
 * asynchronously and reports progress/completion through [TransferBus]
 * under that id.
 */
object TransferManager {
    private val nextWorkId = AtomicInteger(1)

    fun uploadFile(
        context: Context,
        client: VwClient,
        sourceUri: Uri,
        target: UploadTarget,
        label: String,
        sizeBytes: Long,
    ): String {
        val transferId = "up-${System.currentTimeMillis()}"
        run(context, uploadBytes = sizeBytes, downloadBytes = 0) {
            val result = FileTransferer(context, client).uploadFile(sourceUri, target) { done, total ->
                TransferBus.notifyProgress(transferId, label, done, total)
            }
            TransferBus.notifyComplete(transferId, result != null)
        }
        return transferId
    }

    fun downloadFile(
        context: Context,
        client: VwClient,
        fileId: Long,
        destUri: Uri,
        label: String,
        sizeBytes: Long,
    ): String {
        val transferId = "down-${System.currentTimeMillis()}"
        run(context, uploadBytes = 0, downloadBytes = sizeBytes) {
            val success = FileTransferer(context, client).downloadFile(fileId, destUri) { done, total ->
                TransferBus.notifyProgress(transferId, label, done, total)
            }
            TransferBus.notifyComplete(transferId, success)
        }
        return transferId
    }

    private fun run(context: Context, uploadBytes: Long, downloadBytes: Long, work: () -> Unit) {
        val workId = nextWorkId.getAndIncrement()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            PendingWork.put(workId, work)
            val scheduler = context.getSystemService(JobScheduler::class.java)
            // setEstimatedNetworkBytes() throws IllegalStateException unless
            // setRequiredNetwork() is also set (found the hard way — the API
            // doc example that got this right didn't call out that this
            // pairing is mandatory, not just illustrative).
            val networkRequest = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            val jobInfo = JobInfo.Builder(workId, ComponentName(context, TransferJobService::class.java))
                .setUserInitiated(true)
                .setRequiredNetwork(networkRequest)
                .setEstimatedNetworkBytes(downloadBytes.coerceAtLeast(1), uploadBytes.coerceAtLeast(1))
                .build()
            scheduler.schedule(jobInfo)
        } else {
            TransferForegroundService.start(context, workId, work)
        }
    }
}
