package com.vaporwault.client.transfer

/** State of one transfer, snapshotted by [TransferBus.snapshot] — lets a
 * freshly-opened transfer-queue screen show what's already in flight or
 * done, not just future updates it happens to be registered for. */
data class TransferRecord(
    val transferId: String,
    val label: String,
    val bytesDone: Long,
    val bytesTotal: Long,
    val state: TransferState,
)

enum class TransferState { RUNNING, DONE, FAILED }

/** Progress/completion hook for TASK-229's UI to bind to — see
 * [TransferManager]'s class doc for the overall lifecycle this reports on. */
interface TransferListener {
    fun onProgress(transferId: String, label: String, bytesDone: Long, bytesTotal: Long)
    fun onComplete(transferId: String, succeeded: Boolean)
}

/**
 * In-process pub/sub — no reactive-streams dependency pulled in for this,
 * consistent with the project's minimal-dependency philosophy — plus a
 * small in-memory [TransferRecord] table so a UI that opens *after* a
 * transfer already started can still show its current state via
 * [snapshot] instead of only ever seeing updates from that point forward.
 * The table is unbounded for the life of the process (no eviction of old
 * completed records) — acceptable for a "how many transfers happened this
 * session" scale; not meant to survive process death.
 */
object TransferBus {
    private val listeners = mutableSetOf<TransferListener>()
    private val records = LinkedHashMap<String, TransferRecord>()

    @Synchronized fun register(listener: TransferListener) {
        listeners.add(listener)
    }

    @Synchronized fun unregister(listener: TransferListener) {
        listeners.remove(listener)
    }

    @Synchronized fun snapshot(): List<TransferRecord> = records.values.toList()

    @Synchronized fun notifyStarted(transferId: String, label: String, bytesTotal: Long) {
        records[transferId] = TransferRecord(transferId, label, 0, bytesTotal, TransferState.RUNNING)
    }

    @Synchronized fun notifyProgress(transferId: String, label: String, bytesDone: Long, bytesTotal: Long) {
        records[transferId] = TransferRecord(transferId, label, bytesDone, bytesTotal, TransferState.RUNNING)
        listeners.forEach { it.onProgress(transferId, label, bytesDone, bytesTotal) }
    }

    @Synchronized fun notifyComplete(transferId: String, succeeded: Boolean) {
        records[transferId]?.let {
            records[transferId] = it.copy(state = if (succeeded) TransferState.DONE else TransferState.FAILED)
        }
        listeners.forEach { it.onComplete(transferId, succeeded) }
    }
}
