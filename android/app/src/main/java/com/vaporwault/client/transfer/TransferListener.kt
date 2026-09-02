package com.vaporwault.client.transfer

/** Progress/completion hook for TASK-229's UI to bind to — see
 * [TransferManager]'s class doc for the overall lifecycle this reports on. */
interface TransferListener {
    fun onProgress(transferId: String, label: String, bytesDone: Long, bytesTotal: Long)
    fun onComplete(transferId: String, succeeded: Boolean)
}

/** Simple in-process pub/sub — no reactive-streams dependency pulled in
 * for this, consistent with the project's minimal-dependency philosophy;
 * a plain listener set is all a progress hook needs. */
object TransferBus {
    private val listeners = mutableSetOf<TransferListener>()

    @Synchronized fun register(listener: TransferListener) {
        listeners.add(listener)
    }

    @Synchronized fun unregister(listener: TransferListener) {
        listeners.remove(listener)
    }

    @Synchronized fun notifyProgress(transferId: String, label: String, bytesDone: Long, bytesTotal: Long) {
        listeners.forEach { it.onProgress(transferId, label, bytesDone, bytesTotal) }
    }

    @Synchronized fun notifyComplete(transferId: String, succeeded: Boolean) {
        listeners.forEach { it.onComplete(transferId, succeeded) }
    }
}
