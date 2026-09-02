package com.vaporwault.client.transfer

/**
 * In-memory registry handing a transfer-execution service (UIDT
 * [TransferJobService] or the pre-34 [TransferForegroundService]
 * fallback) the actual work closure to run, keyed by a small int id.
 *
 * A User-Initiated job (or a freshly-started foreground service) is
 * scheduled and expected to start essentially immediately within the
 * same live process it was scheduled from — unlike a `WorkManager` job
 * meant to survive reboot/process death — so there's no need for
 * `JobInfo`'s `PersistableBundle`-based extras here; [VwClient]'s native
 * session handle couldn't survive process death anyway.
 */
internal object PendingWork {
    private val work = mutableMapOf<Int, () -> Unit>()

    @Synchronized
    fun put(id: Int, block: () -> Unit) {
        work[id] = block
    }

    @Synchronized
    fun take(id: Int): (() -> Unit)? = work.remove(id)
}
