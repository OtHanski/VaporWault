package com.vaporwault.client.ui

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.transfer.TransferBus
import com.vaporwault.client.transfer.TransferListener

/** Shows in-flight/completed transfers (TASK-229), backed by
 * [TransferBus.snapshot] for what's already happened plus live
 * [TransferListener] updates for what's still running. */
class TransferQueueActivity : AppCompatActivity(), TransferListener {

    private lateinit var adapter: TransferAdapter
    private lateinit var emptyText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transfer_queue)

        emptyText = findViewById(R.id.emptyText)
        val list = findViewById<RecyclerView>(R.id.transferList)
        adapter = TransferAdapter(TransferBus.snapshot())
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        refreshEmptyState()
    }

    override fun onStart() {
        super.onStart()
        TransferBus.register(this)
        adapter.update(TransferBus.snapshot())
        refreshEmptyState()
    }

    override fun onStop() {
        TransferBus.unregister(this)
        super.onStop()
    }

    override fun onProgress(transferId: String, label: String, bytesDone: Long, bytesTotal: Long) {
        runOnUiThread {
            adapter.update(TransferBus.snapshot())
            refreshEmptyState()
        }
    }

    override fun onComplete(transferId: String, succeeded: Boolean) {
        runOnUiThread {
            adapter.update(TransferBus.snapshot())
            refreshEmptyState()
        }
    }

    private fun refreshEmptyState() {
        emptyText.visibility = if (TransferBus.snapshot().isEmpty()) View.VISIBLE else View.GONE
    }
}
