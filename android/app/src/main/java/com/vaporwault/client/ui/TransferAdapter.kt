package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.transfer.TransferManager
import com.vaporwault.client.transfer.TransferRecord
import com.vaporwault.client.transfer.TransferState

class TransferAdapter(
    private var records: List<TransferRecord>,
) : RecyclerView.Adapter<TransferAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.transferLabel)
        val progress: ProgressBar = view.findViewById(R.id.transferProgress)
        val status: TextView = view.findViewById(R.id.transferStatus)
        val cancel: Button = view.findViewById(R.id.transferCancelButton)
    }

    fun update(newRecords: List<TransferRecord>) {
        records = newRecords
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_transfer, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = records.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val record = records[position]
        holder.label.text = record.label
        val percent = if (record.bytesTotal > 0) {
            ((record.bytesDone * 100) / record.bytesTotal).toInt().coerceIn(0, 100)
        } else {
            0
        }
        holder.progress.progress = percent
        holder.status.text = when (record.state) {
            TransferState.RUNNING -> "${record.bytesDone} / ${record.bytesTotal} bytes"
            TransferState.DONE -> "Complete"
            TransferState.FAILED -> "Failed"
        }
        holder.cancel.visibility = if (record.state == TransferState.RUNNING) View.VISIBLE else View.GONE
        holder.cancel.setOnClickListener { TransferManager.cancel(record.transferId) }
    }
}
