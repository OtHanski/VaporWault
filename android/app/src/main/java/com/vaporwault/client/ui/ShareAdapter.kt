package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.ShareEntry

class ShareAdapter(
    private var shares: List<ShareEntry>,
    private val onRevoke: (ShareEntry) -> Unit,
) : RecyclerView.Adapter<ShareAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.shareLabel)
        val revoke: Button = view.findViewById(R.id.shareRevokeButton)
    }

    fun update(newShares: List<ShareEntry>) {
        shares = newShares
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_share, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = shares.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val share = shares[position]
        val perm = if (share.permission == 2) "edit" else "view"
        holder.label.text = "${share.name} → ${share.targetUsername} ($perm)"
        holder.revoke.setOnClickListener { onRevoke(share) }
    }
}
