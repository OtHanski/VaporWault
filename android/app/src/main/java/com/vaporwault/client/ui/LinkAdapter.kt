package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.LinkEntry
import com.vaporwault.client.R

class LinkAdapter(
    private var links: List<LinkEntry>,
    private val onRevoke: (LinkEntry) -> Unit,
) : RecyclerView.Adapter<LinkAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.shareLabel)
        val revoke: Button = view.findViewById(R.id.shareRevokeButton)
    }

    fun update(newLinks: List<LinkEntry>) {
        links = newLinks
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_share, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = links.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val link = links[position]
        val perm = if (link.permission == 2) "edit" else "view"
        val pw = if (link.hasPassword) ", password-protected" else ""
        holder.label.text = "${link.name} ($perm$pw)"
        holder.revoke.setOnClickListener { onRevoke(link) }
    }
}
