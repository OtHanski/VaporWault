package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R

/** One level of [FileBrowserActivity]'s navigation stack. [dirFileId] ==
 * null means the root ("/", listed via `VwClient.listFiles`, not
 * `listFilesById` — the root isn't a real directory record). */
data class BreadcrumbLevel(val label: String, val dirFileId: Long?)

class BreadcrumbAdapter(
    private var levels: List<BreadcrumbLevel>,
    private val onTap: (Int) -> Unit,
) : RecyclerView.Adapter<BreadcrumbAdapter.ViewHolder>() {

    class ViewHolder(val label: TextView) : RecyclerView.ViewHolder(label)

    fun update(newLevels: List<BreadcrumbLevel>) {
        levels = newLevels
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_breadcrumb, parent, false) as TextView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = levels.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val level = levels[position]
        holder.label.text = if (position < levels.size - 1) "${level.label} ›" else level.label
        holder.label.setOnClickListener { onTap(position) }
    }
}
