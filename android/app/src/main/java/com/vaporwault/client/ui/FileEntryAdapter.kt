package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.PopupMenu
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.FileEntry
import com.vaporwault.client.R

class FileEntryAdapter(
    private var entries: List<FileEntry>,
    private val onOpenFolder: (FileEntry) -> Unit,
    private val onAction: (FileEntry, Int) -> Unit, // menu item id from file_entry_actions.xml
) : RecyclerView.Adapter<FileEntryAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val name: TextView = view.findViewById(R.id.entryName)
        val detail: TextView = view.findViewById(R.id.entryDetail)
        val menuButton: Button = view.findViewById(R.id.entryMenuButton)
    }

    fun update(newEntries: List<FileEntry>) {
        entries = newEntries
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_file_entry, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = entries.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val entry = entries[position]
        val isDir = entry.entryType == 1
        holder.name.text = (if (isDir) "📁 " else "📄 ") + entry.name
        holder.detail.text = if (isDir) "" else formatSize(entry.sizeBytes)
        holder.itemView.setOnClickListener { if (isDir) onOpenFolder(entry) }

        holder.menuButton.setOnClickListener { anchor ->
            val popup = PopupMenu(anchor.context, anchor)
            popup.inflate(R.menu.file_entry_actions)
            popup.menu.findItem(R.id.action_download)?.isVisible = !isDir
            popup.setOnMenuItemClickListener { item -> onAction(entry, item.itemId); true }
            popup.show()
        }
    }

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> "${bytes / 1024L} KB"
        else -> "${bytes / (1024L * 1024L)} MB"
    }
}
