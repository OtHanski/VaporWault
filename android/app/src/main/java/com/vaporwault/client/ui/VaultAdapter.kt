package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.VaultEntry

class VaultAdapter(
    private var vaults: List<VaultEntry>,
    private val onUnlock: (VaultEntry) -> Unit,
) : RecyclerView.Adapter<VaultAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.vaultLabel)
        val unlock: Button = view.findViewById(R.id.vaultUnlockButton)
    }

    fun update(newVaults: List<VaultEntry>) {
        vaults = newVaults
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_vault, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = vaults.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val vault = vaults[position]
        holder.label.text = "Vault #${vault.vaultId}"
        holder.unlock.setOnClickListener { onUnlock(vault) }
    }
}
