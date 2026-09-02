package com.vaporwault.client.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.accounts.Profile

class ProfileAdapter(
    private var profiles: List<Profile>,
    private val onTap: (Profile) -> Unit,
    private val onRemove: (Profile) -> Unit,
) : RecyclerView.Adapter<ProfileAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.profileLabel)
        val remove: Button = view.findViewById(R.id.profileRemoveButton)
    }

    fun update(newProfiles: List<Profile>) {
        profiles = newProfiles
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_profile, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = profiles.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val profile = profiles[position]
        holder.label.text = "${profile.label} — ${profile.username}@${profile.host}:${profile.port}"
        holder.label.setOnClickListener { onTap(profile) }
        holder.remove.setOnClickListener { onRemove(profile) }
    }
}
