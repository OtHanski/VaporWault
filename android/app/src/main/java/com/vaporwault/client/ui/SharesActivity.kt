package com.vaporwault.client.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwSession
import kotlin.concurrent.thread

/** Lists share grants the current account has created (mode=0 — "shared
 * with me" browsing is a separate, larger feature, out of TASK-231's
 * scope) and public links it has minted, each with a Revoke action
 * (TASK-231). */
class SharesActivity : AppCompatActivity() {

    private lateinit var shareAdapter: ShareAdapter
    private lateinit var linkAdapter: LinkAdapter
    private lateinit var statusText: TextView
    private lateinit var emptyShares: TextView
    private lateinit var emptyLinks: TextView

    private val client: VwClient get() = VwSession.client ?: error("no active session")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (VwSession.client == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }
        setContentView(R.layout.activity_shares)

        statusText = findViewById(R.id.statusText)
        emptyShares = findViewById(R.id.emptySharesText)
        emptyLinks = findViewById(R.id.emptyLinksText)

        shareAdapter = ShareAdapter(emptyList()) { share -> revokeShare(share.shareId) }
        findViewById<RecyclerView>(R.id.shareList).apply {
            layoutManager = LinearLayoutManager(this@SharesActivity)
            adapter = shareAdapter
        }

        linkAdapter = LinkAdapter(emptyList()) { link -> revokeShare(link.shareId) }
        findViewById<RecyclerView>(R.id.linkList).apply {
            layoutManager = LinearLayoutManager(this@SharesActivity)
            adapter = linkAdapter
        }

        loadAll()
    }

    private fun loadAll() {
        statusText.text = getString(R.string.status_loading)
        thread {
            // SHARE_LIST/LINK_LIST return revoked entries too (their own
            // history, not filtered server-side — see ShareEntry/LinkEntry's
            // `revoked` field) — this is a management view of what's
            // currently active, so filter them out here rather than showing
            // a still-clickable "Revoke" button on an already-dead entry.
            val shares = client.listShares(0)?.filterNot { it.revoked }
            val links = client.listLinks()?.filterNot { it.revoked }
            runOnUiThread {
                statusText.text = ""
                shares?.let {
                    shareAdapter.update(it)
                    emptyShares.visibility = if (it.isEmpty()) View.VISIBLE else View.GONE
                }
                links?.let {
                    linkAdapter.update(it)
                    emptyLinks.visibility = if (it.isEmpty()) View.VISIBLE else View.GONE
                }
            }
        }
    }

    /** Both share grants and public links revoke through the same
     * SHARE_REVOKE-by-share_id wire call — see vw_client_core.h's
     * vw_client_share_revoke doc. */
    private fun revokeShare(shareId: Long) {
        statusText.text = getString(R.string.status_working)
        thread {
            val err = client.shareRevoke(shareId)
            runOnUiThread {
                if (err == 0) {
                    loadAll()
                } else {
                    statusText.text = "Revoke failed: vw_err_t=$err"
                }
            }
        }
    }
}
