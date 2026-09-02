package com.vaporwault.client.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwSession
import com.vaporwault.client.accounts.Profile
import com.vaporwault.client.accounts.VwAccountRegistry
import kotlin.concurrent.thread

/**
 * Launcher activity (TASK-229). Lists saved profiles ([VwAccountRegistry],
 * TASK-227) for one-tap resume, or a plain form to add a new one —
 * including the 2FA challenge/response round trip, which never needs a
 * second real connect attempt: the first attempt (no OTP) either
 * succeeds, fails outright, or fails with `VW_ERR_AUTH_2FA_REQUIRED`, in
 * which case the *second* attempt (now with the OTP the user typed) is
 * the only one that actually consumes the single-use OTP
 * (`docs/PROTOCOL.md` §8.3) — retrying [VwAccountRegistry.addProfile]
 * itself, not a separate throwaway [VwClient.connect] probe first.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var registry: VwAccountRegistry
    private lateinit var profileAdapter: ProfileAdapter
    private lateinit var statusText: TextView
    private lateinit var otpField: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)
        registry = VwAccountRegistry(applicationContext)

        val hostField = findViewById<EditText>(R.id.hostField)
        val portField = findViewById<EditText>(R.id.portField)
        val userField = findViewById<EditText>(R.id.userField)
        val passField = findViewById<EditText>(R.id.passField)
        otpField = findViewById(R.id.otpField)
        statusText = findViewById(R.id.statusText)
        val connectButton = findViewById<Button>(R.id.connectButton)
        val profileList = findViewById<RecyclerView>(R.id.profileList)

        profileAdapter = ProfileAdapter(
            profiles = registry.listProfiles(),
            onTap = { profile -> resumeProfile(profile) },
            onRemove = { profile ->
                registry.removeProfile(profile.id)
                profileAdapter.update(registry.listProfiles())
            },
        )
        profileList.layoutManager = LinearLayoutManager(this)
        profileList.adapter = profileAdapter

        connectButton.setOnClickListener {
            val host = hostField.text.toString().trim()
            val port = portField.text.toString().toIntOrNull() ?: 0
            val user = userField.text.toString().trim()
            val pass = passField.text.toString().toByteArray(Charsets.UTF_8)
            val otp = otpField.text.toString().trim()
            connect(host, port, user, pass, otp)
        }
    }

    private fun resumeProfile(profile: Profile) {
        statusText.text = "Resuming ${profile.label}…"
        thread {
            val client = registry.resume(profile.id)
            // VwClient.lastError() reads a per-thread native slot — it must
            // be captured here, on the same background thread that made the
            // failing native call, not inside runOnUiThread (the main
            // thread's own slot, which was never touched by this attempt).
            val lastError = if (client == null) VwClient.lastError() else 0
            runOnUiThread {
                if (client != null) {
                    VwSession.set(client, profile)
                    goToBrowser()
                } else {
                    // Saved credentials no longer work (e.g. the account's
                    // password changed server-side) — no in-place
                    // "re-authenticate this exact profile" flow exists
                    // yet; the user can add it again below and remove the
                    // stale entry.
                    statusText.text =
                        "Could not resume ${profile.label}: vw_err_t=$lastError. " +
                        "Re-add it below, then remove the old entry."
                }
            }
        }
    }

    private fun connect(host: String, port: Int, user: String, pass: ByteArray, otp: String) {
        statusText.text = "Connecting…"
        thread {
            val result = registry.addProfile(label = user, host = host, port = port, username = user, password = pass, otp = otp)
            // Captured on this background thread — see the identical note
            // in resumeProfile() above; VwClient.lastError() is per-thread.
            val lastError = if (result == null) VwClient.lastError() else 0
            if (result == null && lastError == VwClient.ERR_AUTH_2FA_REQUIRED) {
                runOnUiThread {
                    otpField.visibility = View.VISIBLE
                    otpField.requestFocus()
                    statusText.text = "Enter the 2FA code sent to your email"
                }
                return@thread
            }
            runOnUiThread {
                if (result == null) {
                    statusText.text = "Connect failed: vw_err_t=$lastError"
                    return@runOnUiThread
                }
                val (profile, client) = result
                VwSession.set(client, profile)
                goToBrowser()
            }
        }
    }

    private fun goToBrowser() {
        startActivity(Intent(this, FileBrowserActivity::class.java))
        finish()
    }
}
