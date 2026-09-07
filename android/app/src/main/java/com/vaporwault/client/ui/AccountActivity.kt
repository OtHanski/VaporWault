package com.vaporwault.client.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.vaporwault.client.R
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwSession
import kotlin.concurrent.thread

/** Account self-service settings (TASK-232): email, 2FA toggle, per-category
 * email notification preferences. Every wire message this screen uses
 * already existed from TASK-226 — no protocol work needed here. */
class AccountActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var emailField: EditText
    private lateinit var twoFaStatusText: TextView
    private lateinit var twoFaPasswordField: EditText
    private lateinit var toggle2faButton: Button
    private lateinit var notifyShareReceived: CheckBox
    private lateinit var notifyQuotaWarning: CheckBox
    private lateinit var notifyNewLogin: CheckBox
    private lateinit var notifyAccountSecurityChange: CheckBox

    private var current2fa = false
    /** Guards the checkbox listeners while we're populating them from a
     * freshly-fetched server value, so loading state doesn't itself fire a
     * spurious NOTIFY_PREFS_SET. */
    private var loadingPrefs = false

    private val client: VwClient get() = VwSession.client ?: error("no active session")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (VwSession.client == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }
        setContentView(R.layout.activity_account)

        statusText = findViewById(R.id.statusText)
        emailField = findViewById(R.id.emailField)
        twoFaStatusText = findViewById(R.id.twoFaStatusText)
        twoFaPasswordField = findViewById(R.id.twoFaPasswordField)
        toggle2faButton = findViewById(R.id.toggle2faButton)
        notifyShareReceived = findViewById(R.id.notifyShareReceived)
        notifyQuotaWarning = findViewById(R.id.notifyQuotaWarning)
        notifyNewLogin = findViewById(R.id.notifyNewLogin)
        notifyAccountSecurityChange = findViewById(R.id.notifyAccountSecurityChange)

        findViewById<Button>(R.id.saveEmailButton).setOnClickListener { saveEmail() }
        toggle2faButton.setOnClickListener { toggle2fa() }
        for (box in listOf(notifyShareReceived, notifyQuotaWarning, notifyNewLogin, notifyAccountSecurityChange)) {
            box.setOnCheckedChangeListener { _, _ -> if (!loadingPrefs) saveNotifyPrefs() }
        }

        loadAll()
    }

    private fun loadAll() {
        statusText.text = getString(R.string.status_loading)
        thread {
            val email = client.getEmail()
            val twoFa = client.get2fa()
            val prefs = client.getNotifyPrefs()
            runOnUiThread {
                statusText.text = ""
                email?.let { emailField.setText(it) }
                if (twoFa >= 0) applyTwoFaState(twoFa == 1)
                if (prefs >= 0) applyNotifyPrefs(prefs)
            }
        }
    }

    private fun applyTwoFaState(enabled: Boolean) {
        current2fa = enabled
        twoFaStatusText.text = if (enabled) "Currently ON" else "Currently OFF"
        toggle2faButton.setText(if (enabled) R.string.action_2fa_off else R.string.action_2fa_on)
    }

    private fun applyNotifyPrefs(prefs: Long) {
        loadingPrefs = true
        notifyShareReceived.isChecked = (prefs and NOTIFY_SHARE_RECEIVED) != 0L
        notifyQuotaWarning.isChecked = (prefs and NOTIFY_QUOTA_WARNING) != 0L
        notifyNewLogin.isChecked = (prefs and NOTIFY_NEW_LOGIN) != 0L
        notifyAccountSecurityChange.isChecked = (prefs and NOTIFY_ACCOUNT_SECURITY_CHANGE) != 0L
        loadingPrefs = false
    }

    private fun saveEmail() {
        val email = emailField.text.toString().trim()
        statusText.text = getString(R.string.status_working)
        thread {
            val result = client.setEmail(email)
            val lastError = if (result == null) VwClient.lastError() else 0
            runOnUiThread {
                statusText.text = if (result != null) "Email saved" else "Save failed: vw_err_t=$lastError"
            }
        }
    }

    private fun toggle2fa() {
        val password = twoFaPasswordField.text.toString().toByteArray(Charsets.UTF_8)
        if (password.isEmpty()) {
            statusText.text = "Current password is required"
            return
        }
        val enable = !current2fa
        statusText.text = getString(R.string.status_working)
        thread {
            val result = client.set2fa(password, enable)
            val lastError = if (result < 0) VwClient.lastError() else 0
            runOnUiThread {
                twoFaPasswordField.setText("")
                if (result < 0) {
                    statusText.text = "2FA toggle failed: vw_err_t=$lastError"
                } else {
                    applyTwoFaState(result == 1)
                    statusText.text = "2FA updated"
                }
            }
        }
    }

    private fun saveNotifyPrefs() {
        var prefs = 0L
        if (notifyShareReceived.isChecked) prefs = prefs or NOTIFY_SHARE_RECEIVED
        if (notifyQuotaWarning.isChecked) prefs = prefs or NOTIFY_QUOTA_WARNING
        if (notifyNewLogin.isChecked) prefs = prefs or NOTIFY_NEW_LOGIN
        if (notifyAccountSecurityChange.isChecked) prefs = prefs or NOTIFY_ACCOUNT_SECURITY_CHANGE
        thread {
            val result = client.setNotifyPrefs(prefs)
            if (result < 0) {
                val lastError = VwClient.lastError()
                runOnUiThread { statusText.text = "Notify prefs failed: vw_err_t=$lastError" }
            }
        }
    }

    companion object {
        // Mirrors src/core/vw_proto.h's VW_NOTIFY_* bitmask exactly.
        private const val NOTIFY_SHARE_RECEIVED = 0x1L
        private const val NOTIFY_QUOTA_WARNING = 0x2L
        private const val NOTIFY_NEW_LOGIN = 0x4L
        private const val NOTIFY_ACCOUNT_SECURITY_CHANGE = 0x8L
    }
}
