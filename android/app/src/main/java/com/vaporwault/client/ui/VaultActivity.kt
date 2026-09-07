package com.vaporwault.client.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.R
import com.vaporwault.client.VaultEntry
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwSession
import com.vaporwault.client.VwVault
import kotlin.concurrent.thread

/**
 * Lists existing vaults (unlock-only — passphrase never leaves this
 * screen except as bytes fed straight into the native bridge) and creates
 * new ones (TASK-230). On success either way, sets [VwSession.vault] and
 * hands off to [FileBrowserActivity] in vault mode.
 */
class VaultActivity : AppCompatActivity() {

    private lateinit var adapter: VaultAdapter
    private lateinit var statusText: TextView
    private lateinit var emptyText: TextView

    private val client: VwClient get() = VwSession.client ?: error("no active session")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (VwSession.client == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }
        setContentView(R.layout.activity_vaults)

        statusText = findViewById(R.id.statusText)
        emptyText = findViewById(R.id.emptyVaultsText)
        val vaultList = findViewById<RecyclerView>(R.id.vaultList)
        adapter = VaultAdapter(emptyList()) { vault -> promptUnlock(vault) }
        vaultList.layoutManager = LinearLayoutManager(this)
        vaultList.adapter = adapter

        findViewById<Button>(R.id.createVaultButton).setOnClickListener { createVault() }

        loadVaults()
    }

    private fun loadVaults() {
        statusText.text = getString(R.string.status_loading)
        thread {
            val vaults = client.listVaults()
            val lastError = if (vaults == null) VwClient.lastError() else 0
            runOnUiThread {
                statusText.text = ""
                if (vaults == null) {
                    statusText.text = "List failed: vw_err_t=$lastError"
                    return@runOnUiThread
                }
                adapter.update(vaults)
                emptyText.visibility = if (vaults.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
            }
        }
    }

    /** Reads chars directly out of an EditText's Editable — never through
     * `toString()` — so the passphrase never exists as a Java String. */
    private fun passphraseChars(field: EditText): CharArray {
        val editable = field.text
        val chars = CharArray(editable.length)
        editable.getChars(0, editable.length, chars, 0)
        return chars
    }

    /** Overwrites every element with NUL — the standard char[]-clearing
     * idiom (matches java.util.Arrays.fill(char[], Char.MIN_VALUE) as used
     * by javax.security.auth.Destroyable implementations). */
    private fun wipe(chars: CharArray) {
        for (i in chars.indices) chars[i] = Char.MIN_VALUE
    }

    private fun promptUnlock(vault: VaultEntry) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.action_unlock) + " Vault #${vault.vaultId}")
            .setView(input)
            .setPositiveButton(R.string.action_unlock) { _, _ ->
                val chars = passphraseChars(input)
                statusText.text = getString(R.string.status_unlocking)
                thread {
                    val opened = VwVault.unlock(client, vault.vaultId, chars)
                    wipe(chars)
                    val lastError = if (opened == null) VwVault.lastError() else 0
                    runOnUiThread {
                        if (opened == null) {
                            statusText.text = "Unlock failed: vw_err_t=$lastError"
                            return@runOnUiThread
                        }
                        VwSession.setVault(opened)
                        goToBrowser()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun createVault() {
        val folderField = findViewById<EditText>(R.id.newVaultFolderField)
        val passField = findViewById<EditText>(R.id.newVaultPassphraseField)
        val confirmField = findViewById<EditText>(R.id.newVaultPassphraseConfirmField)

        val folderName = folderField.text.toString().trim()
        if (folderName.isEmpty()) return

        val chars = passphraseChars(passField)
        val confirmChars = passphraseChars(confirmField)
        if (!chars.contentEquals(confirmChars)) {
            wipe(chars); wipe(confirmChars)
            statusText.text = getString(R.string.error_passphrase_mismatch)
            return
        }
        wipe(confirmChars)
        if (chars.size < 8) {
            wipe(chars)
            statusText.text = getString(R.string.error_passphrase_too_short)
            return
        }

        statusText.text = getString(R.string.status_creating_vault)
        thread {
            val newFolderId = client.mkdir(0L, folderName)
            if (newFolderId == 0L) {
                wipe(chars)
                val err = VwClient.lastError()
                runOnUiThread { statusText.text = "Create failed: vw_err_t=$err" }
                return@thread
            }
            val vault = VwVault.setup(client, newFolderId, chars)
            wipe(chars)
            val lastError = if (vault == null) VwVault.lastError() else 0
            runOnUiThread {
                if (vault == null) {
                    statusText.text = "Create failed: vw_err_t=$lastError"
                    return@runOnUiThread
                }
                VwSession.setVault(vault)
                goToBrowser()
            }
        }
    }

    private fun goToBrowser() {
        startActivity(Intent(this, FileBrowserActivity::class.java))
        finish()
    }
}
