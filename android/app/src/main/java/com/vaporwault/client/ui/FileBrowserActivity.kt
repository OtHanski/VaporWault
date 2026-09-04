package com.vaporwault.client.ui

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vaporwault.client.FileEntry
import com.vaporwault.client.R
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwSession
import com.vaporwault.client.transfer.TransferBus
import com.vaporwault.client.transfer.TransferListener
import com.vaporwault.client.transfer.TransferManager
import com.vaporwault.client.transfer.UploadTarget
import java.io.File
import kotlin.concurrent.thread

/**
 * The core "Drive-like" screen (TASK-229): breadcrumb navigation + a
 * RecyclerView of the current folder's contents, upload/new-folder
 * actions, and a per-row menu for download/rename/move/delete. Requires
 * [VwSession.client] to already be set (via [LoginActivity]) — redirects
 * back there defensively if not (shouldn't normally happen).
 */
class FileBrowserActivity : AppCompatActivity() {

    private val breadcrumbs = mutableListOf<BreadcrumbLevel>()
    private lateinit var fileAdapter: FileEntryAdapter
    private lateinit var breadcrumbAdapter: BreadcrumbAdapter
    private lateinit var statusText: TextView
    private lateinit var emptyText: TextView

    private var pendingDownload: FileEntry? = null

    private val client: VwClient get() = VwSession.client ?: error("no active session")

    // TASK-246: every upload actually runs on a background thread inside a
    // JobScheduler-dispatched TransferJobService (API 34+) or foreground
    // service (pre-34), not synchronously on this Activity's own thread.
    // The picker only grants this Activity a read grant on the returned
    // Uri that's guaranteed valid for as long as this callback runs — not
    // guaranteed to survive to whenever that background job actually
    // executes. TASK-243 tried extending that grant's lifetime instead
    // (takePersistableUriPermission) and confirmed, via a diagnostic log,
    // that the grant was genuinely still present at crash time and the
    // read still failed for some document-provider resolutions
    // (MediaDocumentsProvider specifically) — so a longer-lived grant
    // doesn't fully close this. Instead: read the picked Uri's bytes into
    // this app's own private storage synchronously, right here, while the
    // grant is at its freshest — the background job then only ever touches
    // a plain `file://` Uri over that local copy, which needs no SAF grant
    // at all (ContentResolver.openInputStream special-cases the file
    // scheme as a direct filesystem open). [uploadFile] deletes the staged
    // copy once the transfer completes.
    private val openDocument = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) uploadFile(uri)
    }

    private val createDocument = registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val entry = pendingDownload
        pendingDownload = null
        if (uri != null && entry != null) {
            try {
                contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            } catch (_: SecurityException) {
                // Provider doesn't support persistable grants — proceed anyway.
            }
            downloadFile(entry, uri)
        }
    }

    // TASK-243: found while writing VaultFlowTest — every upload/download
    // here runs through TransferManager, which on API 34+ schedules a
    // User-Initiated Data Transfer job (TransferJobService). A UIDT job
    // must promote itself to a visible notification (its
    // setNotification() call); without POST_NOTIFICATIONS granted, that
    // silently degrades the job badly enough that the picked SAF Uri's
    // read grant is gone by the time the transfer actually runs a
    // SecurityException ("... requires ACTION_OPEN_DOCUMENT or related
    // APIs"), reproduced consistently for vault uploads specifically.
    // Requested here (best-effort, no blocking on the result — a denial
    // still leaves every pre-34 and non-UIDT path unaffected) since this
    // screen is where every transfer actually originates.
    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* best-effort */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (VwSession.client == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContentView(R.layout.activity_file_browser)
        val vault = VwSession.vault
        if (vault != null) {
            // Vaults are flat (see uploadFile's note) — a single breadcrumb
            // level at the vault's own folder, never "Home", and no way to
            // navigate above it short of Exit Vault.
            breadcrumbs.add(BreadcrumbLevel(getString(R.string.vault_breadcrumb), vault.folderFileId))
        } else {
            breadcrumbs.add(BreadcrumbLevel(getString(R.string.root_breadcrumb), null))
        }

        statusText = findViewById(R.id.statusText)
        emptyText = findViewById(R.id.emptyText)
        val fileList = findViewById<RecyclerView>(R.id.fileList)
        val breadcrumbList = findViewById<RecyclerView>(R.id.breadcrumbList)

        fileAdapter = FileEntryAdapter(
            entries = emptyList(),
            onOpenFolder = { entry -> openFolder(entry) },
            onAction = { entry, actionId -> handleAction(entry, actionId) },
        )
        fileList.layoutManager = LinearLayoutManager(this)
        fileList.adapter = fileAdapter

        breadcrumbAdapter = BreadcrumbAdapter(breadcrumbs) { index -> navigateToBreadcrumb(index) }
        breadcrumbList.layoutManager = LinearLayoutManager(this, LinearLayoutManager.HORIZONTAL, false)
        breadcrumbList.adapter = breadcrumbAdapter

        findViewById<Button>(R.id.transfersButton).setOnClickListener {
            startActivity(Intent(this, TransferQueueActivity::class.java))
        }
        findViewById<Button>(R.id.logoutButton).setOnClickListener {
            VwSession.clear()
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        }
        findViewById<Button>(R.id.uploadButton).setOnClickListener { openDocument.launch(arrayOf("*/*")) }
        val newFolderButton = findViewById<Button>(R.id.newFolderButton)
        newFolderButton.setOnClickListener { promptNewFolder() }

        if (vault != null) {
            // No subfolder concept inside a vault (see uploadFile's note) —
            // plain FILE_MKDIR would create an unencrypted folder nested
            // inside the vault's own, which is more confusing than useful.
            newFolderButton.visibility = View.GONE
            findViewById<Button>(R.id.vaultsButton).visibility = View.GONE
            findViewById<Button>(R.id.exitVaultButton).apply {
                visibility = View.VISIBLE
                setOnClickListener {
                    VwSession.clearVault()
                    startActivity(Intent(this@FileBrowserActivity, FileBrowserActivity::class.java))
                    finish()
                }
            }
        } else {
            findViewById<Button>(R.id.vaultsButton).setOnClickListener {
                startActivity(Intent(this, VaultActivity::class.java))
            }
        }

        // Account-wide, not folder/vault-scoped — available in both modes.
        findViewById<Button>(R.id.sharesButton).setOnClickListener {
            startActivity(Intent(this, SharesActivity::class.java))
        }
        findViewById<Button>(R.id.accountButton).setOnClickListener {
            startActivity(Intent(this, AccountActivity::class.java))
        }

        loadCurrentFolder()
    }

    private fun currentDirId(): Long = breadcrumbs.last().dirFileId ?: 0L

    private fun loadCurrentFolder() {
        statusText.text = getString(R.string.status_loading)
        val level = breadcrumbs.last()
        thread {
            val entries = if (level.dirFileId == null) {
                client.listFiles("/", recursive = false)
            } else {
                client.listFilesById(level.dirFileId, recursive = false)
            }
            val lastError = if (entries == null) VwClient.lastError() else 0
            runOnUiThread {
                if (entries == null) {
                    statusText.text = "List failed: vw_err_t=$lastError"
                    return@runOnUiThread
                }
                statusText.text = ""
                emptyText.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
                val sorted = entries.sortedWith(compareByDescending<FileEntry> { it.entryType }.thenBy { it.name })
                fileAdapter.update(sorted)
            }
        }
    }

    private fun openFolder(entry: FileEntry) {
        breadcrumbs.add(BreadcrumbLevel(entry.name, entry.fileId))
        breadcrumbAdapter.update(breadcrumbs)
        loadCurrentFolder()
    }

    private fun navigateToBreadcrumb(index: Int) {
        while (breadcrumbs.size > index + 1) breadcrumbs.removeAt(breadcrumbs.size - 1)
        breadcrumbAdapter.update(breadcrumbs)
        loadCurrentFolder()
    }

    private fun handleAction(entry: FileEntry, actionId: Int) {
        when (actionId) {
            R.id.action_download -> promptDownload(entry)
            R.id.action_share -> promptShare(entry)
            R.id.action_get_link -> promptGetLink(entry)
            R.id.action_rename -> promptRename(entry)
            R.id.action_move -> promptMove(entry)
            R.id.action_delete -> confirmDelete(entry)
        }
    }

    private fun promptDownload(entry: FileEntry) {
        pendingDownload = entry
        createDocument.launch(entry.name)
    }

    private fun downloadFile(entry: FileEntry, destUri: Uri) {
        val vault = VwSession.vault
        val transferId = if (vault != null) {
            TransferManager.vaultDownloadFile(
                applicationContext, client, vault, entry.fileId, destUri, entry.name, entry.sizeBytes,
            )
        } else {
            TransferManager.downloadFile(
                applicationContext, client, entry.fileId, destUri, entry.name, entry.sizeBytes,
            )
        }
        awaitAndRefresh(transferId, "Download", releaseUri = destUri, releaseFlags = Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    }

    private fun uploadFile(sourceUri: Uri) {
        val name = queryDisplayName(sourceUri) ?: "upload.bin"
        val size = querySize(sourceUri) ?: -1L

        // vault/target snapshot the background staging thread below needs
        // — read here, on the main thread, since breadcrumbs is only ever
        // otherwise touched from it (openFolder/navigateToBreadcrumb).
        val vault = VwSession.vault
        val target = if (vault == null) {
            if (breadcrumbs.last().dirFileId == null) {
                UploadTarget.NewFile("/$name")
            } else {
                UploadTarget.NewInFolder(currentDirId(), name)
            }
        } else {
            null
        }

        // TASK-246: stage into cacheDir before the picked Uri's grant has
        // any chance to become stale by the time a background transfer
        // job actually runs — but the copy itself is real, possibly slow
        // blocking I/O (a large file), so it must not run on this (the
        // main) thread the way every other network/IO call in this class
        // already avoids doing. Staging is initiated here (from the picker
        // callback, while the grant is freshest) but the actual bytes move
        // on a background thread, same as everything else that touches
        // the network or disk in this Activity.
        statusText.text = "Preparing upload…"
        thread {
            val staged = File.createTempFile("vw_upload_", ".tmp", cacheDir)
            val copied = try {
                contentResolver.openInputStream(sourceUri)?.use { input ->
                    staged.outputStream().use { output -> input.copyTo(output) }
                    true
                } ?: false
            } catch (e: Exception) {
                false
            }
            if (!copied) {
                staged.delete()
                runOnUiThread { statusText.text = "Could not read the selected file" }
                return@thread
            }
            val stagedUri = Uri.fromFile(staged)

            val transferId = if (vault != null) {
                // Vaults are flat — vw_vault_upload_file's file_id==0 mode
                // only ever creates a direct child of the vault's own
                // folder, no nested subfolder concept, so there's no
                // NewInFolder analogue to branch on here the way the
                // plaintext path does.
                TransferManager.vaultUploadFile(applicationContext, client, vault, stagedUri, 0L, name, name, size)
            } else {
                TransferManager.uploadFile(applicationContext, client, stagedUri, target!!, name, size)
            }
            runOnUiThread { awaitAndRefresh(transferId, "Upload", stagedFile = staged) }
        }
    }

    /** Registers a one-shot [TransferListener] that updates [statusText]
     * as the transfer progresses and refreshes the current folder listing
     * once it completes successfully.
     *
     * [releaseUri] (paired with [releaseFlags], matching whichever grant
     * [createDocument] took for a download destination) is released once
     * the transfer finishes, succeeded or not — a persisted grant is only
     * needed long enough to survive to the background transfer job
     * actually running, not forever; Android caps an app at 128 persisted
     * grants total, and every picked document accumulates one otherwise.
     *
     * [stagedFile] (an [uploadFile] source staged into [cacheDir] —
     * TASK-246) is deleted once the transfer finishes, succeeded or not —
     * it was only ever needed for the duration of this one transfer. */
    private fun awaitAndRefresh(
        transferId: String,
        label: String,
        releaseUri: Uri? = null,
        releaseFlags: Int = 0,
        stagedFile: File? = null,
    ) {
        lateinit var listener: TransferListener
        listener = object : TransferListener {
            override fun onProgress(id: String, itemLabel: String, bytesDone: Long, bytesTotal: Long) {
                if (id != transferId) return
                runOnUiThread { statusText.text = "$label $itemLabel: $bytesDone / $bytesTotal bytes" }
            }
            override fun onComplete(id: String, succeeded: Boolean) {
                if (id != transferId) return
                TransferBus.unregister(listener)
                if (releaseUri != null) {
                    try {
                        contentResolver.releasePersistableUriPermission(releaseUri, releaseFlags)
                    } catch (_: SecurityException) {
                        // Nothing to release (e.g. the provider never
                        // actually persisted the grant) — harmless.
                    }
                }
                stagedFile?.delete()
                runOnUiThread {
                    statusText.text = if (succeeded) "$label complete" else "$label failed"
                    if (succeeded) loadCurrentFolder()
                }
            }
        }
        TransferBus.register(listener)
    }

    private fun promptShare(entry: FileEntry) {
        val view = layoutInflater.inflate(R.layout.dialog_share, null)
        val usernameField = view.findViewById<EditText>(R.id.shareUsernameField)
        val permGroup = view.findViewById<RadioGroup>(R.id.sharePermissionGroup)
        val expiryField = view.findViewById<EditText>(R.id.shareExpiryField)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_share)
            .setView(view)
            .setPositiveButton(R.string.action_share) { _, _ ->
                val username = usernameField.text.toString().trim()
                if (username.isEmpty()) return@setPositiveButton
                val permission = if (permGroup.checkedRadioButtonId == R.id.sharePermEdit) 2 else 1
                val expiresAt = expiryDaysToUnix(expiryField.text.toString().trim())
                statusText.text = getString(R.string.status_working)
                thread {
                    val shareId = client.shareGrant(entry.fileId, username, permission, expiresAt)
                    val lastError = if (shareId == 0L) VwClient.lastError() else 0
                    runOnUiThread {
                        statusText.text = if (shareId != 0L) "Shared with $username"
                                           else "Share failed: vw_err_t=$lastError"
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun promptGetLink(entry: FileEntry) {
        val view = layoutInflater.inflate(R.layout.dialog_link, null)
        val permGroup = view.findViewById<RadioGroup>(R.id.linkPermissionGroup)
        val passwordField = view.findViewById<EditText>(R.id.linkPasswordField)
        val expiryField = view.findViewById<EditText>(R.id.linkExpiryField)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_get_link)
            .setView(view)
            .setPositiveButton(R.string.action_get_link) { _, _ ->
                val permission = if (permGroup.checkedRadioButtonId == R.id.linkPermEdit) 2 else 1
                val password = passwordField.text.toString()
                val expiresAt = expiryDaysToUnix(expiryField.text.toString().trim())
                statusText.text = getString(R.string.status_working)
                thread {
                    val result = client.linkCreate(entry.fileId, permission, expiresAt, password)
                    val lastError = if (result == null) VwClient.lastError() else 0
                    runOnUiThread {
                        if (result == null) {
                            statusText.text = "Get link failed: vw_err_t=$lastError"
                            return@runOnUiThread
                        }
                        statusText.text = ""
                        val tokenHex = result.token.joinToString("") { "%02x".format(it) }
                        AlertDialog.Builder(this)
                            .setTitle(R.string.action_get_link)
                            .setMessage(getString(R.string.status_link_created, tokenHex))
                            .setPositiveButton(android.R.string.ok, null)
                            .show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Blank/zero/negative input means "never expires" (0, matching the
     * wire's own expires_at=0 convention) — never a validation error, this
     * is the common case for a share/link. */
    private fun expiryDaysToUnix(daysStr: String): Long {
        val days = daysStr.toLongOrNull() ?: return 0L
        if (days <= 0) return 0L
        return System.currentTimeMillis() / 1000L + days * 86400L
    }

    private fun promptRename(entry: FileEntry) {
        val input = EditText(this).apply { setText(entry.name) }
        AlertDialog.Builder(this)
            .setTitle(R.string.action_rename)
            .setView(input)
            .setPositiveButton(R.string.action_rename) { _, _ ->
                val newName = input.text.toString().trim()
                if (newName.isEmpty()) return@setPositiveButton
                statusText.text = getString(R.string.status_working)
                thread {
                    val err = client.moveFile(entry.fileId, currentDirId(), newName)
                    runOnUiThread {
                        statusText.text = if (err == 0) "Renamed" else "Rename failed: vw_err_t=$err"
                        if (err == 0) loadCurrentFolder()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun promptMove(entry: FileEntry) {
        val input = EditText(this).apply { hint = "Destination folder path, e.g. /archive" }
        AlertDialog.Builder(this)
            .setTitle(R.string.action_move)
            .setView(input)
            .setPositiveButton(R.string.action_move) { _, _ ->
                val destPath = input.text.toString().trim()
                if (destPath.isEmpty()) return@setPositiveButton
                statusText.text = getString(R.string.status_working)
                thread {
                    val destEntry = client.stat(destPath)
                    if (destEntry == null || destEntry.entryType != 1) {
                        runOnUiThread { statusText.text = "Move failed: destination is not a folder" }
                        return@thread
                    }
                    val err = client.moveFile(entry.fileId, destEntry.fileId)
                    runOnUiThread {
                        statusText.text = if (err == 0) "Moved" else "Move failed: vw_err_t=$err"
                        if (err == 0) loadCurrentFolder()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDelete(entry: FileEntry) {
        AlertDialog.Builder(this)
            .setTitle("Delete ${entry.name}?")
            .setPositiveButton(R.string.action_delete) { _, _ ->
                statusText.text = getString(R.string.status_working)
                thread {
                    val err = client.deleteFileById(entry.fileId)
                    runOnUiThread {
                        statusText.text = if (err == 0) "Deleted" else "Delete failed: vw_err_t=$err"
                        if (err == 0) loadCurrentFolder()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun promptNewFolder() {
        val input = EditText(this)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_new_folder)
            .setView(input)
            .setPositiveButton(R.string.action_new_folder) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isEmpty()) return@setPositiveButton
                statusText.text = getString(R.string.status_working)
                thread {
                    val newId = client.mkdir(currentDirId(), name)
                    val lastError = if (newId == 0L) VwClient.lastError() else 0
                    runOnUiThread {
                        if (newId != 0L) {
                            loadCurrentFolder()
                        } else {
                            statusText.text = "mkdir failed: vw_err_t=$lastError"
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun queryDisplayName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) return c.getString(idx)
            }
        }
        return null
    }

    private fun querySize(uri: Uri): Long? {
        contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val idx = c.getColumnIndex(OpenableColumns.SIZE)
                if (idx >= 0 && !c.isNull(idx)) return c.getLong(idx)
            }
        }
        return null
    }
}
