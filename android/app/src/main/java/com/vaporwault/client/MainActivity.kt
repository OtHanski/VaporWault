package com.vaporwault.client

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.vaporwault.client.accounts.VwAccountRegistry
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.concurrent.thread

/**
 * TASK-225/226/227 toolchain + bridge-surface + account-registry smoke
 * test — not real UI (that's TASK-229's job).
 *
 * - CONNECT: the round trip TASK-226's acceptance criteria calls for (list
 *   a directory, upload+commit a file, download it back, share it, revoke
 *   it) against a real vapourwaultd, reporting a step-by-step pass/fail
 *   summary. Sharing needs a second, already-existing account on the test
 *   server to grant to — hardcoded below as "androidtest2"; the connecting
 *   account (whatever is typed into the form) is the grantor.
 * - ADD PROFILE: exercises TASK-227's [VwAccountRegistry.addProfile] with
 *   the typed-in fields, then reads the resulting `.cred` file's raw bytes
 *   directly to confirm the session token is nowhere in it in the clear.
 * - RESUME PROFILES: exercises [VwAccountRegistry.resume] for every saved
 *   profile without touching the password fields at all — this is the
 *   "restart the app" scenario; run it after a real `adb shell am
 *   force-stop` + relaunch, not just within the same process, to actually
 *   prove the AndroidKeyStore-wrapped credentials survive a real restart.
 */
class MainActivity : AppCompatActivity() {

    private val shareTargetUsername = "androidtest2"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hostField = findViewById<EditText>(R.id.hostField)
        val portField = findViewById<EditText>(R.id.portField)
        val userField = findViewById<EditText>(R.id.userField)
        val passField = findViewById<EditText>(R.id.passField)
        val resultText = findViewById<TextView>(R.id.resultText)
        val connectButton = findViewById<Button>(R.id.connectButton)
        val addProfileButton = findViewById<Button>(R.id.addProfileButton)
        val resumeProfilesButton = findViewById<Button>(R.id.resumeProfilesButton)

        connectButton.setOnClickListener {
            val host = hostField.text.toString()
            val port = portField.text.toString().toIntOrNull() ?: 0
            val user = userField.text.toString()
            val pass = passField.text.toString().toByteArray(Charsets.UTF_8)

            resultText.text = "Connecting..."
            runAsync(resultText) { runRoundTrip(host, port, user, pass) }
        }

        addProfileButton.setOnClickListener {
            val host = hostField.text.toString()
            val port = portField.text.toString().toIntOrNull() ?: 0
            val user = userField.text.toString()
            val pass = passField.text.toString().toByteArray(Charsets.UTF_8)

            resultText.text = "Adding profile..."
            runAsync(resultText) { runAddProfile(host, port, user, pass) }
        }

        resumeProfilesButton.setOnClickListener {
            resultText.text = "Resuming profiles..."
            runAsync(resultText) { runResumeAllProfiles() }
        }
    }

    private fun runAsync(resultText: TextView, block: () -> String) {
        thread {
            val message = try {
                block()
            } catch (e: Exception) {
                e.printStackTrace()
                "Exception: ${e.message}"
            }
            runOnUiThread { resultText.text = message }
        }
    }

    private fun runAddProfile(host: String, port: Int, user: String, pass: ByteArray): String {
        val registry = VwAccountRegistry(applicationContext)
        val (profile, client) = registry.addProfile(label = user, host, port, user, pass)
            ?: return "addProfile FAILED: vw_err_t=${VwClient.lastError()}"

        val sessionToken = client.token()
        client.close()

        // TASK-227 acceptance criterion: credentials are never stored in
        // plaintext anywhere on disk. Read the raw .cred file bytes
        // directly and confirm the session token isn't in there verbatim.
        val credFile = File(File(applicationContext.filesDir, "profiles"), "${profile.id}.cred")
        val rawBytes = credFile.readBytes()
        val containsPlaintextToken = rawBytes.indexOfSubarray(sessionToken) >= 0

        return if (containsPlaintextToken) {
            "addProfile FAILED: session token found in cleartext in ${credFile.name}!"
        } else {
            "addProfile ok (profile_id=${profile.id}, user=$user)\n" +
                "cred file is ${rawBytes.size} bytes, session token not found in cleartext\n" +
                "stored profiles: ${registry.listProfiles().size}"
        }
    }

    private fun runResumeAllProfiles(): String {
        val registry = VwAccountRegistry(applicationContext)
        val profiles = registry.listProfiles()
        if (profiles.isEmpty()) return "no stored profiles — tap ADD PROFILE first"

        val results = profiles.joinToString("\n") { profile ->
            val client = registry.resume(profile.id)
            if (client == null) {
                "${profile.username}: FAILED vw_err_t=${VwClient.lastError()}"
            } else {
                val userId = client.userId()
                client.close()
                "${profile.username}: resumed ok (user_id=$userId), no password used"
            }
        }
        return "RESUME RESULTS (${profiles.size} profile(s)):\n$results"
    }

    /** Naive subarray search — these blobs are a few dozen bytes, no need
     * for anything fancier. */
    private fun ByteArray.indexOfSubarray(needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > size) return -1
        outer@ for (start in 0..(size - needle.size)) {
            for (i in needle.indices) {
                if (this[start + i] != needle[i]) continue@outer
            }
            return start
        }
        return -1
    }

    private fun runRoundTrip(host: String, port: Int, user: String, pass: ByteArray): String {
        val client = VwClient.connect(host, port, user, pass)
            ?: return "connect failed: vw_err_t=${VwClient.lastError()}"
        try {
            val steps = StringBuilder()
            steps.append("connect ok (user_id=${client.userId()})\n")

            val folderName = "android_test_${System.currentTimeMillis()}"
            val dirId = client.mkdir(0, folderName)
            if (dirId == 0L) return steps.append("mkdir FAILED: vw_err_t=${VwClient.lastError()}").toString()
            steps.append("mkdir ok (dir_id=$dirId)\n")

            val content = "vaporwault android round-trip test".toByteArray(Charsets.UTF_8)
            val hash = MessageDigest.getInstance("SHA-256").digest(content)
            val uploadBuf = ByteBuffer.allocateDirect(content.size).put(content).apply { flip() }
            val uploadErr = client.chunkUploadIfMissing(hash, uploadBuf, content.size)
            if (uploadErr != 0) return steps.append("chunk upload FAILED: vw_err_t=$uploadErr").toString()
            steps.append("chunk upload ok\n")

            val commit = client.createFileInFolder(dirId, "test.txt", content.size.toLong(), hash)
                ?: return steps.append("commit FAILED: vw_err_t=${VwClient.lastError()}").toString()
            steps.append("commit ok (file_id=${commit.fileId}, version_id=${commit.versionId})\n")

            val listed = client.listFilesById(dirId, recursive = false)
                ?: return steps.append("list FAILED: vw_err_t=${VwClient.lastError()}").toString()
            if (listed.none { e -> e.fileId == commit.fileId })
                return steps.append("list FAILED: uploaded file missing from listing").toString()
            steps.append("list ok (${listed.size} entries)\n")

            val chunks = client.versionChunks(commit.versionId)
                ?: return steps.append("versionChunks FAILED: vw_err_t=${VwClient.lastError()}").toString()
            if (chunks.chunkCount != 1)
                return steps.append("versionChunks FAILED: expected 1 chunk, got ${chunks.chunkCount}").toString()
            steps.append("versionChunks ok\n")

            val downloadBuf = ByteBuffer.allocateDirect(content.size)
            val downloadedLen = client.chunkDownload(hash, downloadBuf, content.size)
            if (downloadedLen != content.size)
                return steps.append("chunk download FAILED: vw_err_t=${VwClient.lastError()}").toString()
            // Native writes via GetDirectBufferAddress (the raw base address) and
            // never touches this buffer's position/limit — no flip() needed
            // (there is no "written region" for it to flip *to*, unlike after a
            // Kotlin-side put()). Read from position 0 directly.
            val downloaded = ByteArray(downloadedLen).also { downloadBuf.get(it) }
            if (!downloaded.contentEquals(content))
                return steps.append("chunk download FAILED: content mismatch").toString()
            steps.append("chunk download ok, content matches\n")

            val shareId = client.shareGrant(commit.fileId, shareTargetUsername, permission = 1 /* VIEW */)
            if (shareId == 0L) return steps.append("share grant FAILED: vw_err_t=${VwClient.lastError()}").toString()
            steps.append("share grant ok (share_id=$shareId)\n")

            val revokeErr = client.shareRevoke(shareId)
            if (revokeErr != 0) return steps.append("share revoke FAILED: vw_err_t=$revokeErr").toString()
            steps.append("share revoke ok\n")

            return "ALL PASS\n$steps"
        } finally {
            client.close()
        }
    }
}
