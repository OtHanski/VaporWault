package com.vaporwault.client

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.concurrent.thread

/**
 * TASK-225/226 toolchain + bridge-surface smoke test — not real UI (that's
 * TASK-229's job). Connects, then exercises the round trip TASK-226's
 * acceptance criteria calls for (list a directory, upload+commit a file,
 * download it back, share it, revoke it) against a real vapourwaultd,
 * reporting a step-by-step pass/fail summary.
 *
 * Sharing needs a second, already-existing account on the test server to
 * grant to — hardcoded below as "androidtest2"; the connecting account
 * (whatever is typed into the form) is the grantor.
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

        connectButton.setOnClickListener {
            val host = hostField.text.toString()
            val port = portField.text.toString().toIntOrNull() ?: 0
            val user = userField.text.toString()
            val pass = passField.text.toString().toByteArray(Charsets.UTF_8)

            resultText.text = "Connecting..."
            thread {
                // Test-only: empty CA path disables cert verification
                // (VW_CERT_VERIFY_NONE). Never do this outside a local
                // smoke test against tests/integration/gen_test_cert.sh.
                val message = try {
                    runRoundTrip(host, port, user, pass)
                } catch (e: Exception) {
                    e.printStackTrace()
                    "Exception: ${e.message}"
                }
                runOnUiThread { resultText.text = message }
            }
        }
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
