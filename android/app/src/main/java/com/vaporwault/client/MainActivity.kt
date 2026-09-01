package com.vaporwault.client

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

/**
 * TASK-225 toolchain smoke test — not real UI (that's TASK-229's job).
 * Connects+logs in against a host/port typed in by hand and reports
 * success/failure, to prove Gradle -> NDK -> CMake -> mbedTLS/Argon2
 * FetchContent -> JNI -> Kotlin works end-to-end before building the real
 * bridge surface and UI on top of it.
 */
class MainActivity : AppCompatActivity() {

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
                val handle = VwNative.nativeConnect(host, port, "", user, pass)
                val message = if (handle != 0L) {
                    VwNative.nativeLogout(handle)
                    "Connected and logged in successfully (session closed)."
                } else {
                    "Failed: vw_err_t = ${VwNative.nativeLastError()}"
                }
                runOnUiThread { resultText.text = message }
            }
        }
    }
}
