package com.vaporwault.client.accounts

import android.content.Context
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Properties
import java.util.UUID

/**
 * One profile's session/login tokens, decrypted. [loginToken] is
 * SHA-256(password) — never the raw password — used to reconnect via
 * [com.vaporwault.client.VwClient.connectWithHash] without re-prompting
 * when [com.vaporwault.client.VwClient.resume] fails (typically the
 * session token's natural expiry).
 */
data class Credentials(val sessionToken: ByteArray, val loginToken: ByteArray, val expiresAt: Long)

/**
 * Persists [Profile] metadata (plaintext — host/username are already
 * known to the user, nothing sensitive there) and per-profile
 * [Credentials] (AndroidKeyStore-encrypted via [VwSecureStore]) as one
 * file pair per profile, under a private app directory. One file pair per
 * profile rather than a single combined index, so writing one profile's
 * credentials can never corrupt or touch another's.
 */
class ProfileStore(context: Context) {
    private val secureStore = VwSecureStore()
    private val dir: File = File(context.filesDir, "profiles").apply { mkdirs() }

    private fun metaFile(id: String) = File(dir, "$id.properties")
    private fun credFile(id: String) = File(dir, "$id.cred")

    fun list(): List<Profile> =
        dir.listFiles { f -> f.name.endsWith(".properties") }
            ?.mapNotNull { readProfile(it.nameWithoutExtension) }
            ?: emptyList()

    fun get(id: String): Profile? = readProfile(id)

    private fun readProfile(id: String): Profile? {
        val file = metaFile(id)
        if (!file.exists()) return null
        val props = Properties().apply { file.inputStream().use { load(it) } }
        return Profile(
            id = id,
            label = props.getProperty("label") ?: return null,
            host = props.getProperty("host") ?: return null,
            port = props.getProperty("port")?.toIntOrNull() ?: return null,
            caCertPemPath = props.getProperty("caCertPemPath") ?: "",
            username = props.getProperty("username") ?: return null,
        )
    }

    /** Creates a new profile (a fresh random id) and persists it with its
     * initial credentials. Writes the credentials file before the
     * metadata file deliberately: [list] only discovers profiles by
     * scanning `.properties` files, so if the process dies between the
     * two writes, the leftover is an orphan `.cred` file with no
     * `.properties` counterpart — invisible to [list], not a permanently
     * broken "ghost" profile a user would otherwise see and be unable to
     * resume. */
    fun create(
        label: String,
        host: String,
        port: Int,
        caCertPemPath: String,
        username: String,
        sessionToken: ByteArray,
        loginToken: ByteArray,
        expiresAt: Long,
    ): Profile {
        val profile = Profile(id = UUID.randomUUID().toString(), label, host, port, caCertPemPath, username)
        writeCredentials(profile.id, sessionToken, loginToken, expiresAt)
        writeProfile(profile)
        return profile
    }

    private fun writeProfile(profile: Profile) {
        val props = Properties().apply {
            setProperty("label", profile.label)
            setProperty("host", profile.host)
            setProperty("port", profile.port.toString())
            setProperty("caCertPemPath", profile.caCertPemPath)
            setProperty("username", profile.username)
        }
        metaFile(profile.id).outputStream().use { props.store(it, null) }
    }

    /** Overwrites the stored credentials for [id]. Call this after every
     * successful resume/reconnect, not just on creation — SESSION_RESUME
     * issues a fresh single-use replacement token each time it succeeds
     * (PROTOCOL.md §7.1), so the previous one is no longer valid. */
    fun writeCredentials(id: String, sessionToken: ByteArray, loginToken: ByteArray, expiresAt: Long) {
        val plain = ByteBuffer.allocate(32 + 32 + 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(sessionToken)
            .put(loginToken)
            .putLong(expiresAt)
            .array()
        val encrypted = secureStore.encrypt(plain)
        secureZero(plain)
        credFile(id).writeBytes(encrypted)
    }

    fun readCredentials(id: String): Credentials? {
        val file = credFile(id)
        if (!file.exists()) return null
        val plain = secureStore.decrypt(file.readBytes())
        val buf = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN)
        val sessionToken = ByteArray(32).also { buf.get(it) }
        val loginToken = ByteArray(32).also { buf.get(it) }
        val expiresAt = buf.long
        secureZero(plain)
        return Credentials(sessionToken, loginToken, expiresAt)
    }

    fun remove(id: String) {
        metaFile(id).delete()
        credFile(id).delete()
    }
}
