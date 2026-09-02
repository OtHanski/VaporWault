package com.vaporwault.client.accounts

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Raw AndroidKeyStore-backed AES-256-GCM encrypt/decrypt of small blobs —
 * no wrapper library (TASK-227: deliberately not androidx.security-crypto's
 * `EncryptedSharedPreferences`, deprecated in 2025 in favor of a heavier
 * Tink+DataStore combo; see ARCHITECTURE.md's Architectural Decisions
 * table for the full "why raw AndroidKeyStore" rationale).
 *
 * The AES key never leaves the AndroidKeyStore — hardware-backed via
 * StrongBox where the device has one, the TEE otherwise — and is
 * generated once, on first use. [getOrCreateKey] always checks for an
 * existing key before generating: regenerating it would make every
 * previously-encrypted blob permanently undecryptable.
 */
class VwSecureStore {
    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "vw_master_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }

    private fun buildKeySpec(strongBox: Boolean): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
        // setIsStrongBoxBacked() doesn't exist on the Builder class at all
        // before API 28 (our minSdk is 26) — calling it unconditionally
        // would throw NoSuchMethodError on those devices, not just silently
        // no-op, so this must stay behind the explicit SDK_INT gate.
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        return builder.build()
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                keyGenerator.init(buildKeySpec(strongBox = true))
                return keyGenerator.generateKey().also(::logHardwareBacking)
            } catch (e: StrongBoxUnavailableException) {
                // Not every device has a StrongBox module — fall through
                // to a TEE-backed (still hardware-backed) key below.
            }
        }
        keyGenerator.init(buildKeySpec(strongBox = false))
        return keyGenerator.generateKey().also(::logHardwareBacking)
    }

    /**
     * TASK-227's acceptance criteria calls out "behavior when hardware
     * backing is unavailable" as something to actually check, not just
     * assume — the vast majority of real devices back an AndroidKeyStore
     * key with at least the TEE even without StrongBox, but a small
     * minority (old/low-end/misconfigured OEM builds) fall back to a
     * software-only Keymaster implementation with no hardware guarantee
     * at all. There's no user-facing toggle to reject that case — the app
     * still has to function — so this only logs a warning (once, at key
     * creation) rather than failing, but at least makes the gap
     * observable instead of silent.
     */
    @Suppress("DEPRECATION") // KeyInfo.isInsideSecureHardware: the only API available
    // below API 31 (our minSdk is 26) — getSecurityLevel() replaced it in API 31,
    // giving a finer-grained result (STRONGBOX/TEE/SOFTWARE/UNKNOWN) that's worth
    // using once available, but the boolean is still accurate on older devices.
    private fun logHardwareBacking(key: SecretKey) {
        try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEY_STORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            val hardwareBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE &&
                    info.securityLevel != KeyProperties.SECURITY_LEVEL_UNKNOWN
            } else {
                info.isInsideSecureHardware
            }
            if (!hardwareBacked) {
                Log.w("VwSecureStore", "AndroidKeyStore key is NOT hardware-backed on this device")
            }
        } catch (e: Exception) {
            Log.w("VwSecureStore", "could not determine key hardware-backing status", e)
        }
    }

    /** Encrypts [plaintext]. The returned blob is self-describing (a
     * length-prefixed IV, then ciphertext+tag) — nothing else needs to be
     * stored alongside it to [decrypt] later. */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return ByteBuffer.allocate(4 + iv.size + ciphertext.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(iv.size)
            .put(iv)
            .put(ciphertext)
            .array()
    }

    /** Throws (does not return null) on tampered/corrupt input — GCM
     * authentication failure surfaces as [javax.crypto.AEADBadTagException],
     * matching javax.crypto's own convention rather than inventing a
     * separate error signal for it. */
    fun decrypt(blob: ByteArray): ByteArray {
        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        val ivLen = buf.int
        val iv = ByteArray(ivLen).also { buf.get(it) }
        val ciphertext = ByteArray(blob.size - 4 - ivLen).also { buf.get(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}

/**
 * Best-effort zeroing. The JVM offers no zeroing guarantee as strong as
 * the native side's `vw_crypto_secure_zero` (a volatile function pointer
 * defeats compiler dead-store elimination in C; the JIT can still in
 * principle do the same to a plain array-fill loop, and a `ByteArray`'s
 * backing memory may already have been copied by the garbage collector
 * before this ever runs) — but overwriting still shrinks the window a
 * secret sits in memory, which is strictly better than doing nothing, and
 * matches the same secret-hygiene intent as the C side (STYLE.md §15).
 */
fun secureZero(bytes: ByteArray) {
    bytes.fill(0)
}
