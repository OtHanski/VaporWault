/*
 * test_vw_crypto.c — unit tests for vw_crypto.
 *
 * Tests:
 *   CRC32 known-vector: ISO 3309 check value for "123456789" = 0xCBF43926
 *   CRC32 incremental: crc32(AB) == crc32_update(crc32(A), B)
 *   CSPRNG: output non-zero, successive calls differ
 *   Argon2id: generate-salt path, verify pass, verify fail
 *   Argon2id: caller-provided salt with NULL out_salt (null-deref regression)
 *   HMAC-SHA256: RFC 4231 test case 1 known-answer vector
 *   Hex encode/decode: round-trip
 *   Vault Argon2id KDF (TASK-099): floor enforcement, determinism
 *   AES-256-GCM (TASK-099): round-trip, tamper detection (tag/ct/key/AAD)
 *   Vault chunk nonce (TASK-099): determinism, retry-safety under GCM
 *
 * NOTE: The argon2id tests are slow (~3–8 seconds, per VW_ARGON2_MEM_KB /
 * VW_VAULT_ARGON2_MIN_MEM_KB). This is expected; correctness takes
 * priority over speed for hashing tests.
 */

#include "vw_test.h"
#include "vw_crypto.h"
#include <string.h>
#include <stdlib.h>

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int all_zero(const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (buf[i] != 0) return 0;
    return 1;
}

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_crypto") {

    VW_ASSERT_OK(vw_crypto_init());

    /* ── CRC32 ─────────────────────────────────────────────────────────── */

    VW_TEST_CASE("CRC32 ISO 3309 known-vector") {
        /* Standard check value: CRC32("123456789") = 0xCBF43926 */
        const uint8_t msg[] = "123456789";
        uint32_t crc = vw_crypto_crc32(msg, 9);
        VW_ASSERT_EQ(crc, (uint32_t)0xCBF43926u);
    }

    VW_TEST_CASE("CRC32 empty string") {
        uint32_t crc = vw_crypto_crc32(NULL, 0);
        VW_ASSERT_EQ(crc, (uint32_t)0u);
    }

    VW_TEST_CASE("CRC32 incremental == one-shot") {
        const char part_a[] = "Hello, ";
        const char part_b[] = "world!";
        uint32_t one_shot = vw_crypto_crc32("Hello, world!", 13);
        uint32_t incr = vw_crypto_crc32_update(0, part_a, 7);
        incr = vw_crypto_crc32_update(incr, part_b, 6);
        VW_ASSERT_EQ(one_shot, incr);
    }

    VW_TEST_CASE("CRC32 distinct inputs give distinct CRCs") {
        uint32_t a = vw_crypto_crc32("foo", 3);
        uint32_t b = vw_crypto_crc32("bar", 3);
        VW_ASSERT_NE(a, b);
    }

    /* ── CSPRNG ────────────────────────────────────────────────────────── */

    VW_TEST_CASE("CSPRNG output is non-zero (birthday-safe: p(fail) < 2^-64)") {
        uint8_t buf[8] = {0};
        VW_ASSERT_OK(vw_crypto_random(buf, sizeof(buf)));
        VW_ASSERT(!all_zero(buf, sizeof(buf)));
    }

    VW_TEST_CASE("CSPRNG successive calls produce different output") {
        uint8_t a[16] = {0}, b[16] = {0};
        VW_ASSERT_OK(vw_crypto_random(a, sizeof(a)));
        VW_ASSERT_OK(vw_crypto_random(b, sizeof(b)));
        VW_ASSERT(memcmp(a, b, sizeof(a)) != 0);
    }

    /* ── Argon2id ──────────────────────────────────────────────────────── */

    VW_TEST_CASE("Argon2id generate-salt path: hash and salt non-zero") {
        uint8_t salt[VW_ARGON2_SALT_BYTES] = {0};
        uint8_t hash[VW_ARGON2_HASH_BYTES] = {0};
        VW_ASSERT_OK(vw_crypto_argon2id_hash("password", 8, NULL, salt, hash));
        VW_ASSERT(!all_zero(salt, VW_ARGON2_SALT_BYTES));
        VW_ASSERT(!all_zero(hash, VW_ARGON2_HASH_BYTES));
    }

    VW_TEST_CASE("Argon2id verify: correct password passes") {
        uint8_t salt[VW_ARGON2_SALT_BYTES] = {0};
        uint8_t hash[VW_ARGON2_HASH_BYTES] = {0};
        VW_ASSERT_OK(vw_crypto_argon2id_hash("secret", 6, NULL, salt, hash));
        VW_ASSERT_OK(vw_crypto_argon2id_verify(hash, salt, "secret", 6));
    }

    VW_TEST_CASE("Argon2id verify: wrong password fails with VW_ERR_AUTH_BAD_CREDS") {
        uint8_t salt[VW_ARGON2_SALT_BYTES] = {0};
        uint8_t hash[VW_ARGON2_HASH_BYTES] = {0};
        VW_ASSERT_OK(vw_crypto_argon2id_hash("correct", 7, NULL, salt, hash));
        VW_ASSERT_ERR(vw_crypto_argon2id_verify(hash, salt, "wrong", 5),
                      VW_ERR_AUTH_BAD_CREDS);
    }

    VW_TEST_CASE("Argon2id caller-provided salt with NULL out_salt does not crash") {
        /* Regression test: null-deref bug when salt!=NULL and out_salt==NULL */
        uint8_t fixed_salt[VW_ARGON2_SALT_BYTES];
        uint8_t hash[VW_ARGON2_HASH_BYTES];
        memset(fixed_salt, 0xAB, VW_ARGON2_SALT_BYTES);
        VW_ASSERT_OK(vw_crypto_argon2id_hash("pw", 2, fixed_salt, NULL, hash));
        VW_ASSERT(!all_zero(hash, VW_ARGON2_HASH_BYTES));
    }

    VW_TEST_CASE("Argon2id same salt+password always gives same hash") {
        uint8_t fixed_salt[VW_ARGON2_SALT_BYTES];
        uint8_t hash_a[VW_ARGON2_HASH_BYTES];
        uint8_t hash_b[VW_ARGON2_HASH_BYTES];
        memset(fixed_salt, 0x11, VW_ARGON2_SALT_BYTES);
        VW_ASSERT_OK(vw_crypto_argon2id_hash("pw", 2, fixed_salt, NULL, hash_a));
        VW_ASSERT_OK(vw_crypto_argon2id_hash("pw", 2, fixed_salt, NULL, hash_b));
        VW_ASSERT_MEM_EQ(hash_a, hash_b, VW_ARGON2_HASH_BYTES);
    }

    /* ── Vault Argon2id KDF (TASK-099) ────────────────────────────────── */
    /* NOTE: mem_cost_kib is pinned at the SEC.07 floor (19456 KiB) in
     * every test below to keep runtime bounded — see the file header note
     * on Argon2id test speed. */

    VW_TEST_CASE("Vault KDF: valid params derive a non-zero KEK") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES];
        uint8_t kek[VW_VAULT_KEK_BYTES] = {0};
        memset(salt, 0x22, sizeof(salt));
        vw_vault_kdf_params_t p = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST, 1 };
        VW_ASSERT_OK(vw_crypto_vault_derive_kek("correct horse battery staple", 29, salt, &p, kek));
        VW_ASSERT(!all_zero(kek, VW_VAULT_KEK_BYTES));
    }

    VW_TEST_CASE("Vault KDF: same passphrase+salt+params always gives same KEK") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES];
        uint8_t kek_a[VW_VAULT_KEK_BYTES], kek_b[VW_VAULT_KEK_BYTES];
        memset(salt, 0x33, sizeof(salt));
        vw_vault_kdf_params_t p = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST, 1 };
        VW_ASSERT_OK(vw_crypto_vault_derive_kek("passphrase", 10, salt, &p, kek_a));
        VW_ASSERT_OK(vw_crypto_vault_derive_kek("passphrase", 10, salt, &p, kek_b));
        VW_ASSERT_MEM_EQ(kek_a, kek_b, VW_VAULT_KEK_BYTES);
    }

    VW_TEST_CASE("Vault KDF: different passphrase gives a different KEK") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES];
        uint8_t kek_a[VW_VAULT_KEK_BYTES], kek_b[VW_VAULT_KEK_BYTES];
        memset(salt, 0x44, sizeof(salt));
        vw_vault_kdf_params_t p = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST, 1 };
        VW_ASSERT_OK(vw_crypto_vault_derive_kek("passphrase-a", 12, salt, &p, kek_a));
        VW_ASSERT_OK(vw_crypto_vault_derive_kek("passphrase-b", 12, salt, &p, kek_b));
        VW_ASSERT(!vw_crypto_constant_time_eq(kek_a, kek_b, VW_VAULT_KEK_BYTES));
    }

    VW_TEST_CASE("Vault KDF: rejects mem_cost below the SEC.07 floor") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES] = {0};
        uint8_t kek[VW_VAULT_KEK_BYTES];
        vw_vault_kdf_params_t p = { VW_VAULT_ARGON2_MIN_MEM_KB - 1u, VW_VAULT_ARGON2_MIN_TIME_COST, 1 };
        VW_ASSERT_ERR(vw_crypto_vault_derive_kek("pw", 2, salt, &p, kek), VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("Vault KDF: rejects time_cost below the SEC.07 floor") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES] = {0};
        uint8_t kek[VW_VAULT_KEK_BYTES];
        vw_vault_kdf_params_t p = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST - 1u, 1 };
        VW_ASSERT_ERR(vw_crypto_vault_derive_kek("pw", 2, salt, &p, kek), VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("Vault KDF: rejects parallelism != 1 (both directions)") {
        uint8_t salt[VW_VAULT_KDF_SALT_BYTES] = {0};
        uint8_t kek[VW_VAULT_KEK_BYTES];
        vw_vault_kdf_params_t p_hi = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST, 4 };
        vw_vault_kdf_params_t p_lo = { VW_VAULT_ARGON2_MIN_MEM_KB, VW_VAULT_ARGON2_MIN_TIME_COST, 0 };
        VW_ASSERT_ERR(vw_crypto_vault_derive_kek("pw", 2, salt, &p_hi, kek), VW_ERR_INVALID_ARG);
        VW_ASSERT_ERR(vw_crypto_vault_derive_kek("pw", 2, salt, &p_lo, kek), VW_ERR_INVALID_ARG);
    }

    /* ── AES-256-GCM (TASK-099) ────────────────────────────────────────── */

    VW_TEST_CASE("AES-256-GCM: encrypt/decrypt round-trips byte-identical plaintext") {
        uint8_t key[VW_AES_GCM_KEY_BYTES], nonce[VW_AES_GCM_NONCE_BYTES];
        memset(key, 0x55, sizeof(key));
        memset(nonce, 0x66, sizeof(nonce));
        const char *pt = "the quick brown fox jumps over the lazy dog";
        size_t len = strlen(pt);
        uint8_t ct[64], tag[VW_AES_GCM_TAG_BYTES], out[64] = {0};

        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, NULL, 0, pt, len, ct, tag));
        VW_ASSERT_OK(vw_crypto_aes256gcm_decrypt(key, nonce, NULL, 0, ct, len, tag, out));
        VW_ASSERT_MEM_EQ(pt, out, len);
    }

    VW_TEST_CASE("AES-256-GCM: ciphertext differs from plaintext") {
        uint8_t key[VW_AES_GCM_KEY_BYTES], nonce[VW_AES_GCM_NONCE_BYTES];
        memset(key, 0x77, sizeof(key));
        memset(nonce, 0x88, sizeof(nonce));
        uint8_t pt[32], ct[32], tag[VW_AES_GCM_TAG_BYTES];
        memset(pt, 0xAA, sizeof(pt));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, NULL, 0, pt, sizeof(pt), ct, tag));
        VW_ASSERT(!vw_crypto_constant_time_eq(pt, ct, sizeof(pt)));
    }

    VW_TEST_CASE("AES-256-GCM: tampered tag fails auth and zeroes output") {
        uint8_t key[VW_AES_GCM_KEY_BYTES] = {0}, nonce[VW_AES_GCM_NONCE_BYTES] = {0};
        uint8_t pt[16], ct[16], tag[VW_AES_GCM_TAG_BYTES], out[16];
        memset(pt, 0x99, sizeof(pt));
        memset(out, 0xFF, sizeof(out));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, NULL, 0, pt, sizeof(pt), ct, tag));
        tag[0] ^= 0x01;
        VW_ASSERT_ERR(vw_crypto_aes256gcm_decrypt(key, nonce, NULL, 0, ct, sizeof(ct), tag, out),
                      VW_ERR_CRYPTO);
        VW_ASSERT(all_zero(out, sizeof(out)));
    }

    VW_TEST_CASE("AES-256-GCM: tampered ciphertext fails auth") {
        uint8_t key[VW_AES_GCM_KEY_BYTES] = {0}, nonce[VW_AES_GCM_NONCE_BYTES] = {0};
        uint8_t pt[16], ct[16], tag[VW_AES_GCM_TAG_BYTES], out[16];
        memset(pt, 0x21, sizeof(pt));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, NULL, 0, pt, sizeof(pt), ct, tag));
        ct[0] ^= 0x01;
        VW_ASSERT_ERR(vw_crypto_aes256gcm_decrypt(key, nonce, NULL, 0, ct, sizeof(ct), tag, out),
                      VW_ERR_CRYPTO);
    }

    VW_TEST_CASE("AES-256-GCM: wrong key fails auth") {
        uint8_t key[VW_AES_GCM_KEY_BYTES] = {0}, wrong_key[VW_AES_GCM_KEY_BYTES] = {0};
        uint8_t nonce[VW_AES_GCM_NONCE_BYTES] = {0};
        wrong_key[0] = 0x01;
        uint8_t pt[16], ct[16], tag[VW_AES_GCM_TAG_BYTES], out[16];
        memset(pt, 0x21, sizeof(pt));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, NULL, 0, pt, sizeof(pt), ct, tag));
        VW_ASSERT_ERR(vw_crypto_aes256gcm_decrypt(wrong_key, nonce, NULL, 0, ct, sizeof(ct), tag, out),
                      VW_ERR_CRYPTO);
    }

    VW_TEST_CASE("AES-256-GCM: mismatched AAD fails auth") {
        uint8_t key[VW_AES_GCM_KEY_BYTES] = {0}, nonce[VW_AES_GCM_NONCE_BYTES] = {0};
        uint8_t pt[16], ct[16], tag[VW_AES_GCM_TAG_BYTES], out[16];
        memset(pt, 0x21, sizeof(pt));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(key, nonce, "aad-a", 5, pt, sizeof(pt), ct, tag));
        VW_ASSERT_ERR(vw_crypto_aes256gcm_decrypt(key, nonce, "aad-b", 5, ct, sizeof(ct), tag, out),
                      VW_ERR_CRYPTO);
        VW_ASSERT_OK(vw_crypto_aes256gcm_decrypt(key, nonce, "aad-a", 5, ct, sizeof(ct), tag, out));
        VW_ASSERT_MEM_EQ(pt, out, sizeof(pt));
    }

    /* ── Vault chunk nonce derivation (TASK-099) ──────────────────────── */

    VW_TEST_CASE("Chunk nonce: deterministic for the same dek+index") {
        uint8_t dek[VW_AES_GCM_KEY_BYTES];
        memset(dek, 0xAB, sizeof(dek));
        uint8_t n1[VW_AES_GCM_NONCE_BYTES], n2[VW_AES_GCM_NONCE_BYTES];
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 7, n1));
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 7, n2));
        VW_ASSERT_MEM_EQ(n1, n2, VW_AES_GCM_NONCE_BYTES);
    }

    VW_TEST_CASE("Chunk nonce: differs across chunk indices for the same dek") {
        uint8_t dek[VW_AES_GCM_KEY_BYTES];
        memset(dek, 0xCD, sizeof(dek));
        uint8_t n0[VW_AES_GCM_NONCE_BYTES], n1[VW_AES_GCM_NONCE_BYTES];
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 0, n0));
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 1, n1));
        VW_ASSERT(!vw_crypto_constant_time_eq(n0, n1, VW_AES_GCM_NONCE_BYTES));
    }

    VW_TEST_CASE("Chunk nonce: differs across DEKs for the same index") {
        uint8_t dek_a[VW_AES_GCM_KEY_BYTES], dek_b[VW_AES_GCM_KEY_BYTES];
        memset(dek_a, 0x11, sizeof(dek_a));
        memset(dek_b, 0x12, sizeof(dek_b));
        uint8_t na[VW_AES_GCM_NONCE_BYTES], nb[VW_AES_GCM_NONCE_BYTES];
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek_a, 42, na));
        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek_b, 42, nb));
        VW_ASSERT(!vw_crypto_constant_time_eq(na, nb, VW_AES_GCM_NONCE_BYTES));
    }

    VW_TEST_CASE("Chunk nonce + GCM: same dek re-encrypting the same chunk index is retry-safe") {
        /* Simulates an interrupted-and-retried upload: encrypting the same
         * plaintext chunk twice with the same dek+chunk_index must derive
         * the same nonce and produce byte-identical ciphertext+tag —
         * never two different (nonce, ciphertext) pairs under one key,
         * which would be the GCM nonce-reuse-with-different-plaintext
         * failure mode this scheme exists to prevent. */
        uint8_t dek[VW_AES_GCM_KEY_BYTES];
        memset(dek, 0xEE, sizeof(dek));
        uint8_t pt[4096];
        memset(pt, 0x5A, sizeof(pt));

        uint8_t nonce1[VW_AES_GCM_NONCE_BYTES], nonce2[VW_AES_GCM_NONCE_BYTES];
        uint8_t ct1[4096], ct2[4096], tag1[VW_AES_GCM_TAG_BYTES], tag2[VW_AES_GCM_TAG_BYTES];

        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 3, nonce1));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(dek, nonce1, NULL, 0, pt, sizeof(pt), ct1, tag1));

        VW_ASSERT_OK(vw_crypto_vault_chunk_nonce(dek, 3, nonce2));
        VW_ASSERT_OK(vw_crypto_aes256gcm_encrypt(dek, nonce2, NULL, 0, pt, sizeof(pt), ct2, tag2));

        VW_ASSERT_MEM_EQ(nonce1, nonce2, VW_AES_GCM_NONCE_BYTES);
        VW_ASSERT_MEM_EQ(ct1, ct2, sizeof(ct1));
        VW_ASSERT_MEM_EQ(tag1, tag2, VW_AES_GCM_TAG_BYTES);
    }

    /* ── HMAC-SHA256 ───────────────────────────────────────────────────── */

    VW_TEST_CASE("HMAC-SHA256 RFC 4231 test case 1 known-answer") {
        /*
         * RFC 4231, Test Case 1:
         * Key  = 0x0b0b0b... (20 bytes of 0x0b)
         * Data = "Hi There"
         * Expected HMAC-SHA-256 =
         *   b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
         */
        static const uint8_t key[20] = {
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
        };
        static const uint8_t expected[32] = {
            0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
            0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
            0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
            0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
        };
        uint8_t mac[VW_HASH_BYTES] = {0};
        VW_ASSERT_OK(vw_crypto_hmac_sha256(key, sizeof(key), "Hi There", 8, mac));
        VW_ASSERT_MEM_EQ(mac, expected, VW_HASH_BYTES);
    }

    VW_TEST_CASE("HMAC-SHA256 different keys give different MACs") {
        uint8_t key_a[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        uint8_t key_b[8] = {0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8};
        uint8_t mac_a[VW_HASH_BYTES], mac_b[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_hmac_sha256(key_a, 8, "data", 4, mac_a));
        VW_ASSERT_OK(vw_crypto_hmac_sha256(key_b, 8, "data", 4, mac_b));
        VW_ASSERT(memcmp(mac_a, mac_b, VW_HASH_BYTES) != 0);
    }

    /* ── Hex encode / decode ───────────────────────────────────────────── */

    VW_TEST_CASE("Hex encode: known output") {
        static const uint8_t bytes[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        char hex[9];
        vw_crypto_hex_encode(bytes, 4, hex);
        VW_ASSERT_STR_EQ(hex, "deadbeef");
    }

    VW_TEST_CASE("Hex decode: known output") {
        uint8_t out[4] = {0};
        static const uint8_t expected[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        VW_ASSERT_OK(vw_crypto_hex_decode("deadbeef", 8, out));
        VW_ASSERT_MEM_EQ(out, expected, 4);
    }

    VW_TEST_CASE("Hex encode/decode round-trip") {
        uint8_t orig[16], decoded[16];
        char hex[33];
        VW_ASSERT_OK(vw_crypto_random(orig, 16));
        vw_crypto_hex_encode(orig, 16, hex);
        VW_ASSERT_OK(vw_crypto_hex_decode(hex, 32, decoded));
        VW_ASSERT_MEM_EQ(orig, decoded, 16);
    }

    VW_TEST_CASE("Hex decode: invalid character returns VW_ERR_INVALID_ARG") {
        uint8_t out[4];
        VW_ASSERT_ERR(vw_crypto_hex_decode("deadbXef", 8, out), VW_ERR_INVALID_ARG);
    }

    /* ── vw_crypto_constant_time_eq ───────────────────────────────────────── */

    VW_TEST_CASE("constant_time_eq: equal inputs are equal") {
        uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        VW_ASSERT(vw_crypto_constant_time_eq(a, b, 16));
    }

    VW_TEST_CASE("constant_time_eq: last-byte-differs is unequal") {
        uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,255};
        VW_ASSERT(!vw_crypto_constant_time_eq(a, b, 16));
    }

    VW_TEST_CASE("constant_time_eq: first-byte-differs is unequal") {
        uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t b[16] = {0,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        VW_ASSERT(!vw_crypto_constant_time_eq(a, b, 16));
    }

    VW_TEST_CASE("constant_time_eq: all-zero buffers are equal") {
        uint8_t z1[16] = {0};
        uint8_t z2[16] = {0};
        VW_ASSERT(vw_crypto_constant_time_eq(z1, z2, 16));
    }

    VW_TEST_CASE("constant_time_eq: zero-length comparison is equal") {
        uint8_t a[1] = {0xFF};
        uint8_t b[1] = {0x00};
        VW_ASSERT(vw_crypto_constant_time_eq(a, b, 0));
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
