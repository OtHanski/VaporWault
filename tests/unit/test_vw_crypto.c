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
 *
 * NOTE: The argon2id tests are slow (~3–8 seconds, per VW_ARGON2_MEM_KB).
 * This is expected; correctness takes priority over speed for hashing tests.
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
