#include "vw_crypto.h"

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#  include <unistd.h>
#endif

/* mbedTLS headers */
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* Argon2 reference implementation */
#include <argon2.h>

/* ── Cross-platform mutex ────────────────────────────────────────────────── */

#ifdef _WIN32
typedef CRITICAL_SECTION vw_mutex_t;
static void mutex_init(vw_mutex_t *m)    { InitializeCriticalSection(m); }
static void mutex_destroy(vw_mutex_t *m) { DeleteCriticalSection(m); }
static void mutex_lock(vw_mutex_t *m)    { EnterCriticalSection(m); }
static void mutex_unlock(vw_mutex_t *m)  { LeaveCriticalSection(m); }
#else
typedef pthread_mutex_t vw_mutex_t;
static void mutex_init(vw_mutex_t *m)    { pthread_mutex_init(m, NULL); }
static void mutex_destroy(vw_mutex_t *m) { pthread_mutex_destroy(m); }
static void mutex_lock(vw_mutex_t *m)    { pthread_mutex_lock(m); }
static void mutex_unlock(vw_mutex_t *m)  { pthread_mutex_unlock(m); }
#endif

/* ── CRC-32 (ISO 3309, polynomial 0xEDB88320) ───────────────────────────── */

static uint32_t g_crc32_table[256];

static void crc32_build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ ((c & 1u) ? 0xEDB88320u : 0u);
        g_crc32_table[i] = c;
    }
}

#ifdef _WIN32
static INIT_ONCE g_crc32_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK crc32_once_cb(PINIT_ONCE o, PVOID p, PVOID *ctx) {
    (void)o; (void)p; (void)ctx;
    crc32_build_table();
    return TRUE;
}
static void crc32_ensure_init(void) {
    InitOnceExecuteOnce(&g_crc32_once, crc32_once_cb, NULL, NULL);
}
#else
static pthread_once_t g_crc32_once = PTHREAD_ONCE_INIT;
static void crc32_ensure_init(void) {
    pthread_once(&g_crc32_once, crc32_build_table);
}
#endif

uint32_t vw_crypto_crc32_update(uint32_t prev_crc, const void *data, size_t len) {
    crc32_ensure_init();
    const uint8_t *p = (const uint8_t *)data;
    uint32_t c = prev_crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = (c >> 8) ^ g_crc32_table[(c ^ p[i]) & 0xFFu];
    return c ^ 0xFFFFFFFFu;
}

uint32_t vw_crypto_crc32(const void *data, size_t len) {
    return vw_crypto_crc32_update(0, data, len);
}

/* ── Module state ────────────────────────────────────────────────────────── */

static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static vw_mutex_t               g_rng_mu;    /* protects g_ctr_drbg */
static int                      g_initialized = 0;

/* ── Init / cleanup ──────────────────────────────────────────────────────── */

vw_err_t vw_crypto_init(void) {
    if (g_initialized) return VW_OK;

    mutex_init(&g_rng_mu);
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    static const unsigned char pers[] = "vapourwault_ctr_drbg_v1";
    int rc = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
                                    &g_entropy, pers, sizeof(pers) - 1);
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        mutex_destroy(&g_rng_mu);
        return VW_ERR_CRYPTO;
    }

    g_initialized = 1;
    return VW_OK;
}

void vw_crypto_cleanup(void) {
    if (!g_initialized) return;
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
    mutex_destroy(&g_rng_mu);
    g_initialized = 0;
}

/* ── SHA-256 ─────────────────────────────────────────────────────────────── */

vw_err_t vw_crypto_sha256(const void *data, size_t len,
                           uint8_t out_hash[VW_HASH_BYTES]) {
    int rc = mbedtls_sha256((const unsigned char *)data, len, out_hash, 0);
    return (rc == 0) ? VW_OK : VW_ERR_CRYPTO;
}

#ifdef _WIN32

vw_err_t vw_crypto_sha256_file(vw_file_handle_t fh, uint8_t out_hash[VW_HASH_BYTES]) {
    HANDLE h = (HANDLE)fh;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts(&ctx, 0) != 0) goto fail;

    unsigned char buf[65536];
    DWORD nread;
    while (ReadFile(h, buf, sizeof(buf), &nread, NULL) && nread > 0) {
        if (mbedtls_sha256_update(&ctx, buf, nread) != 0) goto fail;
    }

    if (mbedtls_sha256_finish(&ctx, out_hash) != 0) goto fail;
    mbedtls_sha256_free(&ctx);
    return VW_OK;

fail:
    mbedtls_sha256_free(&ctx);
    return VW_ERR_CRYPTO;
}

#else  /* POSIX */

vw_err_t vw_crypto_sha256_file(vw_file_handle_t fd, uint8_t out_hash[VW_HASH_BYTES]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts(&ctx, 0) != 0) goto fail;

    unsigned char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (mbedtls_sha256_update(&ctx, buf, (size_t)n) != 0) goto fail;
    }
    if (n < 0) goto fail;

    if (mbedtls_sha256_finish(&ctx, out_hash) != 0) goto fail;
    mbedtls_sha256_free(&ctx);
    return VW_OK;

fail:
    mbedtls_sha256_free(&ctx);
    return VW_ERR_CRYPTO;
}

#endif

/* ── CSPRNG ─────────────────────────────────────────────────────────────── */

vw_err_t vw_crypto_random(void *buf, size_t len) {
    if (!g_initialized) return VW_ERR_CRYPTO;
    mutex_lock(&g_rng_mu);
    int rc = mbedtls_ctr_drbg_random(&g_ctr_drbg, (unsigned char *)buf, len);
    mutex_unlock(&g_rng_mu);
    return (rc == 0) ? VW_OK : VW_ERR_CRYPTO;
}

/* ── Argon2id ────────────────────────────────────────────────────────────── */

vw_err_t vw_crypto_argon2id_hash(const void *password, size_t pw_len,
                                  const uint8_t *salt,
                                  uint8_t out_salt[VW_ARGON2_SALT_BYTES],
                                  uint8_t out_hash[VW_ARGON2_HASH_BYTES]) {
    if (!salt && !out_salt) return VW_ERR_INVALID_ARG;
    if (salt == NULL) {
        /* Generate salt; out_salt must not be NULL in this path */
        if (vw_crypto_random(out_salt, VW_ARGON2_SALT_BYTES) != VW_OK)
            return VW_ERR_CRYPTO;
        salt = out_salt;
    } else {
        (void)out_salt;  /* caller-provided salt; out_salt is not touched */
    }

    int rc = argon2id_hash_raw(
        VW_ARGON2_TIME_COST,
        VW_ARGON2_MEM_KB,
        VW_ARGON2_PARALLELISM,
        password, pw_len,
        salt, VW_ARGON2_SALT_BYTES,
        out_hash, VW_ARGON2_HASH_BYTES
    );

    return (rc == ARGON2_OK) ? VW_OK : VW_ERR_CRYPTO;
}

vw_err_t vw_crypto_argon2id_verify(const uint8_t hash[VW_ARGON2_HASH_BYTES],
                                    const uint8_t salt[VW_ARGON2_SALT_BYTES],
                                    const void *password, size_t pw_len) {
    uint8_t computed[VW_ARGON2_HASH_BYTES];

    int rc = argon2id_hash_raw(
        VW_ARGON2_TIME_COST,
        VW_ARGON2_MEM_KB,
        VW_ARGON2_PARALLELISM,
        password, pw_len,
        salt, VW_ARGON2_SALT_BYTES,
        computed, VW_ARGON2_HASH_BYTES
    );

    if (rc != ARGON2_OK) {
        memset(computed, 0, sizeof(computed));
        return VW_ERR_CRYPTO;
    }

    int match = vw_crypto_constant_time_eq(hash, computed, VW_ARGON2_HASH_BYTES);
    memset(computed, 0, sizeof(computed));
    return match ? VW_OK : VW_ERR_AUTH_BAD_CREDS;
}

/* ── Timing-safe comparison ──────────────────────────────────────────────── */

int vw_crypto_constant_time_eq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= pa[i] ^ pb[i];
    return diff == 0;
}

/* ── HMAC-SHA256 ─────────────────────────────────────────────────────────── */

vw_err_t vw_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                                const void *data, size_t data_len,
                                uint8_t out_mac[VW_HASH_BYTES]) {
    const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!sha256) return VW_ERR_CRYPTO;
    int rc = mbedtls_md_hmac(sha256, key, key_len,
                              (const unsigned char *)data, data_len, out_mac);
    if (rc != 0) {
        memset(out_mac, 0, VW_HASH_BYTES);
        return VW_ERR_CRYPTO;
    }
    return VW_OK;
}

/* ── HOTP / TOTP ─────────────────────────────────────────────────────────── */

vw_err_t vw_crypto_hotp(const uint8_t *key, size_t key_len,
                         uint64_t counter,
                         char out_code[VW_TOTP_DIGITS + 1]) {
    /* Big-endian 8-byte counter (RFC 4226) */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    unsigned char hmac[20];
    size_t hmac_len = 20;
    const mbedtls_md_info_t *sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!sha1) return VW_ERR_CRYPTO;

    int rc = mbedtls_md_hmac(sha1, key, key_len, msg, sizeof(msg), hmac);
    if (rc != 0) return VW_ERR_CRYPTO;

    /* Dynamic truncation (RFC 4226 §5.3) */
    uint8_t offset = hmac[hmac_len - 1] & 0x0F;
    uint32_t code = ((uint32_t)(hmac[offset]     & 0x7F) << 24)
                  | ((uint32_t)(hmac[offset + 1] & 0xFF) << 16)
                  | ((uint32_t)(hmac[offset + 2] & 0xFF) << 8)
                  | ((uint32_t)(hmac[offset + 3] & 0xFF));

    code %= 1000000u;
    snprintf(out_code, VW_TOTP_DIGITS + 1, "%06u", code);
    return VW_OK;
}

vw_err_t vw_crypto_totp_verify(const uint8_t *key, size_t key_len,
                                int64_t unix_time,
                                const char *code) {
    if (!code || strlen(code) != VW_TOTP_DIGITS) return VW_ERR_AUTH_2FA_INVALID;

    uint64_t t = (uint64_t)(unix_time / (int64_t)VW_TOTP_INTERVAL_SECS);

    for (int delta = -(int)VW_TOTP_WINDOW; delta <= (int)VW_TOTP_WINDOW; delta++) {
        char candidate[VW_TOTP_DIGITS + 1];
        uint64_t counter = (uint64_t)((int64_t)t + delta);
        if (vw_crypto_hotp(key, key_len, counter, candidate) != VW_OK) continue;
        if (vw_crypto_constant_time_eq(candidate, code, VW_TOTP_DIGITS))
            return VW_OK;
    }
    return VW_ERR_AUTH_2FA_INVALID;
}

/* ── Hex encoding ────────────────────────────────────────────────────────── */

static const char hex_chars[] = "0123456789abcdef";

void vw_crypto_hex_encode(const uint8_t *src, size_t len, char *dst) {
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hex_chars[src[i] >> 4];
        dst[i * 2 + 1] = hex_chars[src[i] & 0x0F];
    }
    dst[len * 2] = '\0';
}

vw_err_t vw_crypto_hex_decode(const char *hex, size_t hex_len, uint8_t *dst) {
    if (hex_len % 2 != 0) return VW_ERR_INVALID_ARG;

    for (size_t i = 0; i < hex_len; i += 2) {
        uint8_t hi, lo;
        char ch = hex[i];
        if      (ch >= '0' && ch <= '9') hi = (uint8_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') hi = (uint8_t)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') hi = (uint8_t)(ch - 'A' + 10);
        else return VW_ERR_INVALID_ARG;

        ch = hex[i + 1];
        if      (ch >= '0' && ch <= '9') lo = (uint8_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') lo = (uint8_t)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') lo = (uint8_t)(ch - 'A' + 10);
        else return VW_ERR_INVALID_ARG;

        dst[i / 2] = (hi << 4) | lo;
    }
    return VW_OK;
}
