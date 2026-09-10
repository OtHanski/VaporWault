/*
 * vw_ecc.c — GF(256) Reed-Solomon erasure coding primitives.
 *
 * See vw_ecc.h for the design description and the field parameters
 * (polynomial 0x11D, generator 2) this table generation implements.
 */

#include "vw_ecc.h"

#include <string.h>

/* ── GF(256) log/exp tables ──────────────────────────────────────────────── */

static uint8_t g_gf_exp[255];
static uint8_t g_gf_log[256]; /* g_gf_log[0] is never read (mul/div/inv all
                                * special-case a zero operand before
                                * touching the log table) — its value is
                                * meaningless static-zero-init, not UB. */
static int g_gf_ready = 0;

void vw_ecc_init(void)
{
    if (g_gf_ready) return;

    uint16_t x = 1;
    int i;
    for (i = 0; i < 255; i++) {
        g_gf_exp[i] = (uint8_t)x;
        g_gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }

    g_gf_ready = 1;
}

uint8_t vw_gf256_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) return 0;
    int sum = (int)g_gf_log[a] + (int)g_gf_log[b];
    return g_gf_exp[sum % 255];
}

uint8_t vw_gf256_div(uint8_t a, uint8_t b)
{
    if (b == 0) return 0; /* caller bug (division by zero) — defined, not UB */
    if (a == 0) return 0;
    int diff = (int)g_gf_log[a] - (int)g_gf_log[b];
    diff %= 255;
    if (diff < 0) diff += 255;
    return g_gf_exp[diff];
}

uint8_t vw_gf256_pow(uint8_t base, uint8_t exp)
{
    if (exp == 0) return 1;
    if (base == 0) return 0;
    int p = ((int)g_gf_log[base] * (int)exp) % 255;
    return g_gf_exp[p];
}

uint8_t vw_gf256_inv(uint8_t a)
{
    if (a == 0) return 0; /* caller bug (0 has no inverse) — defined, not UB */
    int p = 255 - (int)g_gf_log[a];
    return g_gf_exp[p % 255];
}

/* ── Single-parity coefficient row (Phase 22 MVP, m=1) ───────────────────── */

/*
 * Every data shard contributes with coefficient 1 — see vw_ecc.h's header
 * comment for why this is a genuine, valid systematic Reed-Solomon row,
 * not a stand-in for one. Returned by a function (rather than a fixed-size
 * array literal, which would need to match whatever VW_ECC_MAX_DATA_SHARDS
 * is compiled with — a real bug this project's own unit tests caught by
 * overriding that macro for a fast test build) so a future non-degenerate
 * coefficient row is a one-line change here, not a rewrite of encode's
 * loop structure.
 */
static uint8_t parity_row_coeff(uint32_t data_shard_index)
{
    (void)data_shard_index;
    return 1;
}

/* ── Erasure coding ──────────────────────────────────────────────────────── */

vw_err_t vw_ecc_encode(const uint8_t *const *shards, uint32_t k,
                        size_t shard_size, uint8_t *parity_out)
{
    if (!shards || !parity_out || k == 0 || k > VW_ECC_MAX_DATA_SHARDS ||
        shard_size == 0)
        return VW_ERR_INVALID_ARG;

    uint32_t i;
    for (i = 0; i < k; i++)
        if (!shards[i]) return VW_ERR_INVALID_ARG;

    memset(parity_out, 0, shard_size);

    for (i = 0; i < k; i++) {
        uint8_t coeff = parity_row_coeff(i);
        const uint8_t *s = shards[i];
        size_t b;
        if (coeff == 1) {
            /* gf256_mul(1, x) == x for every x — special-cased for speed
             * on the real MVP hot path (see vw_ecc.h); mathematically
             * identical to the general branch below. */
            for (b = 0; b < shard_size; b++)
                parity_out[b] ^= s[b];
        } else {
            for (b = 0; b < shard_size; b++)
                parity_out[b] ^= vw_gf256_mul(coeff, s[b]);
        }
    }

    return VW_OK;
}

vw_err_t vw_ecc_decode_single(const uint8_t *const *shards, uint32_t k,
                               const uint8_t *parity, uint32_t missing_index,
                               size_t shard_size, uint8_t *out)
{
    if (!shards || !out || k == 0 || k > VW_ECC_MAX_DATA_SHARDS ||
        shard_size == 0 || missing_index > k)
        return VW_ERR_INVALID_ARG;

    uint32_t i;

    if (missing_index == k) {
        /* Reconstructing the parity shard itself: need every data shard
         * present, then it's just a fresh encode. */
        for (i = 0; i < k; i++)
            if (!shards[i]) return VW_ERR_INVALID_ARG;
        return vw_ecc_encode(shards, k, shard_size, out);
    }

    /* Reconstructing data shard `missing_index`: need the parity shard
     * plus every OTHER data shard — any additional gap is a second
     * simultaneous fault this single-parity group cannot cover. */
    if (!parity) return VW_ERR_INVALID_ARG;
    for (i = 0; i < k; i++) {
        if (i == missing_index) continue;
        if (!shards[i]) return VW_ERR_INVALID_ARG;
    }

    /* Coefficients are all 1 (see g_parity_row), so solving
     * parity = XOR_i(coeff_i * shard_i) for the one unknown shard reduces
     * to: missing = parity XOR (XOR of every other present shard). */
    memcpy(out, parity, shard_size);
    for (i = 0; i < k; i++) {
        if (i == missing_index) continue;
        const uint8_t *s = shards[i];
        size_t b;
        for (b = 0; b < shard_size; b++)
            out[b] ^= s[b];
    }

    return VW_OK;
}
