/*
 * test_vw_ecc.c — unit tests for vw_ecc (GF(256) Reed-Solomon primitives).
 *
 * TASK-258 (Phase 22). Covers: GF(256) field properties (including the
 * zero-operand edge cases that must never touch the log table),
 * encode/decode round trips for every possible single missing shard
 * (including the parity shard itself), rejection of two-simultaneous-
 * faults, invalid-argument handling, and a randomized property test over
 * the GF(256) arithmetic (this task's own "fuzz/property test" acceptance
 * criterion — a dedicated persistent libFuzzer-style harness under
 * tests/fuzz/ is TASK-262's separate, broader QA pass, not duplicated
 * here).
 */

#include "vw_test.h"
#include "vw_ecc.h"
#include <stdlib.h>
#include <string.h>

/* Simple deterministic PRNG so failures are reproducible without needing
 * to capture/replay a seed — same rationale as this codebase's other
 * randomized tests (e.g. test_vw_sync.c's walk fuzzing). */
static uint32_t g_rng_state = 0x2f6e2b1u;
static uint32_t next_rand(void)
{
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}

static void fill_random(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(next_rand() & 0xFF);
}

VW_TEST_SUITE("vw_ecc") {
    vw_ecc_init();

    /* ── GF(256) field properties ─────────────────────────────────────── */

    VW_TEST_CASE("gf256_mul: identity, zero, and commutativity") {
        int a;
        for (a = 0; a < 256; a++) {
            VW_ASSERT_EQ(vw_gf256_mul((uint8_t)a, 1), (uint8_t)a);
            VW_ASSERT_EQ(vw_gf256_mul(1, (uint8_t)a), (uint8_t)a);
            VW_ASSERT_EQ(vw_gf256_mul((uint8_t)a, 0), 0);
            VW_ASSERT_EQ(vw_gf256_mul(0, (uint8_t)a), 0);
        }
        VW_ASSERT_EQ(vw_gf256_mul(0x53, 0xCA), vw_gf256_mul(0xCA, 0x53));
        VW_ASSERT_EQ(vw_gf256_mul(17, 23), vw_gf256_mul(23, 17));
    }

    VW_TEST_CASE("gf256_div/inv: never touch the log table on a zero operand") {
        /* Documented caller-bug contract: return 0, never crash / read
         * uninitialized-meaning g_gf_log[0]. */
        VW_ASSERT_EQ(vw_gf256_div(5, 0), 0);
        VW_ASSERT_EQ(vw_gf256_div(0, 5), 0);
        VW_ASSERT_EQ(vw_gf256_div(0, 0), 0);
        VW_ASSERT_EQ(vw_gf256_inv(0), 0);
    }

    VW_TEST_CASE("gf256_div is the inverse of gf256_mul for every nonzero pair") {
        int a, b, all_ok = 1;
        for (a = 1; a < 256 && all_ok; a++) {
            for (b = 1; b < 256; b++) {
                uint8_t prod = vw_gf256_mul((uint8_t)a, (uint8_t)b);
                uint8_t back = vw_gf256_div(prod, (uint8_t)b);
                if (back != (uint8_t)a) { all_ok = 0; break; }
            }
        }
        VW_ASSERT(all_ok);
    }

    VW_TEST_CASE("gf256_mul(a, gf256_inv(a)) == 1 for every nonzero a") {
        int a, all_ok = 1;
        for (a = 1; a < 256; a++) {
            if (vw_gf256_mul((uint8_t)a, vw_gf256_inv((uint8_t)a)) != 1) {
                all_ok = 0;
                break;
            }
        }
        VW_ASSERT(all_ok);
    }

    VW_TEST_CASE("gf256_pow matches repeated multiplication") {
        int a;
        for (a = 1; a < 256; a++) {
            uint8_t expected = 1;
            int e;
            for (e = 0; e <= 6; e++) {
                VW_ASSERT_EQ(vw_gf256_pow((uint8_t)a, (uint8_t)e), expected);
                expected = vw_gf256_mul(expected, (uint8_t)a);
            }
        }
        VW_ASSERT_EQ(vw_gf256_pow(0, 0), 1);
        VW_ASSERT_EQ(vw_gf256_pow(0, 5), 0);
    }

    /* ── Encode/decode round trips ───────────────────────────────────── */

    VW_TEST_CASE("encode+decode: reconstruct each missing data shard in turn") {
        const uint32_t k = 6;
        const size_t shard_size = 777; /* deliberately not a power of 2 */
        uint8_t *data[16];
        uint8_t parity[777];
        uint32_t i;

        for (i = 0; i < k; i++) {
            data[i] = (uint8_t *)malloc(shard_size);
            fill_random(data[i], shard_size);
        }

        const uint8_t *shard_ptrs[16];
        for (i = 0; i < k; i++) shard_ptrs[i] = data[i];
        VW_ASSERT_OK(vw_ecc_encode(shard_ptrs, k, shard_size, parity));

        for (i = 0; i < k; i++) {
            const uint8_t *present[16];
            uint32_t j;
            for (j = 0; j < k; j++) present[j] = (j == i) ? NULL : data[j];

            uint8_t reconstructed[777];
            VW_ASSERT_OK(vw_ecc_decode_single(present, k, parity, i,
                                               shard_size, reconstructed));
            VW_ASSERT_MEM_EQ(reconstructed, data[i], shard_size);
        }

        for (i = 0; i < k; i++) free(data[i]);
    }

    VW_TEST_CASE("encode+decode: reconstruct the parity shard itself") {
        const uint32_t k = 4;
        const size_t shard_size = 256;
        uint8_t *data[16];
        uint8_t parity[256], reconstructed_parity[256];
        uint32_t i;

        for (i = 0; i < k; i++) {
            data[i] = (uint8_t *)malloc(shard_size);
            fill_random(data[i], shard_size);
        }
        const uint8_t *shard_ptrs[16];
        for (i = 0; i < k; i++) shard_ptrs[i] = data[i];
        VW_ASSERT_OK(vw_ecc_encode(shard_ptrs, k, shard_size, parity));

        VW_ASSERT_OK(vw_ecc_decode_single(shard_ptrs, k, NULL, k,
                                           shard_size, reconstructed_parity));
        VW_ASSERT_MEM_EQ(reconstructed_parity, parity, shard_size);

        for (i = 0; i < k; i++) free(data[i]);
    }

    VW_TEST_CASE("decode rejects two simultaneous faults") {
        const uint32_t k = 4;
        const size_t shard_size = 64;
        uint8_t data0[64], data1[64], data2[64], data3[64], parity[64], out[64];
        fill_random(data0, sizeof(data0));
        fill_random(data1, sizeof(data1));
        fill_random(data2, sizeof(data2));
        fill_random(data3, sizeof(data3));
        const uint8_t *shards[4] = { data0, data1, data2, data3 };
        VW_ASSERT_OK(vw_ecc_encode(shards, k, shard_size, parity));

        /* Two missing data shards (index 1 also NULL, on top of the
         * declared missing_index 0) — cannot be covered by 1 parity shard. */
        const uint8_t *present[4] = { NULL, NULL, data2, data3 };
        VW_ASSERT_ERR(vw_ecc_decode_single(present, k, parity, 0,
                                            shard_size, out),
                      VW_ERR_INVALID_ARG);

        /* Missing data shard AND missing parity — also uncoverable. */
        const uint8_t *present2[4] = { NULL, data1, data2, data3 };
        VW_ASSERT_ERR(vw_ecc_decode_single(present2, k, NULL, 0,
                                            shard_size, out),
                      VW_ERR_INVALID_ARG);
    }

    VW_TEST_CASE("encode/decode reject invalid arguments") {
        uint8_t buf[16], parity[16], out[16];
        const uint8_t *shards1[1] = { buf };

        VW_ASSERT_ERR(vw_ecc_encode(NULL, 1, 16, parity), VW_ERR_INVALID_ARG);
        VW_ASSERT_ERR(vw_ecc_encode(shards1, 0, 16, parity), VW_ERR_INVALID_ARG);
        VW_ASSERT_ERR(vw_ecc_encode(shards1, VW_ECC_MAX_DATA_SHARDS + 1, 16, parity),
                      VW_ERR_INVALID_ARG);
        VW_ASSERT_ERR(vw_ecc_encode(shards1, 1, 0, parity), VW_ERR_INVALID_ARG);
        VW_ASSERT_ERR(vw_ecc_encode(shards1, 1, 16, NULL), VW_ERR_INVALID_ARG);

        VW_ASSERT_ERR(vw_ecc_decode_single(shards1, 1, parity, 2, 16, out),
                      VW_ERR_INVALID_ARG); /* missing_index > k */
        VW_ASSERT_ERR(vw_ecc_decode_single(shards1, 1, NULL, 0, 16, out),
                      VW_ERR_INVALID_ARG); /* reconstructing data w/ no parity */
    }

    /* ── Randomized property test (this task's fuzz/property coverage) ── */

    VW_TEST_CASE("property: random k/shard_size/missing_index always round-trips") {
        int trial, all_ok = 1;
        for (trial = 0; trial < 200 && all_ok; trial++) {
            uint32_t k = 1u + (next_rand() % VW_ECC_MAX_DATA_SHARDS);
            size_t shard_size = 1u + (next_rand() % 2048u);
            uint32_t missing = next_rand() % (k + 1u); /* 0..k inclusive */

            uint8_t *bufs[VW_ECC_MAX_DATA_SHARDS];
            const uint8_t *shard_ptrs[VW_ECC_MAX_DATA_SHARDS];
            uint32_t i;
            for (i = 0; i < k; i++) {
                bufs[i] = (uint8_t *)malloc(shard_size);
                fill_random(bufs[i], shard_size);
                shard_ptrs[i] = bufs[i];
            }

            uint8_t *parity = (uint8_t *)malloc(shard_size);
            if (vw_ecc_encode(shard_ptrs, k, shard_size, parity) != VW_OK) {
                all_ok = 0;
            } else {
                const uint8_t *present[VW_ECC_MAX_DATA_SHARDS];
                for (i = 0; i < k; i++)
                    present[i] = (i == missing) ? NULL : bufs[i];

                uint8_t *out = (uint8_t *)malloc(shard_size);
                const uint8_t *use_parity = (missing == k) ? NULL : parity;
                if (vw_ecc_decode_single(present, k, use_parity, missing,
                                          shard_size, out) != VW_OK) {
                    all_ok = 0;
                } else {
                    const uint8_t *expected = (missing == k) ? parity : bufs[missing];
                    if (memcmp(out, expected, shard_size) != 0) all_ok = 0;
                }
                free(out);
            }

            free(parity);
            for (i = 0; i < k; i++) free(bufs[i]);
        }
        VW_ASSERT(all_ok);
    }
}
VW_TEST_SUITE_END()
