/*
 * fuzz_ecc_decode.c — libFuzzer target for vw_ecc's GF(256) Reed-Solomon
 * decode path (vw_ecc_decode_single / vw_ecc_encode), Phase 22 TASK-262.
 *
 * vw_ecc.c is pure storage-agnostic math (no file I/O, no network) that
 * TASK-260's repair pipeline trusts to reconstruct real user data whenever
 * the scrub pass or a client download hits a corrupt chunk. Every call
 * site today derives k/missing_index/shard_size from its own
 * parity_groups.db records, but those records are on-disk state a
 * corrupt or maliciously-crafted parity_groups.db could poison — so
 * treating them as untrusted input here, at the one place that actually
 * does the GF(256) arithmetic, is the conservative choice, same reasoning
 * fuzz_oplog_replay.c already applies to another on-disk-record parser.
 *
 * Input format (every selector byte is reduced mod a small cap so a run
 * stays fast and bounded, and the harness only ever reads bytes already
 * confirmed to be within `size`):
 *   byte 0: k_selector          -> k = 1 + (k_selector % (VW_ECC_MAX_DATA_SHARDS + 2))
 *                                   (the +2 deliberately allows k to land
 *                                    one and two past VW_ECC_MAX_DATA_SHARDS,
 *                                    to also exercise vw_ecc_encode's own
 *                                    out-of-range rejection)
 *   byte 1: missing_selector    -> missing_index = missing_selector % (k + 2)
 *                                   (0..k-1 = a data shard, k = the parity
 *                                    shard itself, k+1 = deliberately out
 *                                    of range, to exercise
 *                                    vw_ecc_decode_single's own rejection)
 *   byte 2: shard_size_selector -> shard_size = 1 + (shard_size_selector % 64)
 *   remaining bytes: raw shard content, consumed shard_size bytes at a
 *                     time for each of the k data shards (missing input
 *                     bytes are treated as zero — the fuzzer explores
 *                     shard content just as much via mutation of the
 *                     earlier header bytes as via these)
 *
 * Strategy: round-trip through vw_ecc_encode to get a real parity shard
 * for k in-range, then reconstruct exactly the one shard named by
 * missing_index via vw_ecc_decode_single (never more than one — that
 * matches the module's own documented single-fault contract, see
 * vw_ecc.h) and assert the reconstructed bytes exactly match the
 * original. A mismatch, an unexpected VW_ERR_INVALID_ARG on an in-range
 * call, or an unexpected VW_OK on a deliberately out-of-range k/
 * missing_index is treated as a bug and aborts — which libFuzzer reports
 * as a crashing input, same as an ASan/UBSan violation would be.
 */

#include "vw_ecc.h"
#include "vw_proto.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_SHARD_SIZE 64u

static void fail(const char *why)
{
    fprintf(stderr, "fuzz_ecc_decode: %s\n", why);
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int inited = 0;
    if (!inited) { vw_ecc_init(); inited = 1; }

    if (size < 3) return 0;

    uint32_t k = 1u + (uint32_t)(data[0] % (VW_ECC_MAX_DATA_SHARDS + 2u));
    uint32_t missing = (uint32_t)(data[1] % (k + 2u));
    size_t shard_size = 1u + (size_t)(data[2] % MAX_SHARD_SIZE);

    const uint8_t *body = data + 3;
    size_t body_len = size - 3;

    /* VW_ECC_MAX_DATA_SHARDS is the *default* here (no build override in
     * the Fuzz configuration), so k can legitimately reach that many
     * in-range shards — size buffers for the largest possible k. */
    uint8_t shard_bufs[VW_ECC_MAX_DATA_SHARDS + 2u][MAX_SHARD_SIZE];
    uint8_t parity_buf[MAX_SHARD_SIZE];
    uint8_t out_buf[MAX_SHARD_SIZE];
    const uint8_t *shard_ptrs[VW_ECC_MAX_DATA_SHARDS + 2u];

    for (uint32_t i = 0; i < k && i <= VW_ECC_MAX_DATA_SHARDS + 1u; i++) {
        for (size_t b = 0; b < shard_size; b++) {
            size_t src = (size_t)i * shard_size + b;
            shard_bufs[i][b] = (body_len > 0) ? body[src % body_len] : 0u;
        }
        shard_ptrs[i] = shard_bufs[i];
    }

    memset(parity_buf, 0, sizeof(parity_buf));
    vw_err_t enc_rc = vw_ecc_encode(shard_ptrs, k, shard_size, parity_buf);

    if (k == 0 || k > VW_ECC_MAX_DATA_SHARDS) {
        if (enc_rc == VW_OK) fail("vw_ecc_encode accepted an out-of-range k");
        return 0;
    }
    if (enc_rc != VW_OK) fail("vw_ecc_encode rejected an in-range k");

    /* Save what the missing slot's original bytes were, then null it out
     * of the shard list exactly as vw_repair.c's real caller would after
     * detecting corruption (missing == k means "reconstruct parity" —
     * shards[] stays fully populated in that case, only decode's own
     * `parity` argument logically drops out). */
    uint8_t expected[MAX_SHARD_SIZE];
    memset(expected, 0, sizeof(expected));
    const uint8_t *decode_shards[VW_ECC_MAX_DATA_SHARDS + 2u];
    memcpy(decode_shards, shard_ptrs, sizeof(shard_ptrs));

    if (missing < k) {
        memcpy(expected, shard_bufs[missing], shard_size);
        decode_shards[missing] = NULL;
    } else if (missing == k) {
        memcpy(expected, parity_buf, shard_size);
    }

    memset(out_buf, 0xAA, sizeof(out_buf));
    vw_err_t dec_rc = vw_ecc_decode_single(decode_shards, k, parity_buf,
                                            missing, shard_size, out_buf);

    if (missing > k) {
        if (dec_rc == VW_OK) fail("vw_ecc_decode_single accepted an out-of-range missing_index");
        return 0;
    }

    if (dec_rc != VW_OK) fail("vw_ecc_decode_single rejected a valid single-fault input");
    if (memcmp(out_buf, expected, shard_size) != 0)
        fail("vw_ecc_decode_single reconstructed the wrong bytes");

    return 0;
}
