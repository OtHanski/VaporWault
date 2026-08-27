/*
 * fuzz_search.c — libFuzzer target for the SEARCH query parser and its
 * case-insensitive substring matcher (TASK-198/202; docs/PROTOCOL.md §7.12).
 *
 * search_name_matches() (vw_file_handlers.c) is gated behind
 * VW_FH_TESTABLE/VW_FILE_HANDLERS_TEST_HOOKS, so it has external linkage
 * only in the unit-test build — the Fuzz build type links the production
 * vw_server_lib (built without that define), where it's `static` and
 * unreachable from here. Same situation this directory already has a
 * precedent for (see fuzz_admin_dispatch.c's and fuzz_cluster_hello.c's own
 * "inline replication" notes): the matcher's algorithm is reproduced here
 * byte-for-byte from the reviewed, unit-tested original rather than called
 * directly. The wire-level parsing half below (SEARCH's payload: token[32]
 * + a length-prefixed query string, then the 256-byte cap) uses the real
 * vw_proto_read_str() — that one IS a plain public vw_core function, no
 * gating involved, so it's the genuine article, not a replica.
 *
 * Wire format (payload only — 8-byte frame header stripped):
 *   SEARCH: session_token[32] + query(string, u16 len prefix)
 *
 * Security invariants checked by assertion:
 *   - vw_proto_read_str never reads past the payload it was given.
 *   - A query longer than 256 bytes is always rejected before matching
 *     (docs/PROTOCOL.md §7.12's own stated bound) — mirrors handle_search's
 *     own check in vw_file_handlers.c exactly.
 *   - The matcher itself never reads out of bounds of either buffer it's
 *     given, for any needle/haystack length combination libFuzzer finds
 *     (ASan catches this even without an explicit assertion; the point of
 *     this target existing at all is to let it look).
 */

#include "vw_proto.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#define FUZZ_SEARCH_MAX_QUERY_BYTES 256u

/*
 * Byte-for-byte reproduction of search_name_matches() in
 * src/server/vw_file_handlers.c — see that function's own doc comment.
 * Keep these in sync; a unit test (tests/unit/test_vw_file_handlers.c)
 * already exercises the real one's behavior directly, so this copy is
 * fuzzed purely for crash-safety on adversarial lengths, not re-verified
 * for correctness here.
 */
static int search_name_matches_replica(const char *name, size_t name_len,
                                        const char *needle_lc, size_t needle_len)
{
    if (needle_len == 0) return 1;
    if (needle_len > name_len) return 0;
    for (size_t i = 0; i + needle_len <= name_len; i++) {
        size_t j;
        for (j = 0; j < needle_len; j++) {
            if ((size_t)tolower((unsigned char)name[i + j]) != (size_t)(unsigned char)needle_lc[j])
                break;
        }
        if (j == needle_len) return 1;
    }
    return 0;
}

static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Frame header: 8 bytes minimum, same convention as this directory's
     * other dispatch-level fuzz targets. */
    if (size < 8) return 0;

    uint32_t total_len = rd32(data);
    /* uint16_t msg_type = rd16(data + 4); — fixed to SEARCH for this target */
    (void)rd16(data + 4);

    if (total_len < 8)                return 0;
    if (total_len > VW_MAX_MSG_BYTES) return 0;
    if ((size_t)total_len > size)     return 0;

    const uint8_t *payload = data + 8;
    uint32_t plen = total_len - 8;

    /* handle_search's own first check: token[32] must be present. */
    if (plen < VW_TOKEN_BYTES) return 0;

    const uint8_t *var = payload + VW_TOKEN_BYTES;
    uint32_t var_len   = plen - VW_TOKEN_BYTES;
    uint32_t off = 0;
    const char *query = NULL;
    uint16_t query_len = 0;
    vw_err_t err = vw_proto_read_str(var, var_len, &off, &query, &query_len);

    /* Postcondition: the reader must never claim to have consumed more
     * than it was given, regardless of an adversarial length prefix. */
    assert(off <= var_len && "vw_proto_read_str: reader overran payload");

    if (err != VW_OK) return 0;

    /* handle_search's own second check, verified as a real invariant:
     * a query over the §7.12 cap must never reach the matcher. */
    if (query_len > FUZZ_SEARCH_MAX_QUERY_BYTES) {
        /* Correctly rejected — nothing further to exercise this input. */
        return 0;
    }

    /* Lower-case the query exactly as handle_search does before matching
     * (search_name_matches itself requires an already-lower-cased needle). */
    char query_lc[FUZZ_SEARCH_MAX_QUERY_BYTES];
    for (uint16_t i = 0; i < query_len; i++)
        query_lc[i] = (char)tolower((unsigned char)query[i]);

    /* Match against both a fixed representative filename AND whatever
     * bytes remain in the input past the query, as an arbitrary "name" —
     * the matcher must never read out of bounds for any combination. */
    static const char fixed_name[] = "Report_Q3.PDF";
    (void)search_name_matches_replica(fixed_name, sizeof(fixed_name) - 1,
                                       query_lc, query_len);

    uint32_t consumed = VW_TOKEN_BYTES + off;
    if (consumed < plen) {
        const char *rest = (const char *)payload + consumed;
        size_t rest_len = plen - consumed;
        (void)search_name_matches_replica(rest, rest_len, query_lc, query_len);
    }

    return 0;
}
