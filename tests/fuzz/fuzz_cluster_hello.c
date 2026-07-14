/*
 * fuzz_cluster_hello.c — libFuzzer target for the NODE_HELLO payload parser.
 *
 * The cluster accept loop (handle_cluster_conn in vw_cluster.c) parses the
 * NODE_HELLO frame payload before any database lookup.  This target
 * replicates those exact parse steps so the fuzzer can explore all
 * combinations of field lengths, overflow conditions, and boundary values.
 *
 * Wire format (payload only — the 8-byte proto header is omitted here,
 * matching how the handler sees it after vw_proto_recv strips the header):
 *
 *   u64  node_id          (8 bytes)
 *   u8[32] auth_token     (32 bytes)  — constant-time compare in the real handler
 *   u64  sync_watermark   (8 bytes)
 *   u16  proto_version    (2 bytes)
 *   u16  hostname_len     (2 bytes)
 *   u8[hostname_len] hostname
 *
 * Minimum valid payload: 8+32+8+2+2 = 52 bytes.
 *
 * Security invariants checked by assertion:
 *   - payload_len < 52 → always rejected (too short)
 *   - off + hostname_len > payload_len → always rejected (overrun)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#define NODE_HELLO_MIN_LEN (8u + 32u + 8u + 2u + 2u)  /* 52 */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint64_t rd64(const uint8_t *p) {
    uint32_t lo = (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    uint32_t hi = (uint32_t)p[4] | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/*
 * Returns 1 if payload is a well-formed NODE_HELLO (fields in bounds),
 * 0 if malformed.
 * This exactly mirrors handle_cluster_conn's validation path.
 */
static int parse_node_hello(const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len < NODE_HELLO_MIN_LEN) return 0;

    uint32_t off = 0;

    uint64_t node_id        = rd64(payload + off); off += 8;
    uint8_t  recv_token[32]; memcpy(recv_token, payload + off, 32); off += 32;
    uint64_t sync_watermark = rd64(payload + off); off += 8;
    uint16_t proto_version  = rd16(payload + off); off += 2;
    uint16_t hostname_len   = rd16(payload + off); off += 2;

    /* Guard: off + hostname_len must not exceed payload_len */
    if ((uint32_t)(off + hostname_len) > payload_len) return 0;

    /* Suppress "unused variable" warnings */
    (void)node_id; (void)sync_watermark; (void)proto_version;
    (void)recv_token;

    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > UINT32_MAX) return 0;
    uint32_t payload_len = (uint32_t)size;

    int well_formed = parse_node_hello(data, payload_len);

    /* Postcondition: short payloads must be rejected */
    if (payload_len < NODE_HELLO_MIN_LEN) {
        assert(well_formed == 0 &&
               "cluster hello: accepted payload shorter than minimum");
    }

    /* Postcondition: hostname overrun must be rejected */
    if (payload_len >= NODE_HELLO_MIN_LEN) {
        uint16_t hlen = rd16(data + 8 + 32 + 8 + 2);
        uint32_t off  = NODE_HELLO_MIN_LEN;
        if ((uint64_t)off + hlen > payload_len) {
            assert(well_formed == 0 &&
                   "cluster hello: accepted truncated hostname");
        }
    }

    return 0;
}
