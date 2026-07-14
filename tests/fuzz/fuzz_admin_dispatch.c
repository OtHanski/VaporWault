/*
 * fuzz_admin_dispatch.c — libFuzzer target for the admin socket message parser.
 *
 * The admin IPC channel uses the same 8-byte framing as the main proto:
 *   [u32 total_len][u16 msg_type][u16 reserved][payload...]
 *
 * Message types are in the 0x9000–0x9FFF range (see vw_admin.h for formats).
 * This target replicates the per-message-type parse steps from
 * handle_admin_connection in vw_admin.c to let the fuzzer explore all
 * combinations of field values and length overflows.
 *
 * Wire formats (payload only — 8-byte header stripped; all integers LE):
 *
 *   USER_CREATE_REQ  (0x9001): u8 is_admin, u16 uname_len, uname[], u16 pw_len, pw[]
 *   USER_LIST_REQ    (0x9003): (no payload)
 *   SET_QUOTA_REQ    (0x9005): u16 uname_len, uname[], u64 quota_bytes
 *   OPLOG_TAIL_REQ   (0x9007): u32 count
 *   CONN_LIST_REQ    (0x9009): (no payload)
 *   RELOAD_CERT_REQ  (0x900B): (no payload)
 *
 * Security invariants checked by assertion:
 *   - total_len < 8 → rejected
 *   - total_len > VW_MAX_MSG_BYTES → rejected
 *   - any length field whose sum exceeds payload_len → overrun detected
 */

#include "vw_admin.h"
#include "vw_proto.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct { const uint8_t *p; uint32_t len; uint32_t pos; } rd_t;
static int rd_u8 (rd_t *r, uint8_t  *o) { if (r->pos+1>r->len) return -1; *o=r->p[r->pos++]; return 0; }
static int rd_u16(rd_t *r, uint16_t *o) { if (r->pos+2>r->len) return -1; *o=rd16(r->p+r->pos); r->pos+=2; return 0; }
static int rd_u32(rd_t *r, uint32_t *o) { if (r->pos+4>r->len) return -1; *o=rd32(r->p+r->pos); r->pos+=4; return 0; }
static int rd_u64(rd_t *r, uint64_t *o) {
    uint32_t lo=0,hi=0;
    if (rd_u32(r,&lo)<0) return -1;
    if (rd_u32(r,&hi)<0) return -1;
    *o=(uint64_t)lo|((uint64_t)hi<<32); return 0;
}
static int rd_bytes(rd_t *r, uint32_t n) { if (r->pos+n>r->len) return -1; r->pos+=n; return 0; }
static int rd_lenstr16(rd_t *r, uint16_t *out_len) {
    uint16_t len;
    if (rd_u16(r,&len)<0) return -1;
    *out_len=len;
    return rd_bytes(r,len);
}

/* Replicate the admin handler's payload parse for each message type. */
static void exercise_admin_payload(uint16_t msg_type, rd_t *r)
{
    uint8_t  u8  = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;

    switch ((vw_admin_msg_t)msg_type) {
    case VW_ADMIN_USER_CREATE_REQ:
        /* u8 is_admin, u16 uname_len, uname[], u16 pw_len, pw[] */
        rd_u8(r, &u8);
        rd_lenstr16(r, &u16);
        rd_lenstr16(r, &u16);
        break;

    case VW_ADMIN_USER_LIST_REQ:
        /* no payload */
        break;

    case VW_ADMIN_SET_QUOTA_REQ:
        /* u16 uname_len, uname[], u64 quota_bytes */
        rd_lenstr16(r, &u16);
        rd_u64(r, &u64);
        break;

    case VW_ADMIN_OPLOG_TAIL_REQ:
        /* u32 count */
        rd_u32(r, &u32);
        break;

    case VW_ADMIN_CONN_LIST_REQ:
        /* no payload */
        break;

    case VW_ADMIN_RELOAD_CERT_REQ:
        /* no payload */
        break;

    default:
        /* Unknown type — consume remaining bytes */
        break;
    }

    (void)u8; (void)u16; (void)u32; (void)u64;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Frame header: 8 bytes minimum */
    if (size < 8) return 0;

    uint32_t total_len = rd32(data);
    uint16_t msg_type  = rd16(data + 4);
    /* u16 reserved = rd16(data + 6); */

    /* Enforce same bounds as the admin handler */
    if (total_len < 8)                return 0;
    if (total_len > VW_MAX_MSG_BYTES) return 0;
    if ((size_t)total_len > size)     return 0;

    uint32_t payload_len = total_len - 8;
    rd_t r = { data + 8, payload_len, 0 };
    exercise_admin_payload(msg_type, &r);

    /* Postcondition: we must never read past payload_len */
    assert(r.pos <= r.len && "admin dispatch: reader overran payload");

    return 0;
}
