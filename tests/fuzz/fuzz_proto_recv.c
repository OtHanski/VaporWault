/*
 * fuzz_proto_recv.c — libFuzzer target for the VaporWault wire-protocol frame
 * decoder and per-message-type payload bounds checking.
 *
 * Strategy: the wire frame format is:
 *   [u32 total_len][u16 msg_type][u16 proto_version][payload ...]
 * This target replicates the frame-header validation logic that vw_proto_recv
 * performs (length bounds, VW_MAX_MSG_BYTES enforcement) and then exercises
 * the payload field reads for the most common request message types using the
 * same read pattern as the handlers in vw_file_handlers.c.
 *
 * Note: vw_proto_recv() requires a live TLS vw_conn_t.  Fuzzing the full stack
 * end-to-end (including TLS) is deferred to an integration fuzz target in a
 * future phase.  This target focuses on the parser logic that runs AFTER the
 * TLS layer has delivered bytes.
 *
 * Build: cmake -B build-fuzz -DCMAKE_BUILD_TYPE=Fuzz -DCMAKE_C_COMPILER=clang
 *        cmake --build build-fuzz --target fuzz_proto_recv
 */

#include "vw_proto.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Inline endian helpers (same as vw_proto.h inlines) ──────────────────── */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* ── Bounds-safe field reader ─────────────────────────────────────────────── */

typedef struct { const uint8_t *p; uint32_t len; uint32_t pos; } reader_t;

static int r_u8(reader_t *r, uint8_t *out) {
    if (r->pos + 1 > r->len) return -1;
    *out = r->p[r->pos++];
    return 0;
}
static int r_u16(reader_t *r, uint16_t *out) {
    if (r->pos + 2 > r->len) return -1;
    *out = rd16(r->p + r->pos); r->pos += 2;
    return 0;
}
static int r_u32(reader_t *r, uint32_t *out) {
    if (r->pos + 4 > r->len) return -1;
    *out = rd32(r->p + r->pos); r->pos += 4;
    return 0;
}
static int r_u64(reader_t *r, uint64_t *out) {
    if (r->pos + 8 > r->len) return -1;
    *out = rd64(r->p + r->pos); r->pos += 8;
    return 0;
}
static int r_bytes(reader_t *r, uint32_t n) {
    if (r->pos + n > r->len) return -1;
    r->pos += n;
    return 0;
}
static int r_lenstr(reader_t *r, uint16_t *out_len) {
    uint16_t len;
    if (r_u16(r, &len) < 0) return -1;
    *out_len = len;
    return r_bytes(r, len);
}

/* ── Exercise per-message-type payload reads ──────────────────────────────── */

static void exercise_payload(uint16_t msg_type, reader_t *r)
{
    uint8_t  u8  = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;

    switch ((vw_msg_type_t)msg_type) {
    case VW_MSG_HELLO:
        /* payload: u16 proto_version */
        r_u16(r, &u16);
        break;

    case VW_MSG_AUTH_REQUEST:
        /* payload: u16 uname_len, uname[], sha256(pw)[32] */
        r_lenstr(r, &u16);
        r_bytes(r, 32);
        break;

    case VW_MSG_AUTH_OTP:
        /* payload: session_token[32], u16 otp_len, otp[] */
        r_bytes(r, 32);
        r_lenstr(r, &u16);
        break;

    case VW_MSG_AUTH_RECOVER_REQUEST:
        /* payload: u16 email_len, email[] */
        r_lenstr(r, &u16);
        break;

    case VW_MSG_AUTH_RECOVER_CONFIRM:
        /* payload: token[32], u16 code_len, code[], u16 pw_len, pw[] */
        r_bytes(r, 32);
        r_lenstr(r, &u16);
        r_lenstr(r, &u16);
        break;

    case VW_MSG_SESSION_RESUME:
        /* payload: token[32] */
        r_bytes(r, 32);
        break;

    case VW_MSG_CHUNK_UPLOAD:
        /* payload: token[32], chunk_hash[32], u32 chunk_len, data[chunk_len] */
        r_bytes(r, 32);
        r_bytes(r, 32);
        { uint32_t dlen = 0; r_u32(r, &dlen); r_bytes(r, dlen); }
        break;

    case VW_MSG_CHUNK_QUERY:
        /* payload: token[32], u16 hash_count, then hash_count × sha256[32] */
        r_bytes(r, 32);
        { uint16_t cnt = 0; r_u16(r, &cnt); r_bytes(r, (uint32_t)cnt * 32); }
        break;

    case VW_MSG_FILE_COMMIT:
        /* payload: token[32], u64 file_id, u64 logical_size, u32 chunk_count,
         *          path (string), chunk_count × sha256[32] */
        r_bytes(r, 32);
        r_u64(r, &u64);   /* file_id */
        r_u64(r, &u64);   /* logical_size */
        { uint32_t cnt = 0; r_u32(r, &cnt);
          r_lenstr(r, &u16);             /* virtual_path */
          r_bytes(r, cnt * 32); }         /* chunk_hashes */
        break;

    case VW_MSG_FILE_LIST:
        /* payload: token[32], u16 path_len, path[] */
        r_bytes(r, 32);
        r_lenstr(r, &u16);
        break;

    case VW_MSG_FILE_DELETE:
        /* payload: token[32], u64 file_id */
        r_bytes(r, 32);
        r_u64(r, &u64);
        break;

    case VW_MSG_INVITE_CREATE:
        /* payload: token[32], u16 email_len, email[], u8 is_admin */
        r_bytes(r, 32);
        r_lenstr(r, &u16);
        r_u8(r, &u8);
        break;

    case VW_MSG_QUOTA_ADJUST:
        /* payload: token[32], u64 target_user_id, u64 quota_bytes */
        r_bytes(r, 32);
        r_u64(r, &u64);
        r_u64(r, &u64);
        break;

    case VW_MSG_CLUSTER_STATUS:
        /* payload: token[32] */
        r_bytes(r, 32);
        break;

    default:
        /* Unknown type — consume remaining bytes (exercises nothing specific) */
        break;
    }

    (void)u8; (void)u16; (void)u32; (void)u64;
}

/* ── libFuzzer entry point ────────────────────────────────────────────────── */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Frame header: total_len(4) + msg_type(2) + version(2) = 8 bytes minimum */
    if (size < 8) return 0;

    uint32_t total_len = rd32(data);
    uint16_t msg_type  = rd16(data + 4);
    /* uint16_t version = rd16(data + 6); — not needed here */

    /* Enforce the same bounds as vw_proto_recv */
    if (total_len < 8)                    return 0;
    if (total_len > VW_MAX_MSG_BYTES)     return 0;
    if ((size_t)total_len > size)         return 0;

    uint32_t payload_len = total_len - 8;
    reader_t r = { data + 8, payload_len, 0 };
    exercise_payload(msg_type, &r);

    return 0;
}
