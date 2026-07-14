/*
 * test_vw_proto.c — unit tests for vw_proto encode / decode functions.
 *
 * Tests the auth-message serialisation layer and the string helpers.
 * vw_proto_send / vw_proto_recv / vw_proto_negotiate require a live
 * connection and are exercised in tests/integration/test_auth_handshake.c.
 *
 * Coverage (TASK-012 §2):
 *   TP-1  AUTH_REQUEST round-trip
 *   TP-2  AUTH_OK round-trip — all 6 fields including user_id (v3 payload)
 *   TP-3  AUTH_FAIL round-trip
 *   TP-4  AUTH_CHALLENGE round-trip
 *   TP-5  AUTH_OTP round-trip
 *   TP-6  ERROR round-trip
 *   TP-7  Encode: buffer too small → VW_ERR_PROTO_TOO_LARGE
 *   TP-8  AUTH_OK decode: truncated input → VW_ERR_PROTO_TRUNCATED
 *   TP-9  AUTH_OK decode: trailing byte → VW_ERR_PROTO_TRUNCATED (o != len)
 *   TP-10 AUTH_FAIL decode: truncated input → VW_ERR_PROTO_TRUNCATED
 *   TP-11 AUTH_REQUEST decode: username_len = 0 rejected
 *   TP-12 AUTH_REQUEST decode: username_len > VW_MAX_USERNAME_BYTES rejected
 *   TP-13 AUTH_OTP decode: otp_len = 0 rejected
 *   TP-14 AUTH_OTP decode: otp_len > 8 rejected
 *   TP-15 write_str: *offset > buf_size unsigned-underflow regression guard
 *   TP-16 AUTH_OK: negative expires_at round-trips correctly via LE two's-complement
 */

#include "vw_test.h"
#include "vw_proto.h"
#include <string.h>
#include <stdint.h>

VW_TEST_SUITE("vw_proto") {

    /* ── TP-1: AUTH_REQUEST round-trip ─────────────────────────────────── */

    VW_TEST_CASE("AUTH_REQUEST round-trip") {
        static const char uname[] = "alice";
        const uint16_t uname_len  = (uint16_t)(sizeof(uname) - 1u);
        uint8_t token[VW_TOKEN_BYTES];
        memset(token, 0xAB, VW_TOKEN_BYTES);

        vw_payload_auth_request_t req;
        req.username     = uname;
        req.username_len = uname_len;
        memcpy(req.auth_token, token, VW_TOKEN_BYTES);

        uint8_t buf[256];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_request(&req, buf, sizeof(buf), &len));

        vw_payload_auth_request_t out;
        VW_ASSERT_OK(vw_proto_decode_auth_request(buf, len, &out));
        VW_ASSERT_EQ(out.username_len, uname_len);
        VW_ASSERT_MEM_EQ(out.username,   uname, uname_len);
        VW_ASSERT_MEM_EQ(out.auth_token, token, VW_TOKEN_BYTES);
    }

    /* ── TP-2: AUTH_OK round-trip — all six v3 fields ──────────────────── */

    VW_TEST_CASE("AUTH_OK round-trip") {
        vw_payload_auth_ok_t ok_in;
        memset(&ok_in, 0, sizeof(ok_in));
        memset(ok_in.session_token, 0xCD, VW_TOKEN_BYTES);
        ok_in.expires_at  = (int64_t)1735689600LL;  /* 2025-01-01T00:00:00Z */
        ok_in.is_admin    = 1;
        ok_in.quota_bytes = 10737418240ULL;          /* 10 GiB */
        ok_in.used_bytes  = 536870912ULL;            /* 512 MiB */
        ok_in.user_id     = 99999ULL;

        uint8_t buf[256];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_ok(&ok_in, buf, sizeof(buf), &len));
        /* v3: session_token(32) + expires_at(8) + is_admin(1) + quota(8) + used(8) + user_id(8) = 65 */
        VW_ASSERT_EQ(len, 32u + 8u + 1u + 8u + 8u + 8u);

        vw_payload_auth_ok_t ok_out;
        memset(&ok_out, 0, sizeof(ok_out));
        VW_ASSERT_OK(vw_proto_decode_auth_ok(buf, len, &ok_out));
        VW_ASSERT_MEM_EQ(ok_out.session_token, ok_in.session_token, VW_TOKEN_BYTES);
        VW_ASSERT_EQ(ok_out.expires_at,  ok_in.expires_at);
        VW_ASSERT_EQ(ok_out.is_admin,    ok_in.is_admin);
        VW_ASSERT_EQ(ok_out.quota_bytes, ok_in.quota_bytes);
        VW_ASSERT_EQ(ok_out.used_bytes,  ok_in.used_bytes);
        VW_ASSERT_EQ(ok_out.user_id,     ok_in.user_id);
    }

    /* ── TP-3: AUTH_FAIL round-trip ────────────────────────────────────── */

    VW_TEST_CASE("AUTH_FAIL round-trip") {
        vw_payload_auth_fail_t fail_in;
        fail_in.error_code             = (uint32_t)VW_ERR_AUTH_BAD_CREDS;
        fail_in.lockout_remaining_secs = 600u;

        uint8_t buf[16];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_fail(&fail_in, buf, sizeof(buf), &len));

        vw_payload_auth_fail_t fail_out;
        VW_ASSERT_OK(vw_proto_decode_auth_fail(buf, len, &fail_out));
        VW_ASSERT_EQ(fail_out.error_code,             fail_in.error_code);
        VW_ASSERT_EQ(fail_out.lockout_remaining_secs, fail_in.lockout_remaining_secs);
    }

    /* ── TP-4: AUTH_CHALLENGE round-trip ───────────────────────────────── */

    VW_TEST_CASE("AUTH_CHALLENGE round-trip") {
        static const char hint[] = "Code sent to a***@example.com";
        const uint16_t hint_len  = (uint16_t)(sizeof(hint) - 1u);

        vw_payload_auth_challenge_t ch_in;
        ch_in.challenge_type = (uint8_t)VW_2FA_EMAIL_OTP;
        ch_in.hint           = hint;
        ch_in.hint_len       = hint_len;

        uint8_t buf[256];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_challenge(&ch_in, buf, sizeof(buf), &len));

        vw_payload_auth_challenge_t ch_out;
        VW_ASSERT_OK(vw_proto_decode_auth_challenge(buf, len, &ch_out));
        VW_ASSERT_EQ(ch_out.challenge_type, ch_in.challenge_type);
        VW_ASSERT_EQ(ch_out.hint_len,       hint_len);
        VW_ASSERT_MEM_EQ(ch_out.hint, hint, hint_len);
    }

    /* ── TP-5: AUTH_OTP round-trip ─────────────────────────────────────── */

    VW_TEST_CASE("AUTH_OTP round-trip") {
        static const char otp[] = "749320";

        vw_payload_auth_otp_t otp_in;
        otp_in.otp_code = otp;
        otp_in.otp_len  = 6;

        uint8_t buf[16];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_otp(&otp_in, buf, sizeof(buf), &len));

        vw_payload_auth_otp_t otp_out;
        VW_ASSERT_OK(vw_proto_decode_auth_otp(buf, len, &otp_out));
        VW_ASSERT_EQ(otp_out.otp_len, 6u);
        VW_ASSERT_MEM_EQ(otp_out.otp_code, otp, 6);
    }

    /* ── TP-6: ERROR round-trip ────────────────────────────────────────── */

    VW_TEST_CASE("ERROR round-trip") {
        static const char msg[] = "quota exceeded";
        const uint16_t msg_len  = (uint16_t)(sizeof(msg) - 1u);

        uint8_t buf[64];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_error(
            (uint32_t)VW_ERR_QUOTA_EXCEEDED, msg, msg_len,
            buf, sizeof(buf), &len));

        uint32_t code_out;
        const char *msg_out;
        uint16_t msg_len_out;
        VW_ASSERT_OK(vw_proto_decode_error(buf, len, &code_out, &msg_out, &msg_len_out));
        VW_ASSERT_EQ(code_out,    (uint32_t)VW_ERR_QUOTA_EXCEEDED);
        VW_ASSERT_EQ(msg_len_out, msg_len);
        VW_ASSERT_MEM_EQ(msg_out, msg, msg_len);
    }

    /* ── TP-7: Encode buffer too small → VW_ERR_PROTO_TOO_LARGE ─────────── */

    VW_TEST_CASE("AUTH_OK encode: buffer too small → VW_ERR_PROTO_TOO_LARGE") {
        vw_payload_auth_ok_t ok;
        memset(&ok, 0, sizeof(ok));
        uint8_t tiny[32];  /* AUTH_OK needs 65 bytes */
        uint32_t len = 0;
        VW_ASSERT_ERR(vw_proto_encode_auth_ok(&ok, tiny, sizeof(tiny), &len),
                      VW_ERR_PROTO_TOO_LARGE);
    }

    VW_TEST_CASE("AUTH_REQUEST encode: buffer too small → VW_ERR_PROTO_TOO_LARGE") {
        vw_payload_auth_request_t req;
        req.username     = "alice";
        req.username_len = 5;
        memset(req.auth_token, 0, VW_TOKEN_BYTES);
        uint8_t tiny[10];  /* needs 2 + 5 + 32 = 39 bytes */
        uint32_t len = 0;
        VW_ASSERT_ERR(vw_proto_encode_auth_request(&req, tiny, sizeof(tiny), &len),
                      VW_ERR_PROTO_TOO_LARGE);
    }

    /* ── TP-8: AUTH_OK decode truncated payload → VW_ERR_PROTO_TRUNCATED ── */

    VW_TEST_CASE("AUTH_OK decode: truncated payload → VW_ERR_PROTO_TRUNCATED") {
        uint8_t truncated[32];  /* AUTH_OK needs 65 bytes */
        memset(truncated, 0, sizeof(truncated));
        vw_payload_auth_ok_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_ok(truncated, sizeof(truncated), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-9: AUTH_OK decode trailing byte → VW_ERR_PROTO_TRUNCATED ────── */

    VW_TEST_CASE("AUTH_OK decode: trailing byte → VW_ERR_PROTO_TRUNCATED (o != len)") {
        vw_payload_auth_ok_t ok;
        memset(&ok, 0, sizeof(ok));
        uint8_t buf[256];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_ok(&ok, buf, sizeof(buf), &len));
        /* Passing len+1 triggers the o != len guard at the end of decode */
        vw_payload_auth_ok_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_ok(buf, len + 1u, &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-10: AUTH_FAIL decode truncated → VW_ERR_PROTO_TRUNCATED ─────── */

    VW_TEST_CASE("AUTH_FAIL decode: truncated payload → VW_ERR_PROTO_TRUNCATED") {
        uint8_t tiny[3];  /* AUTH_FAIL needs 6 bytes */
        memset(tiny, 0, sizeof(tiny));
        vw_payload_auth_fail_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_fail(tiny, sizeof(tiny), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-11: AUTH_REQUEST username_len = 0 rejected ─────────────────── */

    VW_TEST_CASE("AUTH_REQUEST decode: username_len = 0 → VW_ERR_PROTO_TRUNCATED") {
        /* Wire: u16_le(0) || auth_token[32] */
        uint8_t raw[2u + VW_TOKEN_BYTES];
        raw[0] = 0;
        raw[1] = 0;
        memset(raw + 2, 0x55, VW_TOKEN_BYTES);
        vw_payload_auth_request_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_request(raw, sizeof(raw), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-12: AUTH_REQUEST username_len > VW_MAX_USERNAME_BYTES rejected ─ */

    VW_TEST_CASE("AUTH_REQUEST decode: username_len = 65 → VW_ERR_PROTO_TRUNCATED") {
        /* Wire: u16_le(65) || username[65] || auth_token[32] */
        uint8_t raw[2u + 65u + VW_TOKEN_BYTES];
        raw[0] = 65;
        raw[1] = 0;
        memset(raw + 2,       'A', 65u);
        memset(raw + 2 + 65u, 0x55, VW_TOKEN_BYTES);
        vw_payload_auth_request_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_request(raw, sizeof(raw), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-13: AUTH_OTP otp_len = 0 rejected ──────────────────────────── */

    VW_TEST_CASE("AUTH_OTP decode: otp_len = 0 → VW_ERR_PROTO_TRUNCATED") {
        uint8_t raw[2] = {0, 0};
        vw_payload_auth_otp_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_otp(raw, sizeof(raw), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-14: AUTH_OTP otp_len > 8 rejected ──────────────────────────── */

    VW_TEST_CASE("AUTH_OTP decode: otp_len = 9 → VW_ERR_PROTO_TRUNCATED") {
        uint8_t raw[2u + 9u];
        raw[0] = 9;
        raw[1] = 0;
        memset(raw + 2, '1', 9u);
        vw_payload_auth_otp_t out;
        VW_ASSERT_ERR(vw_proto_decode_auth_otp(raw, sizeof(raw), &out),
                      VW_ERR_PROTO_TRUNCATED);
    }

    /* ── TP-15: write_str unsigned-underflow regression guard ───────────── */

    VW_TEST_CASE("write_str: offset > buf_size → VW_ERR_PROTO_TOO_LARGE (no underflow)") {
        uint8_t buf[8];
        uint32_t offset = 9u;  /* intentionally past the buffer end */
        /* Without the '*offset > buf_size' guard, 'buf_size - *offset' wraps
         * to a large unsigned value and the subsequent memcpy overflows. */
        VW_ASSERT_ERR(vw_proto_write_str(buf, sizeof(buf), &offset, "x", 1u),
                      VW_ERR_PROTO_TOO_LARGE);
    }

    /* ── TP-16: AUTH_OK negative expires_at round-trips via LE ─────────── */

    VW_TEST_CASE("AUTH_OK: negative expires_at round-trips correctly") {
        vw_payload_auth_ok_t ok_in, ok_out;
        memset(&ok_in,  0, sizeof(ok_in));
        memset(&ok_out, 0, sizeof(ok_out));
        ok_in.expires_at = (int64_t)-1LL;  /* sentinel: expired / epoch minus one */

        uint8_t buf[256];
        uint32_t len = 0;
        VW_ASSERT_OK(vw_proto_encode_auth_ok(&ok_in, buf, sizeof(buf), &len));
        VW_ASSERT_OK(vw_proto_decode_auth_ok(buf, len, &ok_out));
        VW_ASSERT_EQ(ok_out.expires_at, (int64_t)-1LL);
    }
}
VW_TEST_SUITE_END()
