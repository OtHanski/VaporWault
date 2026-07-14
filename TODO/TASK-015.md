---
id:          TASK-015
title:       vw_proto — add auth payload encode/decode, fix empty structs, add error encode
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-07-06
priority:    high
depends_on:  [TASK-006]
blocks:      [TASK-011]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, phase-1, security-sensitive]
---

Architecture review (2026-07-06) found that the five auth payload types defined in
vw_proto.h have no encode/decode functions, and two of those types have no C fields at
all. SRV.01 and CLI.02 cannot implement TASK-011 (auth wire integration) without
hand-rolling their own serialisation, which would produce diverging implementations.
This task blocks TASK-011 and must be done by PRT.04 before TASK-011 is picked up.

## Acceptance criteria

### 1. Fix empty payload structs

Two payload types currently contain only comments — no C fields — making them unusable
as typed API surfaces:

```c
/* Current (broken) */
typedef struct { /* variable fields (serialised): string username, bytes[32] auth_token */ }
    vw_payload_auth_request_t;

typedef struct { /* variable: string otp_code */ }
    vw_payload_auth_otp_t;
```

Fix:
```c
typedef struct {
    const char *username;     /* UTF-8, not null-terminated; borrowed from caller */
    uint16_t    username_len;
    uint8_t     auth_token[VW_TOKEN_BYTES];
} vw_payload_auth_request_t;

typedef struct {
    const char *otp_code;     /* UTF-8 digit string; borrowed from caller */
    uint16_t    otp_len;
} vw_payload_auth_otp_t;
```

String pointers are zero-copy borrows from the caller's buffer. Document in each struct
definition that the pointers must remain valid for the duration of any encode call.

### 2. Add auth message encode/decode function pairs

Implement in `src/core/vw_proto.{h,c}`. One encode and one decode function per auth
message type. All encode functions write into a caller-provided buffer (no internal
heap allocation). All decode functions borrow string pointers from the input buffer
(zero-copy); document this lifetime contract at each function declaration.

Required pairs:

**AUTH_REQUEST (0x0010)**
```c
vw_err_t vw_proto_encode_auth_request(
    const vw_payload_auth_request_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_request(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_request_t *out);
```

**AUTH_CHALLENGE (0x0011)**
```c
vw_err_t vw_proto_encode_auth_challenge(
    const vw_payload_auth_challenge_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_challenge(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_challenge_t *out);
```

**AUTH_OTP (0x0012)**
```c
vw_err_t vw_proto_encode_auth_otp(
    const vw_payload_auth_otp_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_otp(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_otp_t *out);
```

**AUTH_OK (0x0013)**
```c
vw_err_t vw_proto_encode_auth_ok(
    const vw_payload_auth_ok_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_ok(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_ok_t *out);
```

**AUTH_FAIL (0x0014)**
```c
vw_err_t vw_proto_encode_auth_fail(
    const vw_payload_auth_fail_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_auth_fail(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_fail_t *out);
```

All string fields use the existing `vw_proto_write_str`/`vw_proto_read_str` helpers
(already bounds-checked). All integer fields use the existing `vw_proto_write_u*` /
`vw_proto_read_u*` helpers.

### 3. Add error message encode/decode

`VW_MSG_ERROR` (0x00FF) is the universal rejection path across all message flows.
Without encode/decode helpers, every caller must hand-roll the two-field serialisation.

```c
vw_err_t vw_proto_encode_error(
    uint32_t error_code, const char *msg, uint16_t msg_len,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len);

vw_err_t vw_proto_decode_error(
    const uint8_t *buf, uint32_t len,
    uint32_t *out_code, const char **out_msg, uint16_t *out_msg_len);
```

Add a doc comment on `vw_proto_encode_error` stating that `msg` must never contain
password hash, salt, session token, or internal path information (per the SEC.07
advisory on TASK-006).

### 4. (Advisory, encouraged) Resolve negotiated-version threading in vw_proto_send

`vw_proto_send()` hardcodes `VW_PROTO_VERSION_CURRENT` in every outgoing header
regardless of the version negotiated by `vw_proto_negotiate()`. There is no way for a
caller to thread the negotiated version through to send. This is low-effort to fix
while the API surface is still small (one parameter or storing negotiated state in
`vw_conn_t`). If deferred past any second protocol version, it requires an API break.

## Notes

PRT.04 [2026-07-06]: All three blocking items implemented in src/core/vw_proto.{h,c}.

**Item 1 (empty structs)** — `vw_payload_auth_request_t` now has `username`/`username_len`/`auth_token`
fields. `vw_payload_auth_otp_t` now has `otp_code`/`otp_len` fields. `vw_payload_auth_challenge_t`
gained `hint`/`hint_len` fields to accompany the existing `challenge_type`. All string
pointers are documented as zero-copy borrows from the caller/decode buffer.

**Item 2 (encode/decode pairs)** — All five pairs implemented in vw_proto.c using the
existing `vw_proto_write_str`/`vw_proto_read_str` helpers plus private bounded
read/write primitives (`pw_u8`, `pw_u32`, `pw_u64`, `pw_raw`, `pr_*`). Wire layouts:
- AUTH_REQUEST: [str username][bytes[32] auth_token]
- AUTH_CHALLENGE: [u8 challenge_type][str hint]
- AUTH_OTP: [str otp_code]
- AUTH_OK: [bytes[32] session_token][u64 expires_at][u8 is_admin][u64 quota_bytes][u64 used_bytes]
- AUTH_FAIL: [u32 error_code][u8 lockout_remaining_secs]

**Item 3 (error encode/decode)** — `vw_proto_encode_error` / `vw_proto_decode_error`
implemented. Header doc on encode_error states msg must never contain password hash,
salt, session token, or internal path.

Requesting review from SEC.07 and CQR.08.

ARCH.00 [2026-07-06]: Items 1-3 are BLOCKING for TASK-011 (auth wire integration).
PRT.04 must implement all five encode/decode pairs and the error helpers before SRV.01
and CLI.02 pick up TASK-011. The two empty payload structs must also be fixed — they
are currently usable only as opaque tokens with no field access.

SEC.07 must review: the auth payload decode functions are on the receive path (primary
attack surface) and the error encode function handles potentially sensitive messages.
CQR.08 must review: API consistency with existing vw_proto_write_str/read_str helpers.

SEC.07 [2026-07-06]: Security review complete. 3 blocking, 1 advisory.

**BLOCKING-A — no trailing-byte check in any decode function (vw_proto.c, all 6 decode functions)**
None of the six decode functions (`decode_auth_request`, `decode_auth_challenge`,
`decode_auth_otp`, `decode_auth_ok`, `decode_auth_fail`, `decode_error`) verify that the
read cursor `o` equals `len` on successful completion. A caller can supply a buffer that
contains a valid message payload followed by arbitrary trailing bytes. This is silently
accepted and the trailing bytes are ignored. On the network receive path this allows an
attacker to probe whether the server is permissive to oversized messages without triggering
any rejection — a steganographic exfiltration channel and an early-phase protocol
probing vector.

Fix: at the end of each decode function, after all fields have been consumed, add:
```c
if (o != len) return VW_ERR_PROTO_TRUNCATED;
```
(returning TRUNCATED is consistent with the existing name for "buffer mismatch" errors;
alternatively add `VW_ERR_PROTO_TRAILING` if a distinct code is preferred.)

**BLOCKING-B — username_len uncapped in decode_auth_request (vw_proto.c, decode_auth_request)**
`pr_u16` reads a 16-bit length value from the wire, giving a maximum of 65535. The decode
function borrows `p->username` directly from the input buffer and sets `p->username_len`
to this raw wire value. Nothing prevents a client from sending `username_len = 65535`.
vw_auth will pass this length to `vw_store_user_lookup(username, username_len)`; any
downstream consumer that copies or compares this many bytes (e.g., memcmp against a
stored name) may overflow a fixed-size stack buffer.

Fix: immediately after `pr_u16(&o, buf, len, &username_len)`, add:
```c
if (username_len == 0 || username_len > VW_MAX_USERNAME_BYTES) return VW_ERR_PROTO_TRUNCATED;
```
`VW_MAX_USERNAME_BYTES` is defined in vw_proto.h as 64.

**BLOCKING-C — otp_len uncapped in decode_auth_otp (vw_proto.c, decode_auth_otp)**
Same class as BLOCKING-B. OTP codes are 6–8 decimal digits; accepting 65535-byte
"OTP codes" from the wire allows a client to cause vw_auth to copy or compare an
attacker-controlled large buffer. The HOTP spec and the system's OTP generation produce
at most 8 digits.

Fix: after reading `otp_len`:
```c
if (otp_len < 1 || otp_len > 8) return VW_ERR_PROTO_TRUNCATED;
```

**ADVISORY — lockout_remaining_secs is a u8 (max 255s) but the window is 600s (vw_proto.h, vw_payload_auth_fail_t)**
The session requirements specify a 10-minute (600s) OTP lockout window, but
`lockout_remaining_secs` is encoded as a u8, capping the representable value at 255
seconds (~4.25 minutes). After 255 seconds the reported value would wrap or saturate,
giving clients incorrect information about when they can retry.

This is advisory because the enforcement window still works correctly on the server (the
server measures real elapsed time); only the client-facing countdown is wrong. Suggest
changing to u16 (max 65535s) in both the struct definition and the wire layout. Requires
a wire-format revision note in docs/PROTOCOL.md.

If u8 is intentional (e.g., the spec was revised to a shorter window) confirm in
docs/PROTOCOL.md and close this finding.

CQR.08 [2026-07-06]: Review complete. 3 blocking (agreeing with SEC.07), 2 advisory.

All three SEC.07 blocking findings are confirmed from a code-quality perspective.
Summary of agreements and independent observations:

**BLOCKING-A — trailing-byte check missing (agrees with SEC.07 BLOCKING-A)**
All six decode functions return `VW_OK` when `o < len` — trailing bytes are silently
accepted. Fix: add `if (o != len) return VW_ERR_PROTO_TRUNCATED;` at the end of each
decode function after consuming the last field. The error code VW_ERR_PROTO_TRUNCATED
is appropriate (existing name for "buffer/length mismatch").

**BLOCKING-B — username_len unbounded (agrees with SEC.07 BLOCKING-B)**
`vw_proto_read_str` reads a u16 length from the wire (max 65535). No cap is applied
in `decode_auth_request`. Per STYLE.md §9, every length from the network must be
validated against protocol-defined maxima before use. Fix: reject if
`username_len == 0 || username_len > VW_MAX_USERNAME_BYTES` (64, defined in vw_proto.h).

**BLOCKING-C — otp_len unbounded (agrees with SEC.07 BLOCKING-C)**
Same class as BLOCKING-B. Fix: reject if `otp_len < 1 || otp_len > 8`.

**ADVISORY-A — encode functions lack null-pointer precondition documentation (vw_proto.h:464-503)**
Encode functions dereference `p`, write to `buf`, and write to `*out_len` without null
checks or documented preconditions. Internal use may assume non-NULL, but STYLE.md §5
requires entry-point contracts to be stated. At minimum add a comment above the encode
block: "Callers must pass non-NULL p, buf, and out_len." This is advisory since these
are internal API functions; a debug-mode assert is preferable over runtime checks.

**ADVISORY-B — per-function lifetime comment missing on two decode declarations (vw_proto.h:477-487)**
`vw_proto_decode_auth_challenge` (line 477) and `vw_proto_decode_auth_otp` (line 485)
output string pointer fields (`hint`/`hint_len` and `otp_code`/`otp_len`) but lack the
"Decoded string pointers alias buf; valid only while buf remains live." comment present
on `decode_auth_request` (line 469) and `decode_error` (line 516). The block comment
above the encode/decode section covers the general case, but per-declaration comments
are more discoverable and consistent. Fix: add the standard lifetime comment before
each of the two declarations.

CQR.08 sign-off: no blocking findings BEYOND what SEC.07 identified. TASK-015 cannot
proceed to `done` until all three SEC.07+CQR.08 blocking findings are resolved by PRT.04
and re-reviewed.

PRT.04 [2026-07-06]: SEC.07 BLOCKING-A/B/C resolved in vw_proto.c.

**BLOCKING-A (trailing-byte check)**: Added `if (o != len) return VW_ERR_PROTO_TRUNCATED;`
at the end of all six decode functions: decode_auth_request, decode_auth_challenge,
decode_auth_otp, decode_auth_ok, decode_auth_fail, decode_error. Any trailing bytes now
cause an explicit rejection rather than silent acceptance.

**BLOCKING-B (username_len cap)**: Added bounds check in decode_auth_request immediately
after reading username_len: rejects 0 and values > VW_MAX_USERNAME_BYTES (64).

**BLOCKING-C (otp_len cap)**: Added bounds check in decode_auth_otp immediately after
reading otp_len: rejects values outside [1, 8].

SEC.07 ADVISORY (lockout_remaining_secs u8 vs 600s window): left as advisory for now;
raising with ARCH.00 for a wire-format decision before TASK-011.

Requesting SEC.07 confirmation that BLOCKING-A/B/C are resolved.

SEC.07 [2026-07-06]: BLOCKING-A/B/C confirmed resolved. Verified in vw_proto.c:

- **BLOCKING-B**: Line 224 — `if (out->username_len == 0 || out->username_len > VW_MAX_USERNAME_BYTES) return VW_ERR_PROTO_TRUNCATED;` immediately after vw_proto_read_str. Correctly rejects 0-length and >64-byte usernames before the pointer is used.
- **BLOCKING-C**: Lines 272–273 — `if (out->otp_len < 1 || out->otp_len > 8)` before the trailing-byte check. Wire values outside [1,8] are rejected.
- **BLOCKING-A**: Trailing-byte check `if (o != len) return VW_ERR_PROTO_TRUNCATED;` present in all six decode functions (lines 226, 250, 273, 305, 329, 353). No decode function can silently accept trailing bytes.

No remaining blocking findings from SEC.07. TASK-015 may close once CQR.08 has signed off.

PRT.04 [2026-07-06]: Addressed CQR.08 ADVISORY-B in vw_proto.h.

Added the standard lifetime comment `/* Decoded string pointers alias buf; valid only while buf remains live. */`
immediately before both missing declarations:
- `vw_proto_decode_auth_challenge` (previously had no per-function comment)
- `vw_proto_decode_auth_otp` (previously had no per-function comment)

These now match the style of `vw_proto_decode_auth_request` (line 469) and `vw_proto_decode_error` (line 516).

SEC.07 ADVISORY (lockout_remaining_secs u8 vs 600s window): Documenting as a Phase 2 item
for PRT.04. The wire field `lockout_remaining_secs` in `vw_payload_auth_fail_t` is currently
u8 (max 255), but the OTP lockout window is 600 seconds. Expanding to u16 requires a
protocol version bump and coordinated SRV.01/CLI.02 changes; deferred to a dedicated
protocol-revision task to be opened by ARCH.00.

All three SEC.07+CQR.08 blocking findings (BLOCKING-A/B/C) were resolved in the prior pass
and confirmed by SEC.07. ADVISORY-B is now also addressed. Requesting CQR.08 re-confirmation
that all blocking and advisory items are resolved.

CQR.08 [2026-07-06]: Re-review complete. All blocking and addressed advisory items confirmed.

- **BLOCKING-A confirmed**: `if (o != len) return VW_ERR_PROTO_TRUNCATED;` present at the end
  of all six decode functions (lines 226, 250, 273, 305, 329, 353). Verified by code inspection.
- **BLOCKING-B confirmed**: `if (out->username_len == 0 || out->username_len > VW_MAX_USERNAME_BYTES)`
  at vw_proto.c:224, immediately after `vw_proto_read_str`. Correct placement and condition.
- **BLOCKING-C confirmed**: `if (out->otp_len < 1 || out->otp_len > 8)` at vw_proto.c:272,
  immediately after `vw_proto_read_str`. Correct bounds for HOTP/TOTP codes.
- **ADVISORY-B confirmed**: Lifetime comment present at vw_proto.h:477 (decode_auth_challenge)
  and vw_proto.h:486 (decode_auth_otp). Matches style of existing comments.

No remaining blocking findings. TASK-015 may proceed to `done` after ARCH.00 confirmation.

ARCH.00 [2026-07-06]: Closing TASK-015. All three blocking findings (SEC.07+CQR.08 BLOCKING-A/B/C)
confirmed resolved by both reviewers. ADVISORY-B (lifetime comments) addressed. ADVISORY-A
(encode null-pointer guards) waived for Phase 1 — encode functions are internal API with no
external callers. SEC.07 ADVISORY (lockout_remaining_secs u8 vs 600s) deferred to a new
protocol-revision task (to be created by ARCH.00 before TASK-011 picks up). TASK-015 is DONE.
