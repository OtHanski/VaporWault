---
id:          TASK-044
title:       Protocol spec — invite token and password recovery wire payloads
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-07-12
priority:    normal
depends_on:  []
blocks:      [TASK-045, TASK-046]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, phase-6, security-sensitive]
---

Document the wire payload formats for the invite-token and password-recovery
message types in `docs/PROTOCOL.md`. Message type constants already exist in
`vw_proto.h`; this task specifies their payloads so SRV.01 can implement them.

## Acceptance criteria

### 1. Invite messages (already in vw_proto.h)

Document byte-level payloads for:

| Message | Direction | Type constant |
|---------|-----------|---------------|
| `INVITE_CREATE` | admin → server | `0x0609` |
| `INVITE_CREATE_ACK` | server → admin | `0x060A` |
| `INVITE_REDEEM` | client → server | `0x060B` |
| `INVITE_REDEEM_ACK` | server → client | `0x060C` |

Design notes:
- Invite code: 128-bit random, base32 encoded → 26-character printable string.
- `INVITE_CREATE` payload: `quota_bytes` (u64 LE) + `ttl_secs` (u32 LE, 0 = no
  expiry). Server assigns the code and returns it in `INVITE_CREATE_ACK`.
- `INVITE_CREATE_ACK` payload: `code[26]` (ASCII, NUL-padded to 26).
- `INVITE_REDEEM` payload: `code[26]` + `username[64]` + `password_token[32]`
  (already-stretched client side, same as `AUTH_REQUEST`).
- `INVITE_REDEEM_ACK` payload: same as `AUTH_OK` (`session_token[32]`).
- Redeeming an already-used or expired invite → `AUTH_FAIL` (reason = invalid).

### 2. Password recovery messages (new — add to vw_proto.h)

Add two new message type constants and document their payloads:

| Message | Type | Direction |
|---------|------|-----------|
| `AUTH_RECOVER_REQUEST` | `0x0108` | client → server |
| `AUTH_RECOVER_CONFIRM` | `0x0109` | client → server |
| `AUTH_RECOVER_OK` | `0x010A` | server → client |
| `AUTH_RECOVER_FAIL` | `0x010B` | server → client |

Design notes:
- `AUTH_RECOVER_REQUEST` payload: `email[128]` (NUL-padded). Server emails a
  one-time code (6-digit numeric, 10-minute expiry). Rate-limit: max 3
  requests per email per hour → `AUTH_RECOVER_FAIL` (reason = rate_limited).
- `AUTH_RECOVER_CONFIRM` payload: `email[128]` + `code[8]` (NUL-padded 6-digit
  ASCII) + `new_password_token[32]`. Server resets password, logs out all
  existing sessions, responds with `AUTH_RECOVER_OK`.
- `AUTH_RECOVER_OK` payload: empty (0 bytes).
- `AUTH_RECOVER_FAIL` payload: `reason` (u8, 0 = invalid_code, 1 = expired,
  2 = rate_limited, 3 = unknown_email — all reasons use the same generic
  message to prevent email enumeration).

**SEC.07**: The generic failure reason for unknown_email is mandatory.
Revealing whether an email is registered leaks the user list.

### 3. Protocol version

These messages are new in **protocol v5**. Bump `VW_PROTO_VERSION` in
`vw_proto.h` from 4 to 5 and document the change in `docs/PROTOCOL.md`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-12]: Invite message types (0x0609–0x060C) already exist in
vw_proto.h from Phase 1 design; their payloads were never formally documented.
Recovery message types (0x0108–0x010B) are new in Phase 6. PRT.04 must update
both docs/PROTOCOL.md and vw_proto.h (for the recovery constants and the
version bump) before TASK-045 and TASK-046 can begin.

PRT.04 [2026-07-12]: Implementation complete.
- `src/core/vw_proto.h` — added VW_MSG_AUTH_RECOVER_REQUEST (0x0108),
  VW_MSG_AUTH_RECOVER_CONFIRM (0x0109), VW_MSG_AUTH_RECOVER_OK (0x010A),
  VW_MSG_AUTH_RECOVER_FAIL (0x010B); bumped VW_PROTO_VERSION_CURRENT to 5.
- `docs/PROTOCOL.md` — current version header updated to 5; AUTH_RECOVER_*
  entries added to §7.1 auth table with full payload specs; AUTH_RECOVER_REQUEST
  uses fixed bytes[128] for email (timing uniformity); AUTH_RECOVER_FAIL reason
  is always 0 to prevent email enumeration; INVITE_CREATE/ACK/REDEEM/ACK payload
  specs published in §7.6; version 5 entry added to §11 version history.

SEC.07 [2026-07-12]: Spec reviewed. AUTH_RECOVER_FAIL reason-always-0 rule is
correctly mandated and implemented. INVITE_REDEEM payload layout (code[26] +
username[64] + password_token[32] = 122 bytes) fits comfortably within
AUTH_BUF_SIZE (256). Protocol version bump to v5 is correct. No blocking
findings in the spec itself. **SEC.07 sign-off granted.**

CQR.08 [2026-07-12]: ADVISORY — The rate-limit description in this spec says
"max 3 requests per email per hour" but SRV.01's implementation (TASK-046)
enforces "max 3 unexpired recovery records" with a 10-minute TTL. The
effective window is 10 minutes, not 60 — the implementation is tighter than
the spec. Both are safe, but the spec is imprecise. Recommend updating
`docs/PROTOCOL.md` to say "3 concurrent unexpired requests (each valid 10 min)"
rather than "3 per hour". TASK-044 body should be updated in a follow-up
cleanup PR; does not block Phase 6.

CQR.08 [2026-07-12]: ADVISORY — AUTH_RECOVER_REQUEST spec says rate-limited
requests return `AUTH_RECOVER_FAIL(reason=rate_limited)` but the implementation
silently returns `AUTH_RECOVER_OK` to avoid confirming the user is registered
and being rate-limited. The implementation is more secure. Spec should reflect
the silent-OK behaviour; update docs/PROTOCOL.md in the same cleanup PR.

CQR.08 [2026-07-12]: No blocking findings. Payload sizes, type constants, and
version history are all consistent. **CQR.08 sign-off granted.**

ARCH.00 [2026-07-12]: All reviewers signed off. Advisory spec clarifications
(rate-limit window semantics, silent-OK vs RECOVER_FAIL for rate-limited
requests) to be addressed in a follow-up docs-only task. Task marked done.
