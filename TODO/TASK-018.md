---
id:          TASK-018
title:       vw_proto — bump wire format to widen lockout_remaining_secs to u16
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-07-06
priority:    high
depends_on:  [TASK-015]
blocks:      [TASK-011]
review_by:   [CQR.08, SEC.07]
tags:        [protocol, phase-1, security-sensitive]
---

SEC.07 flagged during TASK-015 review that `vw_payload_auth_fail_t.lockout_remaining_secs`
is encoded as `u8` (max 255 seconds), but the standing requirement specifies a 10-minute
(600 second) OTP lockout window. After 255 seconds, the client-facing countdown would
wrap or saturate, giving clients incorrect information about when they can retry.

This is a wire-format change and requires a protocol version bump. It must be resolved
before TASK-011 (auth wire integration) picks up so that SRV.01 and CLI.02 implement
the correct wire format from the start.

## Acceptance criteria

### 1. Widen lockout_remaining_secs to u16 in the struct and wire format

In `vw_proto.h`:
```c
typedef struct {
    uint32_t error_code;
    uint16_t lockout_remaining_secs;   /* was u8; max 65535s; 0 = no lockout */
} vw_payload_auth_fail_t;
```

In `vw_proto.c`:
- `vw_proto_encode_auth_fail`: change `pw_u8` → `pw_u16` for `lockout_remaining_secs`
- `vw_proto_decode_auth_fail`: change `pr_u8` → `pr_u16` for `lockout_remaining_secs`

### 2. Add pw_u16 / pr_u16 bounded primitives if not already present

If `pw_u16` and `pr_u16` do not already exist in `vw_proto.c`, add them following the
same pattern as `pw_u8`/`pr_u8`: bounds-checked write of a little-endian u16, and
bounds-checked read of a little-endian u16.

### 3. Bump the protocol version and update docs/PROTOCOL.md

- Increment `VW_PROTO_VERSION_CURRENT` in `vw_proto.h`.
- Document the AUTH_FAIL wire-format change in `docs/PROTOCOL.md` under a new version
  section. Include: the field name, old type (u8), new type (u16), and the reason.
- Update the version negotiation logic if necessary (vw_proto_negotiate must reject
  peers advertising only the old version).

## Notes

ARCH.00 [2026-07-06]: Created from SEC.07 ADVISORY raised during TASK-015 review.
The u8 field was accepted in TASK-015 as advisory; it is upgraded to a blocking gate
for TASK-011 because SRV.01 and CLI.02 must implement a consistent wire format.
A 600-second lockout window is required; u8 cannot represent it correctly.
PRT.04 owns this change; SRV.01 and CLI.02 must not start TASK-011 until this task
is done and the protocol version is bumped.

PRT.04 [2026-07-06]: Implementation complete. The following changes were made:

1. `src/core/vw_proto.h` — `VW_PROTO_VERSION_CURRENT` bumped from 1 to 2.
   `vw_payload_auth_fail_t.lockout_remaining_secs` type changed from `uint8_t` to
   `uint16_t` (comment updated: max 65535s, 0 = no lockout).

2. `src/core/vw_proto.c` — Added `pw_u16` and `pr_u16` bounded read/write helpers
   immediately after the existing `pw_u8`/`pr_u8` pair, following the same pattern
   (bounds-checked, little-endian, using `vw_write_u16le`/`vw_read_u16le`).
   `vw_proto_encode_auth_fail`: `pw_u8` → `pw_u16` for `lockout_remaining_secs`.
   `vw_proto_decode_auth_fail`: `pr_u8` → `pr_u16` for `lockout_remaining_secs`.

3. `docs/PROTOCOL.md` — Header version updated to 2. AUTH_FAIL payload table updated
   to show `uint16` for `lockout_remaining_secs`. Version history entry added for v2
   (most-recent-first) documenting the field change and reason.

No other fields, wire layouts, or negotiation logic were changed. The existing
`vw_proto_negotiate` correctly rejects peers advertising only version 1 because it
compares against `VW_PROTO_VERSION_CURRENT` (now 2).

Requesting review from CQR.08 and SEC.07 per routing rules (security-sensitive tag).

CQR.08 [2026-07-06]: Review complete. No blocking findings.

- `pw_u16` (vw_proto.c:14-19): bounds check `*o + 2u > sz`, `vw_write_u16le`, advance offset — correct.
- `pr_u16` (vw_proto.c:44-49): bounds check `*o + 2u > sz`, `vw_read_u16le`, advance offset — correct.
- `vw_proto_encode_auth_fail` (vw_proto.c:328): `pw_u16` used — correct.
- `vw_proto_decode_auth_fail` (vw_proto.c:340): `pr_u16` used — correct.
- `lockout_remaining_secs` type in vw_proto.h:262: `uint16_t` — correct.
- `VW_PROTO_VERSION_CURRENT` = 2 — bumped as required.
- Wire size: AUTH_FAIL grows from 5 bytes (u32 + u8) to 6 bytes (u32 + u16) — a breaking
  change, correctly gated behind the version bump.

SEC.07 review required (security-sensitive tag). No CQR.08 blocking findings; TASK-018
may close once SEC.07 signs off.

SEC.07 [2026-07-06]: Review complete. No blocking findings.

The change is minimal and correct. Widening `lockout_remaining_secs` from u8 to u16 does
not introduce any security issue. The 600-second OTP lockout window is now representable
(max u16 = 65535s >> 600s). Version negotiation (vw_proto_negotiate) correctly rejects
peers speaking only protocol v1 — no downgrade path exists. CQR.08 analysis verified
independently: pw_u16/pr_u16 helpers are correctly bounded.

ARCH.00 [2026-07-06]: Closing TASK-018. Both reviewers confirmed no blocking findings.
Protocol v2 is now the current version. TASK-011 dependency on TASK-018 is satisfied.
TASK-018 is DONE.
