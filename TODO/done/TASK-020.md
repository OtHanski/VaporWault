---
id:          TASK-020
title:       Add user_id to AUTH_OK payload (protocol extension)
status:      done
assignee:    PRT.04
created_by:  CQR.08
created:     2026-07-07
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [protocol, auth, phase-1, security-sensitive]
---

`vw_client_user_id_of()` always returns 0 because `PROTOCOL.md §7.1` does not include
`user_id` in the AUTH_OK payload.  Every consumer of the session's user identity
(admin operations, file sharing, GUI "logged in as") receives 0 silently.

This is a blocking finding (CQR.08-B-2) against TASK-011.  TASK-011 cannot move to
`done` until this task is complete and CQR.08 clears the finding.

## Acceptance criteria

- `docs/PROTOCOL.md §7.1` updated: AUTH_OK payload includes `user_id: uint64` (LE)
  appended after `used_bytes`; spec version bumped.
- `build_and_send_auth_ok` in `src/server/vw_server_core.c` sets `ok.user_id = user_id`.
- `recv_auth_result` in `src/client/vw_client_core.c` reads and stores `ok.user_id`
  into `sess->user_id`.
- `vw_client_user_id_of()` returns the correct value in TC-1 and TC-3 of the
  integration test (`tests/integration/test_auth_handshake.c`).
- Placeholder comment removed from `vw_client_user_id_of` declaration in
  `src/client/vw_client_core.h`.

## Security notes

SEC.07: `user_id` is already known to the authenticated client; including it in AUTH_OK
does not expand the information surface.  Confirm that `user_id` is not a secret value
that should be withheld from the session owner.

## Notes

CQR.08 [2026-07-07]: Created from review of TASK-011.  The server already passes
`user_id` to `build_and_send_auth_ok`; the gap is in the protocol encoding and client
parsing only.  Scope is small — same files as TASK-011.

PRT.04 [2026-07-10]: Implementation complete.  Changes applied:
- `docs/PROTOCOL.md §7.1`: `user_id | uint64` row appended to AUTH_OK table; version
  header updated to 3; §11 version history entry added.
- `src/core/vw_proto.h`: `uint64_t user_id` added to `vw_payload_auth_ok_t`;
  `VW_PROTO_VERSION_CURRENT` bumped to 3.
- `src/core/vw_proto.c`: `pw_u64(... user_id)` added to `vw_proto_encode_auth_ok`;
  `pr_u64(... user_id)` added to `vw_proto_decode_auth_ok` (before the `o != len` check).
- `src/server/vw_server_core.c`: `ok.user_id = user_id` set in
  `build_and_send_auth_ok`; `buf[64]` → `buf[72]` (65 bytes encoded, 72 for alignment).
- `src/client/vw_client_core.c`: `sess->user_id = ok.user_id` populated in both
  `recv_auth_result` (SESSION_RESUME / 2FA path) and the inline AUTH_OK branch of
  `vw_client_connect` (direct login path).
- `src/client/vw_client_core.h`: placeholder NOTE comment removed from
  `vw_client_user_id_of` declaration.
- `tests/integration/test_auth_handshake.c`: `VW_ASSERT_EQ(vw_client_user_id_of(sess),
  test_uid)` added to TC-1 (login) and TC-3 (SESSION_RESUME).
SEC.07 [2026-07-10]: Review complete. No blocking or advisory findings.

`user_id` is the session owner's own database identifier; returning it in AUTH_OK
does not expand the information surface beyond what the user already controls.  The
value originates in the server's auth store, not from any client-supplied field, so
there is no injection risk.  The version bump (2 → 3) is correct and necessary:
the `vw_proto_negotiate` function rejects clients whose `max_version < 3`, preventing
a v2 client from receiving a 65-byte AUTH_OK it would attempt to parse as the old
57-byte format.  Even without the negotiate gate, a v2 decoder would fail safely at
the `pr_u64` call for `user_id` (returns `VW_ERR_PROTO_TRUNCATED`) or the `o != len`
check (trailing bytes).  No new attack surface is introduced.

SEC.07 clears the security review for TASK-020. ✓

CQR.08 [2026-07-10]: Review complete. No blocking findings.

Encode and decode are symmetric and follow the established `pw_u64`/`pr_u64` pattern.
The new `pr_u64` for `user_id` is correctly placed before the `o != len` length check.
`buf[72]` in `build_and_send_auth_ok` is ample (65 bytes encoded); comment updated to
reflect the new arithmetic.  Both AUTH_OK decode paths in the client are updated
(`recv_auth_result` for SESSION_RESUME/2FA and the inline branch of `vw_client_connect`
for direct login).  Test assertions use `VW_ASSERT_EQ` with both sides typed `uint64_t`.
`VW_PROTO_VERSION_CURRENT` correctly bumped; `PROTOCOL.md` header and §11 both updated.

CQR.08-B-2 is cleared.  TASK-011 may now proceed to `done`. ✓
