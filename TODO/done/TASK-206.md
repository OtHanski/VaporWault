---
id:          TASK-206
title:       "Protocol: NOTIFY_PREFS_GET / NOTIFY_PREFS_SET"
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-205]
blocks:      [TASK-207, TASK-209]
review_by:   [CQR.08]
tags:        [protocol]
---

Publishes the wire side of `TASK-205`'s user-category notification
preferences. Admin categories are server-config-only (`TASK-208`) and do
not need a wire message.

## Work

- New opcode pair `NOTIFY_PREFS_GET`/`NOTIFY_PREFS_GET_RESP` and
  `NOTIFY_PREFS_SET`/`NOTIFY_PREFS_SET_ACK` (next free opcode block,
  following this project's numbering convention).
- Preferences represented as a bitmask (one bit per category:
  `share_received`, `quota_warning`, `new_login`,
  `account_security_change`) so adding a category later is a new bit,
  not a new message — same additive spirit as every other bitmask/flags
  field already in this protocol.
- `NOTIFY_PREFS_GET`: no payload (operates on the caller's own session/
  user record — never another user's, no `user_id` parameter).
  `NOTIFY_PREFS_GET_RESP`: the bitmask.
- `NOTIFY_PREFS_SET`: the new bitmask. `NOTIFY_PREFS_SET_ACK`: confirmation.
- Permission section: `NOTIFY_PREFS_GET`/`_SET` require only "an
  authenticated, non-scoped session" (same bar as changing your own
  password) — no `VW_PERM_*` file-permission concept applies here since
  this isn't a file operation.
- Error codes: reuse `VW_ERR_INVALID_ARG` for an unrecognized bit
  pattern (reserved/future bits set) rather than silently ignoring them.

## Acceptance criteria

- SRV.01 and CLI.02 can implement against this section without further
  clarification.
- No existing message's byte layout changes.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

PRT.04 [2026-08-26]: Published `docs/PROTOCOL.md` §7.13 and bumped the
document revision counter (24) and header. New opcode block `0x0A01`-
`0x0A04` (`NOTIFY_PREFS_GET`/`_GET_RESP`/`SET`/`_SET_ACK`) — the first use
of the `0x0A` high byte, following directly after `0x09` (filename
search, `TASK-197`).

- Bitmask: bit 0 `share_received`, bit 1 `quota_warning`, bit 2
  `new_login`, bit 3 `account_security_change`; bits 4-31 reserved.
  `NOTIFY_PREFS_SET` replaces the whole bitmask (not a per-bit toggle) —
  simplest wire shape; a client wanting to flip one category does
  GET → flip locally → SET, documented explicitly so `CLI.02` doesn't have
  to guess at the intended pattern.
- Reserved bits in a `SET` request are rejected with `VW_ERR_INVALID_ARG`,
  per this task's own instruction — documented the one real tradeoff of
  that choice (a mixed-version client/daemon pair can't round-trip a bit
  neither end recognizes) rather than silently picking it without
  comment.
- Added `VW_MSG_NOTIFY_PREFS_GET`/`_GET_RESP`/`SET`/`_SET_ACK` and the
  `VW_NOTIFY_*` bit-flag `#define`s to `src/core/vw_proto.h`, matching the
  precedent `TASK-197` set (enum constants published alongside the spec,
  ahead of the server/client implementation tasks) rather than leaving
  `TASK-207`/`209` to invent the numeric values themselves.
- No `user_id` field on either request — confirmed by design, not by
  omission: this is deliberately impossible to point at another account,
  matching `TASK-205`'s "same trust bar as changing your own password"
  requirement.
- Storage note added to §7.13 pointing `TASK-207` at a new `notify_prefs`
  `uint32` field on `vw_user_record_t`, mirroring the existing
  `otp_enabled` flag's precedent, so the server task doesn't have to
  re-derive where this lives.
- No existing message's byte layout changed; no wire version bump
  required (document-revision bump only, same as every other purely
  additive change in this table).

**Testing**: `cmake --build build-gw-e2e --target vw_core` (WSL/GCC) —
clean compile of `vw_proto.h`'s new enum/macro additions. No runtime
behavior yet (that's `TASK-207`); nothing to unit-test at the protocol-spec
stage beyond "it compiles" and "the doc is internally consistent."

Moving to `review`.

CQR.08 [2026-08-26]: Reviewed for consistency with existing protocol
conventions.

- Opcode block placement (`0x0A01`+, directly after search's `0x09`) and
  naming (`_GET_RESP`/`_SET_ACK` suffix convention) match every prior
  additive message pair in this document.
- The bitmask/reserved-bit-rejection design is internally consistent
  between `docs/PROTOCOL.md` §7.13 and `vw_proto.h`'s new `#define`s —
  spot-checked the bit values in both places match exactly (0x01/0x02/
  0x04/0x08).
- `VW_NOTIFY_ALL_KNOWN` as an OR of the four defined bits is a reasonable
  addition (not asked for explicitly, but a natural, low-risk helper for
  `TASK-207`'s validation check) rather than scope creep — a single macro,
  directly useful for the very next task in the chain.
- Confirmed no existing opcode or `#define` collides with the new ones
  (`0x0A01`-`0x0A04` were unused; grepped for `VW_NOTIFY_` beforehand).
- No blocking findings. Approved.