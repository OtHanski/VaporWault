---
id:          TASK-219
title:       "Design: self-service 2FA enable/disable (no such mechanism exists today)"
status:      todo
assignee:    ARCH.00
created_by:  SRV.01
created:     2026-08-26
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [design, security-sensitive]
---

Discovered while implementing `TASK-207` (user-facing email alerts —
`account_security_change` is supposed to fire on "password changed, or
2FA enabled/disabled" per `TASK-205`'s design). Checked thoroughly before
filing, not assumed: grepped every write site of `vw_user_record_t.otp_enabled`
across the whole codebase. There is exactly one — `vw_store_user_create`
zeroing a brand-new record (`otp_enabled` starts at 0, i.e. never set to
1 anywhere). `VW_MSG_USER_MODIFY`/`_ACK` (`0x0603`/`0x0604`) exist as
reserved opcodes in `vw_proto.h` but have never had a handler implemented
anywhere (`vw_admin.c`, `vw_file_handlers.c` — neither references them).
There is no self-service *or* admin-driven way to toggle a user's 2FA
enrollment after account creation at all today.

`TASK-207` was implemented against reality rather than the design's
assumption: `account_security_change` currently fires only on a completed
password-recovery confirm (`handle_recover_confirm`, the one real
password-change site that does exist). It does not — and cannot yet —
fire for a 2FA toggle, because that event doesn't exist. This is recorded
honestly in `TASK-207`'s own notes rather than the trigger being
silently left half-implemented with no explanation, or this task's actual
missing-feature scope being quietly folded into `TASK-207` itself (a
self-service 2FA toggle is a real design decision — wire shape, whether
it requires re-authentication, whether it's exposed via `USER_MODIFY` or a
new dedicated message pair — not a one-line addition to a notification
task).

## Work

- Decide the actual mechanism: repurpose `USER_MODIFY` (already-reserved
  opcodes, would need its own payload spec — currently has none) versus a
  new dedicated `2FA_ENABLE`/`2FA_DISABLE`-style message pair. Recommend
  the latter unless a real reason favors overloading `USER_MODIFY`, since
  this is a security-sensitive, single-purpose action, not a general
  field-patch operation.
- Decide whether toggling 2FA requires re-entering the current password
  (recommended — same bar a real password change should have) versus
  being allowed on session-token authority alone.
- Once designed, file the PRT.04 (protocol spec) and SRV.01 (server
  handler) follow-up tasks, and connect `TASK-207`'s
  `vw_notify_account_security_change` call to the new handler — the
  notification-dispatch side already exists and needs no further change,
  only a real caller.

## Acceptance criteria

- A user can enable and disable their own 2FA enrollment without admin
  intervention, through some real, specified wire mechanism.
- `account_security_change` fires on both directions of that toggle.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Filed per CLAUDE.md routing rule 4 (out-of-domain
discovery — building a whole new self-service 2FA toggle mechanism is a
design decision, ARCH.00's call, not something to invent unilaterally
while implementing `TASK-207`'s notification dispatch).
