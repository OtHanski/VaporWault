---
id:          TASK-222
title:       "No wire or admin path exists to set a user's email address"
status:      todo
assignee:    ARCH.00
created_by:  QA.06
created:     2026-08-27
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [design, security-sensitive]
---

Discovered while implementing `TASK-213` (integration tests for the
email-alert system). Needed a way to give a test user a real email
address to verify a notification actually gets delivered — and found,
by checking every account-creation and account-modification path in the
codebase rather than assuming one existed, that **there is none**:

- `USER_CREATE_REQ` (admin socket, `vw_admin.h`): `is_admin`, `uname_len`,
  `uname`, `pw_len`, `pw` — no email field.
- `INVITE_CREATE`/`INVITE_REDEEM` (`docs/PROTOCOL.md` §7.6): neither
  payload has an email field either (`INVITE_REDEEM` takes `code`,
  `username`, `password_token` only).
- `USER_MODIFY`/`_ACK` (`0x0603`/`0x0604`) is a reserved opcode with
  **no handler implemented anywhere** — confirmed by grepping
  `vw_admin.c`/`vw_file_handlers.c` for it, same finding `TASK-219`
  independently made for the same opcode while investigating self-service
  2FA toggling.
- `vapourwault-server-cli user-create` (the only user-facing tool that
  wraps `USER_CREATE_REQ`) has no `--email` flag, consistent with the
  wire message having nowhere to put one.

**Practical impact, not just a testing inconvenience**: `vw_user_record_t.email`
is checked by `vw_store_user_get_by_email` (password recovery,
`AUTH_RECOVER_REQUEST`, shipped in `TASK-046`) and by `vw_notify.c`'s
`notify_send_if_enabled` (`rec.email[0] == '\0'` short-circuits every
trigger, `TASK-207`). Since no account created through either existing
path ever has a non-empty email, **both password recovery and the entire
user-facing notification system are unreachable for every real account
in this system today** — not a hypothetical edge case, the only two ways
to create an account both skip this field entirely. `tests/integration/test_notify_alerts.py`
had to patch `users.dat` directly (bypassing the product entirely, for
test purposes only, clearly marked as such) to exercise real email
delivery at all.

## Work

- Decide the actual mechanism (this needs a real design call, not a
  guess):
  - Add an optional `email` field to `USER_CREATE_REQ` (admin sets it at
    creation time) and/or `INVITE_REDEEM` (the invitee supplies their
    own) — both are plausible and not mutually exclusive.
  - And/or design and implement `USER_MODIFY` for real (admin-driven
    field patch) or a dedicated self-service "set my email" message —
    same design question `TASK-219` raised for 2FA, worth deciding
    together rather than as two unrelated one-off wire messages if the
    answer ends up being "a general self-service account-settings
    message."
- Whichever shape is chosen, publish the `docs/PROTOCOL.md` section
  before filing the SRV.01 (server) and CLI.02/GUI.03/WEB.09 (surfacing)
  follow-up tasks, per `CLAUDE.md` routing rule 3.

## Acceptance criteria

- A real admin or end user can get a non-empty, real email address onto
  an account through some documented, implemented wire mechanism —
  verified by an integration test that does NOT need to patch `users.dat`
  directly.
- `docs/PROTOCOL.md` documents the chosen mechanism's payload shape and
  permission requirements.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

QA.06 [2026-08-27]: Filed per CLAUDE.md routing rule 4 (out-of-domain
discovery — this needs a protocol/design decision, ARCH.00's call, not
something QA.06 should invent unilaterally while writing `TASK-213`'s
integration tests) after confirming, by reading every relevant handler
rather than assuming, that no such path exists anywhere in this
codebase. Marked `priority: high` rather than `low` (unlike `TASK-219`,
its closest sibling finding) because this doesn't just block a new
feature — it silently breaks an already-shipped one (`TASK-046` password
recovery) that presumably no one has ever exercised against a real
account for exactly this reason.
