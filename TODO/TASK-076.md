---
id:          TASK-076
title:       AUTH_OK always reports quota_bytes=0 and used_bytes=0 (hardcoded stub, never populated from store)
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-19
priority:    high
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [bug, ci, quota]
---

Discovered while verifying TASK-073 end-to-end against the full pytest
integration suite (not part of TASK-073's own scope — filed separately per
CLAUDE.md's out-of-domain/out-of-task-scope discovery rule; noted in
TASK-073's notes pending ARCH.00 triage).

## Symptom

`tests/integration/test_quota.py::test_used_bytes_does_not_increase_after_delete`
uploads a 4 KiB file, then re-logs-in and asserts
`info_after_upload["used_bytes"] > 0` (the login response's reported usage
should reflect the just-uploaded chunk). The assertion fails: `used_bytes`
is `0` immediately after a real upload.

## Root cause (grep-verified, found in the AUTH_OK builder, not the upload path)

`build_and_send_auth_ok` (`src/server/vw_server_core.c:64-100`), called by
both `handle_auth_request` and `handle_session_resume` to build every
`AUTH_OK` response, hardcodes both quota fields instead of reading them
from the store:

```c
vw_payload_auth_ok_t ok;
memcpy(ok.session_token, token, VW_TOKEN_BYTES);
ok.expires_at  = (int64_t)sess_rec.expires_at;
ok.is_admin    = user_rec.is_admin;
ok.quota_bytes = 0;  /* TODO(SRV.01): populate from vw_store_quota_get */
ok.used_bytes  = 0;
ok.user_id     = user_id;
```
(`vw_server_core.c:80-83`)

The `TODO(SRV.01)` comment is already there and names the exact function
to call. `vw_store_quota_get(vw_store_t *ctx, uint64_t user_id,
vw_quota_record_t *out)` (`src/server/vw_store.h:382-383`) already exists
and is already used correctly elsewhere for exactly this purpose —
compare `src/server/vw_file_handlers.c:1097-1100` (`ADMIN_USER_LIST`-style
handler) and `src/server/vw_admin.c:220-242` (admin user-list response),
both of which call `vw_store_quota_get`-equivalent lookups and populate
`quota_bytes`/`used_bytes` correctly into their respective wire responses.
`build_and_send_auth_ok` is the one caller that never got wired up to it —
this looks like a stub left over from initial AUTH_OK scaffolding
(payload-encoding plumbed and the TODO comment already placed) that was
never followed up.

This is **not** a quota-accounting/GC bug — i.e. it is unrelated to the
test's actual GC-liveness scenario. `vw_store_quota_adjust`
(`src/server/vw_store.c:1580-1595`, referenced in its header doc at
`vw_store.h:393-399`) appears to correctly track `used_bytes` internally
(increment on upload with over-quota check, decrement on delete/GC,
clamped to 0) — `test_upload_fails_when_quota_exceeded` and
`test_quota_adjust_allows_upload` (same file) both pass, which depends on
enforcement actually working against the real stored counter. The bug is
purely that **the login response never reads that counter** — confirm
this during implementation by checking whether the underlying store value
is actually correct via the admin socket's `oplog_tail`/user-list path
(which does read it correctly per above) before and after the upload, to
positively rule out a deeper accounting bug rather than just assuming the
`AUTH_OK` builder is the sole defect.

## Suggested fix

In `build_and_send_auth_ok` (`vw_server_core.c:64-100`), call
`vw_store_quota_get(ctx->store, user_id, &quota_rec)` and populate
`ok.quota_bytes = quota_rec.quota_bytes;` /
`ok.used_bytes = quota_rec.used_bytes;` in place of the two hardcoded
`0`s — mirroring the pattern already used in `vw_file_handlers.c:1097-1100`
and `vw_admin.c:220-242`. Check `vw_store_quota_get`'s documented behavior
for a user with no quota record yet (`vw_store.h:380`: "record exists
(meaning: quota = unlimited, used_bytes = 0)") and handle its return value
the same way those two existing call sites do, rather than assuming it
always succeeds.

## Acceptance criteria

- `AUTH_OK` (both the `AUTH_REQUEST` and `SESSION_RESUME` paths, since
  both call `build_and_send_auth_ok`) reports the user's real
  `quota_bytes`/`used_bytes` from the store, not `0`/`0`.
- `test_quota.py::test_used_bytes_does_not_increase_after_delete` passes.
- No regression in `test_upload_fails_when_quota_exceeded` /
  `test_quota_adjust_allows_upload` (both already passing; confirm they
  still pass since they share the same quota-record read path).
- Full pytest integration suite passes locally (or in CI) against the real
  server binary for this test.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Filing per SRV.01's note in TASK-073 (found while
running the full pytest suite end-to-end; not filed as a task yet pending
triage). Assigning to SRV.01 per CLAUDE.md's explicit domain listing
("Quota enforcement, server-side audit log" under SRV.01) — not a
protocol/wire-format question (the `AUTH_OK` payload already has
`quota_bytes`/`used_bytes` fields per the existing struct and encoder; this
is purely a server-side bug where those fields are stubbed to `0` instead
of populated from the store) and not GUI/client domain. Not tagging
`security-sensitive`: this is an informational-usage-reporting bug (a
user's own login response under-reports their own quota usage back to
themselves) with no auth-bypass, privilege-escalation, cross-user data
exposure, or quota-*enforcement* implication — enforcement itself
(`vw_store_quota_adjust`) appears to work correctly and is untouched by
this bug; only the client-facing *display* of the counter is wrong. Per
routing rule 2, `CQR.08` alone in `review_by` is sufficient. Priority
`high` (not `critical`): isolated test failure, not blocking the rest of
the suite, and has no security impact — but it is a real, user-visible
correctness bug (clients cannot see their own storage usage), so not
`normal`/`low` either.
