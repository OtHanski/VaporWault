---
id:          TASK-076
title:       AUTH_OK always reports quota_bytes=0 and used_bytes=0 (hardcoded stub, never populated from store)
status:      done
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

SRV.01 [2026-07-19]: Fixed. In `build_and_send_auth_ok`
(`src/server/vw_server_core.c:77-88`), replaced the hardcoded
`ok.quota_bytes = 0; ok.used_bytes = 0;` with a real
`vw_store_quota_get(ctx->store, user_id, &quota_rec)` call, populating
`quota_bytes`/`used_bytes` from the returned record and falling back to
`0`/`0` only when `vw_store_quota_get` returns non-`VW_OK` (i.e. no quota
record yet - per `vw_store.h:379-380`, "unlimited quota, 0 used"). This
mirrors the existing call sites at `vw_file_handlers.c:1096-1101` and
`vw_admin.c:223-226`. Since `build_and_send_auth_ok` is the single shared
builder for both `handle_auth_request` and `handle_session_resume`, both
paths now report real usage - no separate fix needed for `SESSION_RESUME`.

Verified end-to-end, not just statically: built the full project on Linux
(WSL Ubuntu, GCC 13.3.0) via a fresh out-of-tree CMake configure with
`-DVW_WERROR=ON -DCMAKE_BUILD_TYPE=Debug` (matching CI's strict-warnings
flag); zero warnings/errors across the whole build. Ran the full pytest
integration suite (`pytest tests/integration -m "not cluster"`, 20/20
passed) - `test_quota.py::test_used_bytes_does_not_increase_after_delete`
and its two siblings (`test_upload_fails_when_quota_exceeded`,
`test_quota_adjust_allows_upload`) all pass, confirming both the fix and
no regression in existing quota-enforcement behavior. Also ran the
`ctest` suite (all 11 targets, including `unit_vw_store`,
`integration_auth_handshake`, and the Phase 5 `integration` TAP runner) -
100% pass.

No wire/protocol change: `vw_payload_auth_ok_t` already had
`quota_bytes`/`used_bytes` fields (PROTOCOL.md section 7.1's AUTH_OK
payload table already documents them); this was purely a server-side bug
in what value got written into an existing field. Setting `status:
review` for CQR.08 per `review_by`.

CQR.08 [2026-07-19]: Code-quality review. Confirmed `vw_store_quota_get`'s
documented semantics (`vw_store.h:378-381`: returns `VW_ERR_NOT_FOUND` when
no quota record exists, meaning "unlimited, 0 used" - not a
corruption/uninitialized-record signal). The new code's fallback-to-0/0 on
any non-`VW_OK` return (not just `VW_ERR_NOT_FOUND` specifically) is
correct and matches the existing pattern exactly at both cited call
sites - `vw_file_handlers.c`'s `ulist_tls_cb` (~1096-1101) and
`vw_admin.c`'s `ulist_cb` (~220-242) both use the identical
"`if (get() == VW_OK) populate; else leave zero-initialized`" idiom
without distinguishing NOT_FOUND from other errors either, so this isn't
a new gap being introduced. Grepped `build_and_send_auth_ok` project-wide:
4 call sites total - `handle_auth_request`'s two success branches
(direct-login and post-2FA), `handle_session_resume`, and
`handle_invite_redeem` - all four now get real quota/usage automatically
since it's one shared builder. Confirms SRV.01's claim that both
`AUTH_REQUEST` and `SESSION_RESUME` are fixed (plus `INVITE_REDEEM` as an
unclaimed bonus, also correctly fixed). Style: the new mid-block
declarations (`quota_rec`, `quota_bytes`/`used_bytes`) match this same
function's pre-existing C11 idiom just above (`sess_rec`, `user_rec` are
declared the same way, not hoisted to the top of the function) - no
inconsistency introduced. No blocking findings. Clean sign-off.

ARCH.00 [2026-07-19]: CQR.08 signed off clean. Confirming resolution and
closing — status: done.
