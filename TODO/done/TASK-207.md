---
id:          TASK-207
title:       "Server: user-facing email alert triggers"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-206]
blocks:      [TASK-208, TASK-209, TASK-211, TASK-212, TASK-213]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive, server]
---

Implements `TASK-206`'s wire spec plus the four user-category triggers
from `TASK-205`'s design. Introduces a small shared dispatch helper
(suggest `vw_notify.c`/`.h`: wraps `vw_smtp_send`, checks a recipient's
preference bitmask/config bool before sending, and holds the debounce
state for threshold-style categories) that `TASK-208`'s admin categories
should reuse rather than duplicate.

## Work

- User record gains a notification-preference bitmask field (extends
  `vw_user_record_t`/`vw_store`, same precedent as the existing
  2FA-enabled flag). Default: all bits off.
- `NOTIFY_PREFS_GET`/`_SET` handlers.
- Trigger call sites:
  - `share_received`: wherever a `SHARE_GRANT` targeting another user is
    created (not `LINK_CREATE` — no addressable recipient there).
  - `quota_warning`: wherever quota usage is checked/updated
    (`vw_store`'s quota accounting) — edge-triggered on crossing the
    threshold (e.g. 90%), re-armed only after usage drops back under it.
  - `new_login`: on a **successful, fresh** `AUTH_REQUEST` only —
    explicitly excluding `SESSION_RESUME`, which is the normal
    reconnect path and would otherwise fire on every daemon reconnect.
  - `account_security_change`: password change handler, 2FA
    enable/disable handler.
- Email content: never include the password, session token, or any
  secret. State the fact plainly (e.g. "A new login to your account
  succeeded from <context available>, at <time>") and, where relevant,
  a pointer to revoke sessions/change password if it wasn't them.

## Security note (`security-sensitive`)

- This is a new place secrets could leak into an email body if a future
  edit is careless — the acceptance criteria below require an explicit
  check for this, not just "it compiles."
- `new_login`/`account_security_change` are themselves security-relevant
  signals; get SEC.07 sign-off on the exact wording and on the
  fresh-auth-vs-resume distinction before this reaches `done`.
- The recipient of every email is always the target user's own on-file
  `email` field — never an address supplied fresh in the triggering
  request, to avoid this becoming an arbitrary-email-relay primitive.

## Acceptance criteria

- With no preferences set (default off), zero email is ever sent —
  verified, not assumed.
- Each category fires exactly once per real trigger, and quota_warning
  correctly re-arms after dropping back under threshold and crossing
  again.
- `SESSION_RESUME` never fires `new_login`.
- No email body ever contains a password, session token, or OTP.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

SRV.01 [2026-08-26]: Implemented.

- `notify_prefs` storage: **not** a `vw_user_record_t` field — that record
  is already exactly 256 bytes with zero spare padding (verified by
  actually adding up every field's size before deciding, not assumed).
  New `notify_prefs.db` side table (`vw_notify_prefs_record_t`, 16 bytes,
  same free-list/slot pattern as the existing `quotas.db`), with
  `vw_store_notify_prefs_get`/`_set` mirroring `vw_store_quota_get`/`_set`
  exactly. `_get` never returns `VW_ERR_NOT_FOUND` (unlike quota) — a
  never-set user reads back `VW_OK`/`0`, matching "default off" without
  every caller needing its own not-found-means-default special case.
- New `src/server/vw_notify.c`/`.h`: the shared dispatch/debounce helper
  the task suggested, wrapping `vw_smtp_send`. Every trigger function is a
  no-op unless SMTP is configured AND the target user's preference bit is
  set. `vw_notify_ctx_t` is owned by `vw_server_ctx_t` (created/destroyed
  internally, not by `vw_server_main.c`) since its only job is wiring
  `vw_store`'s new quota hook to `vw_smtp` — see below.
- `NOTIFY_PREFS_GET`/`_SET` handlers added to `vw_file_handlers.c`'s
  dispatcher (account-scoped only; a scoped/anonymous `LINK_ACCESS`
  session is rejected with `VW_ERR_PERMISSION`, same as `SEARCH`).
  `NOTIFY_PREFS_SET` added to `is_write_shaped_msg` — rejected on a
  replica with `VW_ERR_READ_ONLY_REPLICA`, same as every other write.
- **share_received**: `handle_share_grant` (`vw_file_handlers.c`), right
  after `vw_share_grant_create` succeeds. Never fires for `LINK_CREATE`
  (no addressable recipient there) — only ever reachable from
  `SHARE_GRANT`'s own code path.
- **new_login**: both success branches of `handle_auth_request`
  (`vw_server_core.c`) — the no-2FA path and the 2FA-verified path — right
  before `build_and_send_auth_ok`. `handle_session_resume` never calls
  this function at all, so `SESSION_RESUME` structurally cannot trigger
  it; not just "excluded by a check" but genuinely a different code path.
- **quota_warning**: real design change from the task's own suggestion.
  Rather than hooking every one of `vw_store_quota_add`'s 7 call sites in
  `vw_storage.c` (upload, dedup, delete, GC — all at a lower layer with no
  `smtp_cfg` access), added a `vw_store_set_quota_hook`/
  `vw_store_quota_hook_fn` callback registration to `vw_store.c` itself
  (same opaque-callback idiom `vw_store_user_scan` already uses — no new
  link-time dependency from `vw_store` onto `vw_notify`/`vw_smtp`).
  `vw_store_quota_add` invokes the hook once, outside its own lock, with
  the post-update `(used_bytes, quota_bytes)`; `vw_notify_quota_hook`
  (registered as that hook in `vw_server_ctx_set_notify`) does the actual
  90%-threshold edge-trigger/re-arm, with its own small per-user debounce
  table. This was the correct place for the threshold decision anyway —
  computing old-vs-new against the threshold at the one point that
  already holds the lock atomically avoids a TOCTOU between the update
  and a separate check.
- **account_security_change**: fires from `handle_recover_confirm`
  (`vw_server_core.c`) after a successful password-recovery password
  change. **Correction to `TASK-205`'s design assumption, found by
  actually checking rather than assumed**: there is no 2FA enable/disable
  mechanism anywhere in this codebase to hook at all (grepped every write
  site of `otp_enabled` — exactly one, in `vw_store_user_create`, always
  0). Filed `TASK-219` (design gap, ARCH.00) rather than either
  silently building a whole new self-service 2FA toggle feature inside
  this task, or silently shipping a half-true trigger with no
  explanation.
- **Known gap, filed rather than fixed here**: `notify_prefs.db` is not
  part of `TASK-172`'s replica hot-standby file-tag replication list — a
  fallback-connected replica's `NOTIFY_PREFS_GET` always reads back
  defaults regardless of the primary's real value. Extending that fixed,
  wire-documented table is a protocol change; filed as `TASK-220`
  (PRT.04) rather than decided unilaterally here.
- Email content: every body is a fixed template with only pre-validated,
  non-secret fields interpolated (a username string, a file leaf name, a
  peer IP, one of this module's own pre-approved `account_security_change`
  phrases) — never a password, session token, or OTP. Verified by an
  actual regression test (below), not just code review.

**Testing**:
- New `tests/unit/test_vw_notify.c` (45 assertions): default-off (no send
  for any category with prefs unset); `share_received` fires only when
  opted in, with correct recipient/content; no email body/subject ever
  contains a password-shaped string (all three one-shot categories,
  checked against a real secret literal via `strstr`); `quota_warning`
  edge-triggers exactly once on crossing 90%, does not repeat while still
  over, silently re-arms on dropping back under, fires again on a second
  crossing, and never fires for an unlimited (`quota_bytes == 0`) account;
  SMTP-not-configured is a silent no-op for every category including the
  quota hook. Uses a test-only function-pointer seam
  (`vw_notify_test_set_smtp_send_fn`, same idiom as `vw_auth.c`'s
  `vw_auth_test_set_time_fn` — declared in the .c file, not the public
  header) to record calls instead of touching the network.
- Full rebuild + `ctest --test-dir build-gw-e2e`: 20/20 passed (WSL/GCC).
- Full non-cluster pytest integration suite (111 passed, 15 deselected)
  re-run after these changes — no regression in `test_auth.py` (confirms
  `new_login`'s hook doesn't break either auth path),
  `test_sharing.py`/`test_quota.py` (confirm `handle_share_grant`'s new
  parameter and the quota hook don't break existing behavior).
- MSVC (`build-msvc-105`) and WSL/GCC (`build-gw-e2e`) both build clean;
  `test_vw_notify` run directly on both, 45/45 passing on each.
- Found and fixed two build-time gaps before they could hide a real
  regression: `tests/unit/CMakeLists.txt`'s `test_vw_file_handlers` and
  `tests/integration/CMakeLists.txt`'s `test_auth_handshake`/
  `test_file_list_vault_id` each duplicate `vw_server_lib`'s source list
  (documented, pre-existing pattern in this codebase, flagged by
  `vw_server_lib`'s own CMakeLists comment as a "must update this too or
  it will silently stop reflecting what ships" trap) — all three were
  missing `vw_notify.c` until added here.

SRV.01 [2026-08-26]: Added a UTC timestamp to `new_login`'s email body
(`%Y-%m-%d %H:%M:%S UTC`) — the task's own example wording included "at
<time>" and the first draft omitted it. Re-ran `test_vw_notify` (45/45),
full `ctest` on both toolchains (20/20 WSL/GCC, 19/19 MSVC — MSVC's ctest
set excludes the pytest-based `integration` phase5 test, consistent with
prior sessions) after this change.

Moving to `review`.

SEC.07 [2026-08-26]: Reviewed against this task's own security note.

- Read every email-body `snprintf` call in `vw_notify.c` line by line:
  each interpolates only pre-validated, non-secret values (a username
  already resolved via `vw_store_user_get_by_id`, a file leaf name from
  `vw_file_record_t.name`, a peer IP string, a UTC timestamp, or one of
  this module's own fixed phrases) — no password, session token, or OTP
  is ever in scope at any call site, structurally, not just by convention.
  Confirmed further by `test_vw_notify.c`'s dedicated
  "no email body ever contains a password/token-shaped secret" case,
  which checks a real secret literal with `strstr` against every category
  — actually executed, not just asserted in prose.
- Confirmed the recipient is always `vw_store_user_get_by_id`'s on-file
  `email` field in every call site — no code path threads a
  caller-supplied address into `vw_smtp_send`. This can't become an
  arbitrary-email-relay primitive.
- `new_login`/`account_security_change` wording: plain, factual, includes
  a "if this wasn't you" remediation pointer, no enumeration-sensitive
  content (doesn't reveal whether an email address exists elsewhere,
  doesn't echo back anything secret). Approved as written.
- `SESSION_RESUME` structurally cannot reach `vw_notify_new_login` —
  verified by reading `handle_session_resume` in full: it has no call to
  `build_and_send_auth_ok` or `vw_notify_new_login` anywhere in its body,
  confirming this isn't merely "excluded by a runtime check" that could
  regress silently, but a different function entirely.
- `NOTIFY_PREFS_SET`'s reserved-bit rejection (`VW_ERR_INVALID_ARG` for
  any bit outside `VW_NOTIFY_ALL_KNOWN`) is present and correctly placed
  before the store write. Noted for `TASK-213`: no wire-level test yet
  exercises this specific rejection path (`test_vw_notify.c` tests
  `vw_notify.c`'s own dispatch logic, not `vw_file_handlers.c`'s bit
  validation) — not blocking, since `TASK-213` is explicitly scoped to
  this level of coverage, but flagging so it isn't forgotten.
- The two follow-ups filed (`TASK-219`: no 2FA-toggle mechanism exists to
  hook; `TASK-220`: notify_prefs.db not replicated to hot-standby
  replicas) are both honestly scoped and correctly identified as
  out-of-domain for this task rather than either silently skipped or
  silently over-built.
- No blocking findings. Approved.

CQR.08 [2026-08-26]: Reviewed for code quality and consistency.

- `vw_store`'s new quota-hook callback is a clean dependency-inversion
  choice — avoids `vw_store.c` linking against `vw_notify`/`vw_smtp`,
  reuses the exact opaque-callback idiom `vw_store_user_scan` already
  established in this same header, and correctly computes the
  threshold-crossing decision at the one point that already holds the
  lock atomically (avoids a TOCTOU the task's own suggested "hook every
  call site" approach would have been more exposed to).
- `notify_prefs.db`'s slot/free-list/write-slot helpers are a faithful,
  line-by-line mirror of `quotas.db`'s existing pattern — verified by
  reading both side by side, not assumed to match from memory.
- `vw_notify_ctx_t` being owned internally by `vw_server_ctx_t` (created
  in `vw_server_ctx_set_notify`, freed in `vw_server_ctx_close`, hook
  cleared before the free) rather than borrowed like every other
  attachment is a deliberate, explained deviation from this file's usual
  convention, not an inconsistency — the reasoning (it's purely internal
  wiring with nothing external needing to own it) holds up.
- `vw_notify_test_set_smtp_send_fn`'s test-only seam correctly follows
  `vw_auth.c`'s own precedent (`g_time_fn`/`vw_auth_test_set_time_fn`) —
  declared in the .c file, not the public header, and the test file
  forward-declares its own prototype rather than the production header
  growing a test-only export.
- Found and fixed, before this reached review, a real build-breaking gap:
  three duplicated-source-list CMake targets
  (`test_vw_file_handlers`/`test_auth_handshake`/`test_file_list_vault_id`)
  were each missing the new `vw_notify.c`, exactly the trap
  `vw_server_lib`'s own CMakeLists comment warns about — caught by
  actually attempting a full rebuild, not assumed clean because the
  primary `vw_server_lib` target linked.
- `test_vw_notify.c`'s coverage is real and specific: exact assertion
  counts checked at every step (not just "no crash"), a genuine
  secret-literal `strstr` check rather than a superficial "email was
  sent" assertion, and the quota debounce test walks the full
  cross/stay-over/re-arm/cross-again state machine rather than only the
  first transition.
- No blocking findings. Approved.

Moving to `done`.
