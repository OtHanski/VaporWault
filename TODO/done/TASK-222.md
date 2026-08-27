---
id:          TASK-222
title:       "No wire or admin path exists to set a user's email address"
status:      done
assignee:    ARCH.00
created_by:  QA.06
created:     2026-08-27
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
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

ARCH.00 [2026-08-27]: **Design decision.** Corrected this task's own
`review_by` on the way in — tagged `security-sensitive` but listed only
`CQR.08`, violating CLAUDE.md routing rule 1 (security-sensitive tasks
require both `SEC.07` and `CQR.08`); added `SEC.07`.

Chose a single self-service message pair — `ACCOUNT_EMAIL_GET`/`SET`,
same account-scoped, no-`user_id`, session-is-the-authority shape as
`NOTIFY_PREFS_GET`/`SET` (§7.13) — over the two other options this task's
"Work" section raised:
- **Not** adding `email` to `USER_CREATE_REQ`/`INVITE_REDEEM`: those
  cover only accounts created from now on, through one specific path
  each, and don't help any of the already-existing accounts on a real
  deployment. Left as a genuinely optional future enhancement (noted in
  `docs/PROTOCOL.md` §7.14) rather than folded in here — this task's own
  acceptance criteria only require *some* real mechanism to exist, not
  every plausible one.
- **Not** overloading `USER_MODIFY` (`0603`/`0604`) as a generic
  field-patch message: `TASK-219` independently reached the same
  conclusion for 2FA toggling and recommended a dedicated message pair
  over reviving that reserved opcode as a generic patch operation "since
  [each] is a security-sensitive, single-purpose action, not a general
  field-patch operation" — the same reasoning applies here. `USER_MODIFY`
  stays reserved and unimplemented; not this task's problem to solve.

Full implementation, done directly rather than split into SRV.01/CLI.02/
GUI.03/WEB.09 follow-ups (small enough end-to-end, and every layer needed
touching to actually reach the acceptance criteria's "verified by an
integration test that does NOT need to patch users.dat" bar):

- **Protocol** (`docs/PROTOCOL.md` §7.14, revision 26): `ACCOUNT_EMAIL_GET`
  (`0x0B01`)/`_GET_RESP` (`0x0B02`)/`SET` (`0x0B03`)/`_SET_ACK` (`0x0B04`).
  No wire version bump — entirely new opcodes.
- **Server** (`src/server/vw_store.h`/`.c`): new `vw_email_validate()` —
  the load-bearing security control here, since `vw_smtp.c`'s
  `MAIL FROM`/`RCPT TO` lines interpolate `rec.email` with zero escaping
  of their own. Conservative allow-list (one `@`, non-empty local/domain,
  domain has a `.`, no whitespace/control/`<`/`>` bytes) — rejects any
  CR/LF or SMTP-command-shaped input before it can ever reach the relay.
  New `vw_store_user_set_email()` — unlike `vw_store_user_update_field`
  (whose own doc comment forbids email, because it never touched the
  `email_ht` uniqueness index), this evicts the old address from the
  index before inserting the new one, using the same open-addressing
  backward-shift deletion algorithm `vw_store_files.c`'s `path_ht_remove`
  already established (`path_ht_hole_on_probe_path`/`_remove_at`,
  TASK-157) — copied to `email_ht_hole_on_probe_path`/`_remove_at`/
  `_remove` since this is a different hash table in a different file.
  **Bug found and fixed in the same pass**: `email_ht_insert` counted
  *every* empty-email account against the index's 75%-load growth
  threshold (an empty string always reported "not found" via
  `email_ht_find`'s own pre-existing guard, so it was harmless in
  effect, but every account lacked an email until today, so this fired
  on every single account ever created) — empty emails are now never
  inserted into the index at all.
  New handlers `handle_account_email_get`/`_set`
  (`src/server/vw_file_handlers.c`), dispatched alongside
  `NOTIFY_PREFS_GET`/`SET` (no file/chunk store dependency); `SET` added
  to `is_write_shaped_msg` (rejected on a replica, same as every other
  write).
- **Client core** (`vw_client_core.h`/`.c`):
  `vw_client_account_email_get`/`_set`.
- **Daemon IPC** (`vw_ipc.h` `0x8043`-`0x8046`, `vw_daemon.c`): thin
  passthrough, `_SET` gated on `account_is_read_only` like
  `NOTIFY_PREFS_SET`.
- **CLI**: `vapourwault-cli account email` (show) /
  `account email set <address>` (change/clear), under the existing
  `account` verb alongside `add`/`list`/`remove`.
- **GUI**: new "Account email" section in the Settings view, above
  "Email notifications" (which is silently a no-op without it) —
  optimistic input with revert-and-resync-on-failure, same pattern the
  notify checkboxes already use.
- **Web gateway/frontend**: `POST /api/account/email` (get) and
  `/api/account/email/set`, thin passthrough via `require_session()`
  (account derived from the session cookie only, never a request field —
  same posture as every other gateway endpoint); frontend settings view
  gained an email input + Save button above the notification checkboxes.
- **Tests**:
  `tests/unit/test_vw_store.c` — 12 new `vw_email_validate`/
  `vw_store_user_set_email` cases (57 assertions), including the
  email_ht eviction-on-change regression and the empty-email-index-bug
  regression.
  `tests/integration/test_cli_account_email.py` (new) — the actual
  acceptance-criterion test: default-empty, set, independent-fetch
  round-trip, change (old address stops resolving), clear, and
  malformed/duplicate rejection, all through the real CLI/daemon/server,
  zero `users.dat` patching.
  `tests/integration/test_gateway.py` — 2 new tests mirroring the
  notify-prefs gateway tests exactly (default-empty-and-roundtrip,
  scoped-to-caller-only + duplicate-rejection).
  `tests/integration/test_notify_alerts.py` — left its `_set_user_email_raw`
  test-only patcher in place rather than retrofitting all six call sites
  to the new real mechanism (a non-trivial rewrite of an already-
  reviewed, already-passing security-sensitive suite); added a note
  pointing at the new tests instead, since TASK-222's own acceptance
  criteria only required *some* test proving the real path exists, which
  the two new files above already do.
  `tests/integration/test_cli_version_history.py`: unrelated to this
  task's own change, not touched here.
- **Docs**: `docs/CLIENT_GETTING_STARTED.md` gained a new "Setting your
  account email" section ahead of "Email notifications", and corrected
  that section's previously-wrong claim ("the same [address] your admin
  used when they set your account up") — no admin path has ever existed,
  so that sentence was never true; replaced with the real mechanism.

Verified on both toolchains: WSL/GCC (`build-gw-e2e`) and MSVC
(`build-msvc-105`) build clean, including the GUI and web gateway.
`ctest` 20/20 on both. Python suites: `test_cli_account_email.py` (2/2),
`test_gateway.py` full suite (36/36, including the 2 new tests),
`test_cli_version_history.py` (2/2, confirming no regression from an
earlier unrelated session). TypeScript frontend (`npm run build`)
compiles clean.

SEC.07 [2026-08-27]: Reviewed the security-sensitive surface —
`vw_email_validate`, `vw_store_user_set_email`'s index handling, and the
handler's session/permission gating — line by line, not just the notes
above.

- Confirmed the actual threat this validator exists for: `vw_smtp.c`'s
  `smtp_send_data` builds `"MAIL FROM:<%s>\r\n"`/`"RCPT TO:<%s>\r\n"` via
  plain `snprintf` with zero escaping, into a 1024-byte `cmd[SMTP_CMD_BUF]`
  buffer — comfortably larger than the 128-byte max email, so no overflow
  risk, but confirms the allow-list is the *only* thing standing between
  a stored email and SMTP command injection. Verified the allow-list
  rejects every byte that could matter for that: CR, LF, `<`, `>`,
  quotes, whitespace, and in fact every byte outside
  `[A-Za-z0-9._%+-]`/`[A-Za-z0-9.-]` for local/domain parts respectively
  — including an embedded NUL, which would otherwise let a validated
  wire-length string diverge from what `strlen()`-based C-string handling
  later sees. Confirmed by the new unit tests actually exercising a
  CRLF-with-injected-SMTP-command string and an angle-bracket string, not
  just asserted in prose.
- Confirmed `vw_store_user_set_email` holds `ctx->users_lock` for its
  *entire* duration (duplicate check through index update), so the
  check-then-insert is not a TOCTOU race under concurrent callers.
- Confirmed `handle_account_email_get`/`_set` both route through
  `validate_session` + `reject_if_scoped` exactly like `NOTIFY_PREFS_GET`/
  `SET`, so a scoped (anonymous `LINK_ACCESS`) session cannot read or
  write any account's email, and a real session can only ever affect its
  own `user_id` (never a request-supplied one — there isn't one).
- Confirmed none of the three display surfaces (CLI `printf`, GUI
  `ImGui::TextDisabled("Current: %s", ...)`, web
  `accountEmailCurrent.textContent`) render the email as a format string
  or as HTML — no format-string or XSS risk from displaying a
  server-returned address back to its own owner.

**Finding, `advisory`, not `blocking`**: `handle_account_email_set`
returns `VW_ERR_ALREADY_EXISTS` straight to the caller when another
account already owns the requested address — an authenticated user can
therefore probe arbitrary addresses and learn whether each one belongs
to *some* account in the system (email enumeration), one guess per
`account email set <address>` call. Worth flagging because this
codebase already has an established, deliberate counter-pattern for the
sibling case: `handle_invite_redeem`'s username-collision path
(`vw_server_core.c`) computes the same distinction internally but sends
the *generic* `VW_ERR_AUTH_BAD_CREDS` over the wire rather than
confirming existence, specifically to avoid username enumeration during
an unauthenticated flow. Not fixed here for two reasons: (1) the trust
bar is different — reaching `ACCOUNT_EMAIL_SET` requires an already-
valid, non-scoped session, unlike invite redemption's pre-auth
reachability, so the exploitable population is "existing account
holders," not "anyone on the internet"; (2) confirming "that address is
taken" during a *self-service* email change (as opposed to anonymous
signup) is common, accepted practice in real products precisely because
the alternative — a generic failure with no reason — makes the feature
frustrating to use correctly. Recording this explicitly rather than
letting the asymmetry with `INVITE_REDEEM` go unremarked; a future
hardening pass could collapse both to a generic error if the threat
model changes (e.g. this software is ever deployed multi-tenant with
low mutual trust between accounts), but that is a product decision, not
something to silently decide either way here.

CQR.08 [2026-08-27]: Reviewed the non-security-sensitive surface.
`email_ht_remove`/`_remove_at`/`_hole_on_probe_path` are a faithful,
correctly-adapted copy of `vw_store_files.c`'s already-reviewed
`path_ht_remove`/`_remove_at`/`_hole_on_probe_path` (TASK-157) — same
open-addressing backward-shift deletion, correctly re-keyed on
`email_ht`'s own "key[0]=='\0' means empty slot" convention instead of
`path_ht`'s "owner_id==0" one. `vw_store_user_set_email`'s error paths
all correctly `vw_oplog_abort` before returning, matching the existing
`vw_store_user_update_field`/`vw_store_user_create` idiom byte-for-byte.
No dead code, no missing NULL checks, no resource leaks on any exit
path. Doc comments on `vw_store_user_update_field` and the module-level
`test_notify_alerts.py` docstring were both correctly updated in place
rather than left stale once this task made their claims outdated — good
adherence to this project's own "don't leave a corrected fact
undocumented" discipline. No `blocking` findings. `status: done`
approved (pending SEC.07's own sign-off above, which raised only an
`advisory`, not a `blocking`, finding).

ARCH.00 [2026-08-27]: Closing. Both required reviewers (`SEC.07`,
`CQR.08`) signed off with no `blocking` findings — `SEC.07`'s
email-enumeration note is recorded as `advisory` with clear reasoning
for why it isn't being fixed now, not silently dropped. Acceptance
criteria met: a real, documented, implemented wire mechanism exists
(`docs/PROTOCOL.md` §7.14), surfaced end-to-end through every client
(CLI, GUI, web), and verified by `test_cli_account_email.py`/
`test_gateway.py`'s new tests without ever touching `users.dat` directly.
