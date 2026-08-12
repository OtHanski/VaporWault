---
id:          TASK-073
title:       Fix credential-derivation mismatch between admin user-create and login (AUTH_FAIL code=300)
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-19
priority:    critical
depends_on:  [TASK-070, TASK-072]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [bug, ci, auth, crypto, security-sensitive]
---

With TASK-070 and TASK-072 both landed and confirmed in CI run 29683468506
(TLS handshake succeeds; `test_login_wrong_password` / `test_login_unknown_user`
no longer fail on the handshake), a third, independent, pre-existing bug is
now exposed and is the last blocker for this CI job going green: every test
that creates a user via the admin socket and then logs in over the main wire
protocol fails with `vw_client.VwAuthError: AUTH_FAIL code=300` (bad
credentials) — even though the password used at creation and at login is
identical.

## Root cause

Two code paths are supposed to derive the same stored/verified credential
value but don't:

1. **Admin user creation** — `handle_user_create`
   (`src/server/vw_admin.c:132-180`), per the admin socket's own documented
   wire format (`src/server/vw_admin.h:52`:
   `USER_CREATE_REQ: u8 is_admin, u16 uname_len, uname[], u16 pw_len, pw[]`
   — deliberately raw, since this admin protocol is meant for an operator
   CLI typing a plaintext password). Line 159 calls
   `vw_auth_hash_password(p + 3 + uname_len + 2, pw_len, hash, salt)`
   directly on the **raw password bytes**, then stores the resulting
   Argon2id hash+salt via `vw_store_user_create`. Confirmed the operator
   CLI (`cmd_user_create` in `src/server/vw_server_cli.c:177-196`) does
   exactly this: takes the raw password argv string and copies it verbatim
   into the request payload (`vw_server_cli.c:191`) — no hashing on the
   client/CLI side either.

2. **Login** — `handle_auth_request` (`src/server/vw_server_core.c:105-193`)
   → `vw_auth_begin_login` (`src/server/vw_auth.c:171-220`). The real
   client computes `auth_token = SHA-256(password)` **client-side** before
   sending it — documented, intentional Phase-0 design
   (`docs/PROTOCOL.md:166`: "auth_token bytes[32] | Password hash sent from
   client (see §8 for derivation)"; `docs/PROTOCOL.md:697-702`: "Security
   Note (Phase 1 issue TASK-009): For Phase 0 the wire token is
   SHA-256(password) sent from client."). The server then calls
   `vw_crypto_argon2id_verify(real_hash, real_salt, password, pw_len)`
   (`vw_auth.c:211`) where `password`/`pw_len` is already that 32-byte
   SHA-256'd `auth_token` — i.e. login verifies
   `Argon2id(SHA-256(raw_password))`, never `Argon2id(raw_password)`.

Because admin-created accounts store `Argon2id(raw_password)` but login
verifies against `Argon2id(SHA-256(raw_password))`, these can never match —
every admin-created user's password verification fails, always, regardless
of whether the password is correct.

`docs/PROTOCOL.md:508` documents the **main wire protocol's own**
client-facing `USER_CREATE` (message `0x0601`, distinct from the admin
socket's `0x9001 ADMIN_USER_CREATE_REQ`): `password_token bytes[32] |
Credential (same derivation as AUTH_REQUEST.auth_token)` — confirming the
intended system-wide invariant is that every stored credential is derived
as `Argon2id(SHA-256(password))`, consistently. It is specifically the
**admin socket path** that breaks this invariant by skipping the SHA-256
pre-hash step. This has nothing to do with TASK-070/072; it is a separate,
independent bug in credential-derivation consistency, only now reachable
because the first two bugs no longer block execution before reaching this
code path.

This is a same-CI-run failure across nearly every integration test that
logs in after creating a user (`test_login_success`, `test_session_resume*`,
`test_brute_force_lockout` partially, `test_dedup*`, `test_file_ops*`,
`test_gc*`, `test_quota*`) — i.e. it is now the last blocker for CI going
green today. Full failure log via
`gh run view 29683468506 --log-failed` if still accessible, or re-fetchable
from a fresh CI run.

## Required fix

SHA-256 the raw password before it reaches `vw_auth_hash_password()` in the
admin user-create path, so the stored hash matches what login verifies
against (`Argon2id(SHA-256(password))`). A shared helper already exists —
`vw_crypto_sha256()` (`src/core/vw_crypto.h:60`) — use that rather than
hand-rolling the SHA-256 call; do not duplicate hashing logic inline if a
cleaner shared helper (e.g. a single `vw_auth_derive_token()`-style function
used by both the admin path and login) would remove the duplication and the
risk of this class of bug recurring — consider adding one if it doesn't
already exist in a suitable form.

Before implementing, investigate and decide between two places to apply the
fix, and document the choice in this task's notes:

- **Option A — server-side, in `handle_user_create`
  (`src/server/vw_admin.c`)**: SHA-256 the raw `pw[]` bytes received over
  the admin socket before calling `vw_auth_hash_password`. Wire format
  (`vw_admin.h:52`) stays "raw password bytes," unchanged.
- **Option B — CLI-side, in `cmd_user_create`
  (`src/server/vw_server_cli.c:177-196`)**: SHA-256 the password before
  building the `ADMIN_USER_CREATE_REQ` payload, so the admin CLI behaves
  like "a normal client" and sends the same 32-byte token shape a real
  client's `USER_CREATE` (`0x0601`) sends per `docs/PROTOCOL.md:508`. This
  would change the admin wire format's `pw[]` field to a fixed 32-byte
  token, requiring an update to `vw_admin.h`'s documented wire format.

Weigh which better matches the existing architecture (e.g.: is the admin
socket meant to stay a "raw password in, server does all derivation"
channel per its current docs, or should it be brought in line with the
main protocol's "client derives the token" convention?) and pick one — do
not implement both. If the admin wire format changes (Option B), update
`vw_admin.h`'s payload documentation accordingly; this is an internal admin
IPC format, not the main wire protocol, so routing rule 3 (PRT.04
`docs/PROTOCOL.md` sign-off) does not apply, but note the change clearly in
this task regardless.

## Acceptance criteria

- Admin-created users can log in via the main wire protocol using the same
  password supplied at creation time.
- Chosen fix location documented in this task's notes with rationale.
- If the admin wire format (`vw_admin.h`) changes, its payload
  documentation comment is updated to match.
- Full pytest integration suite and the legacy TAP suite pass locally (or
  in CI) against the real server binary.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Assigning to SRV.01, not PRT.04. This mirrors
TASK-070's reasoning: the correct derivation convention already exists and
is already correctly specified by PRT.04 (`docs/PROTOCOL.md:508`,
"same derivation as AUTH_REQUEST.auth_token") — no new protocol design or
crypto primitive work is needed, only fixing server-side (and possibly
admin-CLI-side) code to actually follow that already-documented
convention. Both `vw_admin.c` and `vw_server_cli.c` are pure C
server-adjacent code squarely in SRV.01's domain ("HTTP-lite request
dispatcher," server-side account management per the roster), not a wire
protocol design change. Tagged `security-sensitive` per routing rule 1
(credential/auth correctness bug touching password derivation), requiring
both SEC.07 and CQR.08 in `review_by`. `depends_on: [TASK-070, TASK-072]`
recorded for lineage — this bug was only reachable once both prior fixes
landed — not because either is currently blocking (both are done).
Priority `critical`: this is the last known blocker for the CI job going
fully green today. If SRV.01's investigation concludes Option B is the
right fix and touches the admin CLI's operator-facing behavior in a way
that affects deployment/ops docs, file a follow-up note for
`docs/DEPLOYMENT.md` rather than folding unrelated doc work into this task.

SRV.01 [2026-07-19]: Investigated both options and chose **Option A
(server-side, in `handle_user_create`, `src/server/vw_admin.c`)** over
Option B (CLI-side, `vw_server_cli.c`). Rationale:

- Confirmed via `vw_server_core.c:462` (`handle_recover_confirm`) and
  `vw_server_core.c:586` (`handle_invite_redeem`) that every OTHER caller
  of `vw_auth_hash_password()` in the codebase already passes it a
  32-byte, pre-SHA-256'd `password_token`/`new_password_token` (from the
  main wire protocol, per `docs/PROTOCOL.md:508`) — never a raw password.
  `vw_admin.c`'s `handle_user_create` was the sole outlier calling
  `vw_auth_hash_password()` directly on raw bytes. Option A brings the
  admin path in line with the convention every other call site already
  follows, rather than special-casing it further.
- Confirmed `tests/integration/vw_client.py`'s `AdminClient.create_user()`
  (`vw_client.py:517-538`) sends the raw password verbatim over the admin
  socket, exactly like `vapourwault-server-cli`'s `cmd_user_create`
  (`vw_server_cli.c:177-196`) does. A CLI-side fix (Option B) would have
  required updating the Python test client too, and would leave the door
  open for any future admin tool to reintroduce this exact bug by sending
  a raw password. A server-side fix (Option A) covers every current and
  future caller of the admin socket uniformly, with a single point of
  truth for the derivation.
- The admin socket is local-only (`AF_UNIX`, mode 0600, `SO_PEERCRED`
  verified — see `vw_admin.h` header comment), so there is no network
  transport-security reason to prefer a pre-hashed wire format there, unlike
  the main protocol.

**Changes made:**

- `src/server/vw_admin.c:16` — added `#include "../core/vw_crypto.h"` for
  `vw_crypto_sha256()`.
- `src/server/vw_admin.c` in `handle_user_create` (was line 159, now inside
  a new block after the `pw_len` bounds check) — SHA-256 the raw `pw[]`
  bytes into a 32-byte `pw_token` buffer via `vw_crypto_sha256()`, then call
  `vw_auth_hash_password(pw_token, sizeof(pw_token), hash, salt)` instead of
  calling it directly on the raw bytes. `pw_token` is zeroed immediately
  after use (matches existing `hash`/`salt` zeroing convention in the same
  function).
- `src/server/vw_admin.h:52` — updated the `USER_CREATE_REQ` wire-format
  comment to document that `pw[]` is intentionally the raw operator
  password (safe because the channel is local-only), that the server
  SHA-256s it internally before Argon2id, and that callers must not
  pre-hash it themselves. Referenced this task.
- No wire format change — `pw[]` remains raw bytes; only internal
  server-side handling changed. Routing rule 3 (PRT.04 sign-off) does not
  apply, consistent with the task's own note.

**Verification:**

- **Static**: Full project build succeeded on Windows/MSVC
  (`-DCMAKE_BUILD_TYPE=Release`, existing configured `-DVW_WERROR=ON`
  cache) for `vapourwaultd` and `vapourwault-server-cli` — but on Windows
  the entire POSIX admin-socket implementation (including
  `handle_user_create`) is compiled out (`vw_admin.c:25` `#ifdef _WIN32`
  stub), so that build only confirmed the Windows stub path, not the
  changed code. To actually compile and exercise the changed code, used
  WSL Ubuntu (gcc 13.3.0): first a `gcc -fsyntax-only -Wall -Wextra`
  check on `vw_admin.c` alone (clean, no warnings/errors), then a full
  `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DVW_WERROR=ON` configure +
  build of the whole project on Linux — this is the actual POSIX branch
  containing the fix, closely matching CI's Linux/gcc/Release job. Clean
  build, no warnings on `vw_admin.c`.
- **End-to-end**: Built `vapourwaultd` + `vapourwault-server-cli` under
  WSL/Linux, generated a test cert via `tests/integration/gen_test_cert.sh`,
  and ran the real pytest integration suite (`pytest tests/integration/ -m
  "not cluster"`) against the built binaries.
  `test_auth.py::test_login_success`, `test_login_wrong_password`,
  `test_login_unknown_user`, `test_session_resume`, and
  `test_session_resume_single_use` **all pass** — confirming an
  admin-created user can now log in with the correct password over the
  main wire protocol, and still correctly fails with a wrong password /
  unknown user. This directly satisfies this task's acceptance criterion
  ("Admin-created users can log in via the main wire protocol using the
  same password supplied at creation time").
- Ran the fuller non-cluster suite (20 tests, excluding `-m cluster`): 13
  passed, 7 failed. `test_brute_force_lockout` and 5 others fail due to
  **separate, pre-existing, unrelated bugs** independent of credential
  derivation — filed as **TASK-074** (admin socket handles only one
  request per connection, but `tests/integration/vw_client.py`'s
  `AdminClient` and its pytest fixture reuse one connection for multiple
  RPCs per test, causing `BrokenPipeError` on the 2nd+ RPC in a test).
  One further failure, `test_quota.py::test_used_bytes_does_not_increase_after_delete`
  (asserts `used_bytes > 0` after upload, gets 0), looks like an unrelated
  quota-accounting bug, not yet filed as its own task — flagging here for
  ARCH.00 to triage/assign. None of these 7 failures are caused by, or
  regressions from, this task's change: the credential-mismatch fix only
  touches `handle_user_create`'s internal hashing, doesn't alter the wire
  response format, and none of the 7 failing tests exercise a login with
  the *correct* password as their failure point.
- Did **not** run the legacy TAP suite (not located/verified in this pass);
  flagging as unverified rather than claiming coverage.

Given the above, I'm setting `status: review`. The credential-derivation
bug itself (this task's actual scope) is fixed and verified end-to-end;
the "full pytest suite passes" acceptance criterion is not fully met, but
the remaining failures are independent pre-existing bugs (TASK-074 and one
untriaged quota issue), not regressions or omissions in this fix. Over to
SEC.07 / CQR.08 for review.

CQR.08 [2026-07-19]: Reviewed the diff (`vw_admin.c`, `vw_admin.h`). Clean
sign-off, no blocking findings; one advisory (comment trim, same as
TASK-072 earlier today).

- **Security-boundary claim verified against code, not just the header
  comment**: `vw_admin_server_start` (`vw_admin.c:527-576`) creates
  `AF_UNIX`/`SOCK_STREAM`, binds under `umask(0177)` so the kernel assigns
  mode 0600 atomically (`vw_admin.c:559-565`), and `admin_listener`
  (`vw_admin.c:491-516`) rejects any connection whose `SO_PEERCRED` (Linux)
  / `LOCAL_PEERCRED` (BSD-likes) UID doesn't match the server's own `getuid()`.
  Claim holds.
- **Sibling call-site consistency verified independently**: grepped
  `vw_auth_hash_password` and `vw_crypto_sha256` project-wide.
  `vw_server_core.c:462` (`handle_recover_confirm`) and `vw_server_core.c:586`
  (`handle_invite_redeem`) both call `vw_auth_hash_password(token,
  VW_TOKEN_BYTES, ...)` where `token` is a 32-byte value already derived
  client-side/SHA-256'd — `VW_TOKEN_BYTES` is 32 (`vw_proto.h:35`), matching
  `VW_HASH_BYTES` (`vw_proto.h:34`) and the new `pw_token[32]`. The new code
  is consistent with the established pattern, not a third variant.
- **`vw_crypto_sha256` signature checked** (`vw_crypto.h:60-61`):
  `vw_err_t vw_crypto_sha256(const void *data, size_t len, uint8_t
  out_hash[VW_HASH_BYTES])`. Call site (`data=p+3+uname_len+2, len=pw_len,
  out=pw_token`) matches argument order, count, and return-type usage.
  Correct.
- **Zeroing**: `pw_token` is zeroed on both exits — the early return on
  `vw_crypto_sha256()` failure (`vw_admin.c:174`) and unconditionally after
  the `vw_auth_hash_password()` call regardless of its result
  (`vw_admin.c:178`) — matching how `hash`/`salt` are zeroed unconditionally
  after use elsewhere in the same function (e.g. `vw_admin.c:189`). No leak
  path found.
- **Advisory (non-blocking), consistent with today's TASK-072 precedent**:
  both new comment blocks bake in dated task-attribution narrative — `/*
  SRV.01 [2026-07-19] TASK-073: ... */` in `vw_admin.c` (10 lines) and
  `TASK-073 [SRV.01, 2026-07-19]: fixed a mismatch where...` in `vw_admin.h`
  (16 lines) — plus a `docs/PROTOCOL.md:508, 697-702` line-number citation
  that will rot as that doc is edited. STYLE.md §10 asks for terse,
  why-only comments; task/ticket narrative belongs in this TODO file and
  the commit message, not permanent source comments. Suggest trimming both
  to the essential why (admin socket is local-only so raw pw[] is
  acceptable; server SHA-256s it internally so the stored hash matches
  login's `Argon2id(SHA-256(password))` verification; callers must not
  pre-hash) and dropping the ticket/date/history exposition. Note: the
  existing one-line `SRV.01 [2026-07-12]: TASK-040 implementation.` header
  at the top of `vw_admin.c` is fine as a terse provenance marker — it's the
  multi-line narrative form that's the issue, not attribution itself.
- Separately, noting for the record (not a finding against this task, out
  of scope per routing rule 4): `vw_admin.c` zeroes all secrets
  (`hash`/`salt`/`pw_token`/`rec.password_*`) with plain `memset`, not the
  `secure_zero` volatile-indirection wrapper STYLE.md §15 requires for
  password hashes/tokens (which `vw_server_core.c` already uses via
  `secure_zero`). This is a pre-existing, file-wide gap predating this
  diff — the new `pw_token` zeroing simply matches the file's existing
  (already non-compliant) local convention, so it isn't a regression
  introduced here. Flagging for a follow-up task rather than blocking this
  fix on unrelated scope.

No blocking findings. Sign-off from CQR.08.

SEC.07 [2026-07-19]: Reviewed the diff (`vw_admin.c`, `vw_admin.h`) plus the
full call graph. **Clean sign-off — no blocking findings.**

1. **Invariant correctly restored, not weakened.** Traced the derivation
   chain end-to-end: client `vw_client_core.c:103` and GUI
   `vw_view_login.cpp:79` both compute `auth_token = SHA-256(password)`
   client-side; `vw_auth_begin_login` (`vw_auth.c:211`) calls
   `vw_crypto_argon2id_verify(real_hash, real_salt, password/*=auth_token*/,
   pw_len)`. `vw_auth_hash_password` (`vw_auth.c:67-72`) is a thin wrapper
   with **no internal SHA-256** — every caller is required to pre-hash.
   Confirmed the other two call sites already did this correctly before
   this fix: `vw_server_core.c:462` (`handle_recover_confirm`) and `:586`
   (`handle_invite_redeem`) both pass a 32-byte `*_token` that arrived
   pre-hashed over the wire (`INVITE_REDEEM`'s `password_token[32]`,
   `docs/PROTOCOL.md`-documented derivation). The new
   `vw_crypto_sha256(raw_pw) → vw_auth_hash_password(pw_token, 32, ...)`
   sequence in `vw_admin.c:172-177` produces exactly
   `Argon2id(SHA-256(password))`, matching this convention bit-for-bit — no
   new/incompatible/weaker scheme introduced.

2. **Admin socket safety claim verified independently, not taken on faith.**
   Read `vw_admin_server_start` (`vw_admin.c:527-576`): `AF_UNIX` +
   `SOCK_STREAM`, `umask(0177)` held around `bind()` so the kernel assigns
   mode 0600 atomically, confirmed. `admin_listener` (`vw_admin.c:471-523`)
   checks `SO_PEERCRED`/`getuid()` on Linux and `LOCAL_PEERCRED` on
   `*BSD`/macOS, closing the connection on mismatch before any data is
   parsed — claim holds on those platforms. (Note: on POSIX platforms with
   neither macro, there'd be no peer-credential check at all, only the 0600
   mode bit — but that's pre-existing scope from TASK-040, not touched or
   worsened by this diff.) No `fprintf`/log call anywhere in `vw_admin.c`
   touches `payload`, `p`, `pw_token`, `hash`, or `salt` — greped the whole
   file, confirmed. Zeroing: `pw_token` is memset in **both** the
   SHA-256-failure branch (line 174) and the success branch (line 178);
   `hash`/`salt` are zeroed on the pre-existing failure branch (181) and
   after use (189). The raw password bytes inside `payload` are zeroed
   unconditionally by the caller, `handle_admin_connection`
   (`vw_admin.c:465`), after `handle_user_create` returns via **any** path
   (early `VW_ERR_INVALID_ARG` returns included) — so no early-return
   branch, old or new, leaves raw password material un-zeroed in the
   payload buffer.

3. **No new timing side-channel.** `vw_crypto_sha256` (`vw_crypto.c:127-131`)
   is a direct `mbedtls_sha256` call — time depends only on input length
   (fixed here: `pw_len` from a bounds-checked wire field), never on byte
   content. No new branch on password content was added; the only branch
   added is on `vw_crypto_sha256`'s own return code (OOM/internal error),
   not password-dependent.

4. **Downstream consistency confirmed.** As in (1) — `vw_server_core.c:462`
   and `:586` already followed `SHA-256-then-Argon2id` before this fix
   landed. This change brings `vw_admin.c` into line with an
   already-correct, pre-existing system-wide convention; it is not the
   first or only place doing this, which rules out a deeper/systemic
   design problem.

5. **No auth bypass / credential-leak / downgrade concern found** in this
   diff. `vw_server_cli.c`'s `cmd_user_create` was also checked for
   completeness (not part of this diff): it sends the raw password as
   before, wire format unchanged, and already offers a
   `--stdin-password`/`-` option to avoid argv exposure — pre-existing
   behavior, out of scope here, not regressed.

No blocking or advisory findings. Sign-off given for the security aspects
of this diff.

ARCH.00 [2026-07-19]: Both required reviewers signed off clean. Trimmed
the two new comment blocks (`vw_admin.c`, `vw_admin.h`) per CQR.08's
advisory, same as TASK-072 — kept the essential why, dropped the
dated task-attribution narrative. Confirming resolution and closing —
status: done. Filed `TASK-077` for CQR.08's other advisory (`vw_admin.c`
using plain `memset` instead of the `secure_zero` wrapper for secrets,
file-wide, pre-existing and not a regression from this fix). The
remaining 7 non-cluster test failures SRV.01 found while verifying this
task are tracked separately: TASK-074 (admin socket connection reuse),
TASK-075 (brute-force lockout), TASK-076 (quota accounting) — not
blockers for this task's own scope.
