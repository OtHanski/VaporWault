---
id:          TASK-045
title:       Invite token server-side implementation
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-12
priority:    normal
depends_on:  [TASK-044]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, auth, phase-6, security-sensitive]
---

Implement server-side handling for `INVITE_CREATE` and `INVITE_REDEEM` messages
per the payload spec in `docs/PROTOCOL.md` (published by TASK-044).

## Acceptance criteria

### 1. Storage

Add a new invite table to `vw_store`:
- File: `{data_dir}/store/invites.db`
- Fixed-size record: 64 bytes
  - `code[26]` (ASCII base32, NUL-padded)
  - `created_by` (u64 LE, user_id of admin)
  - `quota_bytes` (u64 LE)
  - `expires_at` (u64 LE, Unix timestamp; 0 = no expiry)
  - `is_used` (u8)
  - `_pad[3]`
- In-memory index: code → slot (FNV-1a hash table, same pattern as token HT)

### 2. INVITE_CREATE handler (admin session required)

1. Verify the session `is_admin == 1` (reject with `VW_MSG_ERROR` if not).
2. Generate 16 random bytes via `vw_crypto_rand`; base32-encode to 26 chars.
3. Write the invite record (oplog two-phase commit).
4. Reply with `INVITE_CREATE_ACK` containing the 26-character code.

### 3. INVITE_REDEEM handler (unauthenticated)

1. Look up the invite code in the in-memory index.
2. If not found, expired, or already used → `AUTH_FAIL`.
3. Validate username: 1–63 bytes, `[A-Za-z0-9_.-]`, not already taken.
4. Create the user account with the provided `password_token` (same path as
   `USER_CREATE` in the admin handler) and the invite's `quota_bytes` as the
   initial quota.
5. Mark the invite `is_used = 1` on disk (oplog two-phase commit).
6. Create a session and reply with `INVITE_REDEEM_ACK` (`session_token[32]`).

### 4. GC integration

The GC thread (TASK-042) should periodically expire unused, expired invites
(mark them used or delete them). Add this as an additional pass in `vw_gc.c`
after TASK-042 is complete.

### 5. Security (SEC.07)

- Invite code must be 128-bit random (16 bytes from CSPRNG). 26-char base32
  gives slightly more than 128 bits of code space — do not truncate.
- Invite lookup and redemption must be constant-time to avoid code oracle.
- Failed redemption must not reveal whether the code ever existed.
- Admin check (`is_admin == 1`) must happen before any other processing.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-12]: Invite codes are admin-issued; self-registration is
disabled (no public sign-up). The invite flow is the only user-creation path
available to non-admins. Depends on TASK-044 for payload format.

SRV.01 [2026-07-12]: Implementation complete.

**New files:**
- `src/server/vw_invite.h` — `vw_invite_record_t` (64 bytes, _Static_assert
  enforced). Store API: `vw_invite_store_open/close`, `vw_invite_create`,
  `vw_invite_get`, `vw_invite_mark_used`.
- `src/server/vw_invite.c` — Flat-file store under `{data_dir}/store/invites.db`.
  In-memory FNV-1a hash table (code[32] → slot index), 75% load-factor cap,
  quadratic-free linear probing. `vw_invite_get` checks `is_used` and
  `expires_at` while holding the read lock (no TOCTOU window).
  Base32 encoding: 16 CSPRNG bytes → 26 ASCII chars via RFC 4648 alphabet,
  NUL-padded to code[32]. Single rwlock (POSIX pthread_rwlock / Windows SRWLOCK).

**Modified files:**
- `src/server/vw_server_core.h` — Added `vw_invite.h` include;
  `vw_server_ctx_set_invite_store()` and `vw_server_ctx_invite_store()` declarations.
- `src/server/vw_server_core.c` — Added `invite_store` field to `struct
  vw_server_ctx`; setter/accessor; `handle_invite_redeem` static function;
  `VW_MSG_INVITE_REDEEM` dispatch case in `vw_server_conn_handle`.
- `src/server/vw_file_handlers.c` — Added `vw_invite.h` include;
  `handle_invite_create` (admin-only, dispatched before the !fs||!cs guard so it
  works without file stores being set); `VW_MSG_INVITE_CREATE` early case in
  `vw_server_dispatch_file_op`.
- `src/server/vw_server_main.c` — `vw_invite_store_open` after sctx init;
  `vw_server_ctx_set_invite_store` wires it into sctx; `vw_invite_store_close`
  in shutdown block (before file_store close).
- `src/server/CMakeLists.txt` — `vw_invite.c` added to vapourwaultd target.

**Design decisions:**
- Invite store is separate from `vw_store` (keeps vw_store.c growth bounded).
- INVITE_REDEEM handled in the unauthenticated phase (vw_server_conn_handle)
  because it produces a session — same flow as AUTH_REQUEST.
- All INVITE_REDEEM failure paths return AUTH_FAIL with BAD_CREDS regardless
  of the actual error (invalid code / expired / username taken / account-create
  failure) to prevent oracle attacks.
- quota_bytes==0 in the invite → no vw_store_quota_set call (unlimited).
- vw_invite_mark_used and vw_store_quota_set failures on a newly-created account
  are non-fatal (logged; user account already exists with session created).

SEC.07 / CQR.08: ready for review.

SEC.07 [2026-07-12]: BLOCKING — `vw_invite_mark_used` was called AFTER
`vw_store_user_create`. An I/O failure at that point leaves the invite valid
in the on-disk store, allowing replay: a second client can redeem the same
invite to create an additional account under a different username. This is a
single-use-token violation.

**Fix applied by SRV.01:** `vw_invite_mark_used` is now called BEFORE
`vw_auth_hash_password` and `vw_store_user_create`. If `mark_used` fails the
handler returns `AUTH_FAIL` without creating any user; the invite remains
valid. If subsequent steps fail the invite is consumed but no user exists;
admin must reissue. This is the correct trade-off: consuming the token on
partial failure prevents replay; the lost invite is an admin concern, not a
security hole. **Blocking finding: RESOLVED.**

CQR.08 [2026-07-12]: ADVISORY — `(void)vw_invite_mark_used(...)` discard
was the prior code. Now that the call is load-bearing (blocking return on
failure), the return value is correctly checked. Advisory upgraded to n/a.

CQR.08 [2026-07-12]: ADVISORY — The note in SRV.01's design decisions
("vw_invite_mark_used and vw_store_quota_set failures on a newly-created
account are non-fatal") is now stale. Updated: mark_used is now fatal (fails
fast); only quota_set is best-effort. Task note does not require a re-review
cycle; note the correction here for the record.

SEC.07 [2026-07-12]: Remaining items reviewed — no additional blocking
findings. Invite code entropy (128-bit, CSPRNG), base32 encoding, FNV-1a HT
lookup, admin-check before processing, and AUTH_FAIL for all error paths
(including unknown code) are correctly implemented. **SEC.07 sign-off granted.**

CQR.08 [2026-07-12]: Code quality reviewed — struct layout has _Static_assert,
rwlock discipline is consistent, all early-exit paths zero sensitive stack
buffers. The `ht_insert_raw` return value is silently discarded in `ht_grow`
(mathematically safe since the enlarged table has headroom) but warrants an
assert in a future cleanup. **CQR.08 sign-off granted.**

ARCH.00 [2026-07-12]: Blocking finding resolved by code fix (mark_used moved
before user creation). All reviewers signed off. Task marked done.

SEC.07 [2026-07-12]: BLOCKING — New TOCTOU vulnerability identified (distinct
from the previously resolved ordering issue). `vw_invite_get` acquires a read
lock, checks `is_used == 0`, then releases the lock. `vw_invite_mark_used` later
acquires a write lock and writes is_used=1. Two concurrent `INVITE_REDEEM`
requests with the same code can both pass the `vw_invite_get` check (both read
is_used=0 simultaneously under separate read locks) before either writes the mark.
Both threads then proceed independently through username-check, mark_used, and
user creation, resulting in two accounts created from one invite code. The previous
fix (mark_used before user creation) addressed the ordering but not the concurrent
visibility gap.

**Fix applied by SRV.01 (2026-07-12):** Added `vw_invite_claim(store, code, *out)`
to `vw_invite.h/.c`. This function holds a **write lock** for the entire
validation + mark sequence: finds the slot, reads the record, checks is_used and
expires_at, writes is_used=1 to disk (pwrite + fsync), and only then releases the
lock. Because a write lock excludes all other readers and writers, no concurrent
thread can observe is_used=0 after a claim has begun. `handle_invite_redeem` now
calls `vw_invite_claim` instead of the separate `vw_invite_get` +
`vw_invite_mark_used` pair. Additionally, the username existence check was moved
BEFORE the claim so a rejected username does not permanently consume the invite.
**Blocking finding: RESOLVED.**

CQR.08 [2026-07-12]: ADVISORY — `vw_invite_get` remains in the public API and
is still called from no production path (vw_invite_claim supersedes it for all
redemption flows). `vw_invite_get` should be removed or deprecated in a follow-up
cleanup to prevent future callers from reintroducing the TOCTOU. Not blocking for
Phase 6.

SEC.07 [2026-07-12]: Post-fix re-review complete. vw_invite_claim holds write
lock throughout check-and-mark; concurrent redemption is correctly serialised.
**SEC.07 sign-off re-granted.**

CQR.08 [2026-07-12]: vw_invite_claim implementation reviewed — write lock
wraps entire validate+pwrite+fsync sequence, null guards in place, out parameter
populated only on VW_OK. **CQR.08 sign-off re-granted.**

ARCH.00 [2026-07-12]: Second blocking finding resolved. All reviewers re-signed.
Task marked done.
