---
id:          TASK-094
title:       "Implement server-side sharing (grants + public links)"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-29
priority:    high
depends_on:  [TASK-088]
blocks:      [TASK-097]
review_by:   [SEC.07, CQR.08]
tags:        [server, storage, protocol, security-sensitive]
---

Implement the server side of the sharing design published in
`docs/PROTOCOL.md` §7.5/§7.10 (`TASK-088`). This is the security-critical
half of the feature — it owns the actual cross-user access control.

Scope:

- New `vw_share` module (`vw_share.h`/`.c`): `vw_share_record_t` (128 bytes,
  `_Static_assert`-enforced per this codebase's convention), fixed-size
  on-disk table (`shares/shares.db`), in-memory indexes rebuilt on load
  (`file_id → [share_id...]`, `link_token → share_id`), CRUD matching the
  style of `vw_store_files.c`.
- Extend `vw_session_record_t` (`vw_store.h`) with `scope_file_id`/
  `scope_permission` fields, reusing existing `_pad[70]` reserved bytes —
  do not grow the struct; add a `_Static_assert` comment explaining the
  reuse, matching `TASK-090`'s `deleted_at` precedent.
- Extend the permission check in `vw_file_handlers.c` per the ordered rule
  in §7.5: owner check (existing, unchanged) → walk-up share-grant check →
  scoped-session check → deny. Every file-op entry point in the 0x02xx/
  0x03xx groups must go through this, not just a subset.
- Implement `SHARE_GRANT`/`_REVOKE`/`_LIST` and `LINK_CREATE`/`_REVOKE`/
  `_LIST`/`LINK_ACCESS` handlers per the wire formats in §7.5. Rename the
  `VW_MSG_SUB_CREATE`/`VW_MSG_SUB_DELETE` enumerators in `vw_proto.h` to
  `VW_MSG_LINK_CREATE`/`VW_MSG_LINK_REVOKE` (same numeric values — confirmed
  unimplemented, safe to repurpose).
- `LINK_ACCESS` handling: unauthenticated, pre-`AUTH_REQUEST`, mirrors
  `INVITE_REDEEM`'s dispatch path. Apply the same IP-based rate limit
  already implemented for `NODE_HELLO` in `vw_cluster.c` (5 failures/60s →
  silent drop) — reuse that pattern rather than writing a second one.
- Quota resolution: every quota-check call site in the upload/commit path
  must resolve the quota owner from `file.owner_id` (or the containing
  folder's `owner_id` for new files), never from the acting session's
  `user_id`. Audit every existing quota-check call site, not just new ones,
  since shared-folder uploads go through the same commit path as any other
  upload.
- **Live revocation**: scoped-session validity must be re-checked against
  the live `vw_share_record_t.revoked`/`expires_at` on every request bound
  to that session, not cached at `LINK_ACCESS` time.
- Oplog/audit: writes made through a scoped session must record the acting
  identity as anonymous (`user_id = 0`) distinctly from the file's real
  owner, so the owner's audit trail shows "modified via link" rather than
  appearing to be their own write.
- **FILE_MOVE (SEC.07 finding, added 2026-07-29)**: requires EDIT on both
  the source's current parent and the destination parent, **and**
  `destination_parent.owner_id == file.owner_id` (prevents a grantee from
  moving a shared file out of the owner's tree — see §7.5's "FILE_MOVE
  ownership and cycle rules"). Also reject any directory move whose
  destination is the directory itself or one of its own descendants
  (cycle check) — this applies to every FILE_MOVE, not just shared ones.
- **Authenticated-session-only grant/revoke (SEC.07 finding, added
  2026-07-29)**: `SHARE_GRANT`, `SHARE_REVOKE`, `LINK_CREATE`, `LINK_REVOKE`
  must reject any request from a scoped (anonymous) session with
  `VW_ERR_PERMISSION`, checked before any other handler logic — an
  anonymous link redeemer must never be able to mint an independent grant
  or link that would survive revocation of the one they used to get in.
- **Scoped-session write-count rate limit (SEC.07 finding, added
  2026-07-29)**: apply a per-scoped-session limit on write operations
  (`FILE_COMMIT`, `CHUNK_UPLOAD`, `FILE_DELETE`, `FILE_MOVE`), independent
  of and in addition to the byte-quota check — an anonymous public-edit-link
  holder must not be able to create unbounded files/versions/oplog entries.
  Concrete threshold is this task's to set (e.g. N writes/minute per scoped
  session), but the limit itself is not optional.
- **Scoped-session root navigation**: `FILE_LIST` with `parent_dir_id == 0`
  from a scoped session returns the single scoped item or its immediate
  children, never the server's actual root — see §7.5's "Scoped-session
  navigation."
- **`FILE_LIST_RESP`/`FILE_STAT_RESP` permission field**: stop hardcoding
  `VW_PERM_OWNER`; populate it from the caller's actually-resolved effective
  permission (own → `VW_PERM_OWNER`; via grant/scope → the grant's/scope's
  `vw_perm_t` value). `TASK-096`'s file-browser indicator reads this field.

## Acceptance criteria

- All wire messages in §7.5 implemented and round-trip correctly against a
  real client (WSL validation, not just unit tests, per this project's
  established practice).
- Permission-check rule enforced for every 0x02xx/0x03xx handler, verified
  by a deliberate attempt to access another user's file both directly and
  via a share/link boundary (should fail cleanly).
- Quota always resolves to the file's real owner — verified by uploading
  through someone else's EDIT grant and through a public edit link, and
  confirming the *editor's* quota is unaffected while the *owner's* is
  debited.
- A revoked share/link immediately blocks a request from an already-issued
  scoped session (not just newly-issued ones).
- A scoped (anonymous) session cannot call `SHARE_GRANT`/`SHARE_REVOKE`/
  `LINK_CREATE`/`LINK_REVOKE` under any circumstances.
- Moving a shared file into a folder owned by someone other than the file's
  own owner fails; moving a directory into its own descendant fails.
- Repeated writes from one scoped session past the configured threshold are
  rejected, independent of remaining byte quota.
- SEC.07 signs off specifically on cross-user access control and the
  public-link attack surface (unauthenticated endpoint, rate limiting,
  enumeration resistance, write-count limiting) before this moves to `done`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088` once its
design was settled and published in `docs/PROTOCOL.md` §7.5/§7.10.

SRV.01 [2026-07-30]: Implemented in full. Summary of the pieces:

**New `vw_share` module** (`src/server/vw_share.{h,c}`): `vw_share_record_t`
(128 bytes, `_Static_assert`-enforced), flat file under
`{data_dir}/shares/shares.db` (slot 0 guard, `share_id` == slot index
directly — no separate id index needed). In-memory `link_token` hash table
for O(1) `LINK_ACCESS`. `vw_share_resolve_permission()` implements §7.5
rules 2/3 (grants and scoped-session access, via ancestor walk-up through
`vw_store_file_get_by_id`'s `parent_dir_id` chain) — rule 1 (owner check)
stays the caller's job, matching the existing §7.8.1 convention. Rule 3
re-reads the live share record on every call (no caching), which is what
makes live revocation automatic rather than a separate mechanism to keep
in sync. Also owns: the scoped-session write-count rate limiter and the
LINK_ACCESS IP failure rate limiter (mirrors `vw_cluster.c`'s
`rate_entry_t` pattern, with TASK-078's eviction-fairness fix applied from
the start).

**`vw_session_record_t` extended** (`vw_store.h`): new `scope_share_id`
field, reusing `_pad[70]` (same precedent as TASK-090's `deleted_at`).
Deliberately stores the share_id, not a denormalized file_id/permission
copy — every scoped-session check re-derives current state from the live
share record via this id. `vw_auth_create_scoped_session()` (`vw_auth.c`)
creates one directly (user_id always 0), bypassing the normal
lockout/2FA/user-lookup machinery entirely, since a scoped session has no
associated user account.

**`vw_server_core.c`**: `LINK_ACCESS` handled in the pre-auth phase
alongside `AUTH_REQUEST`/`INVITE_REDEEM` (same anti-enumeration
convention: every failure — unknown/revoked/expired token, sharing
disabled — reports generic `AUTH_FAIL`/`BAD_CREDS`). IP-based rate
limiting on failures via `vw_share_link_access_*`, mirroring the existing
`NODE_HELLO` pattern.

**`vw_file_handlers.c`** — the bulk of the change:
- `effective_permission()`/`require_permission()` helpers used by every
  handler in place of the old `rec.owner_id != user_id` SEC.07-B-1 check.
  `NOT_FOUND` when the caller has no access at all (hides existence,
  matching the prior convention); `PERMISSION` when they have some access
  but not enough (existence is already visible to them).
- `FILE_LIST`: scoped-session root navigation (empty/root path resolves
  to the scope's own target, never the server's real root, per the CQR.08
  finding); `list_owner_id` introduced since a shared subtree's owner
  differs from the acting session — `vw_store_file_list`'s `owner_id`
  param is a hard per-owner filter, not a permission check.
- `FILE_STAT`/`VERSION_LIST`/`VERSION_RESTORE`/`VERSION_CHUNKS`: permission
  checks now go through the grant/scope walk-up, not just ownership.
  `VERSION_RESTORE` requires EDIT (a modification, per §7.5's table).
- `CHUNK_DOWNLOAD_REQ`: `check_chunk_ownership` renamed/extended to
  `check_chunk_access` — also BFS-checks the caller's active grants'
  subtrees and a scoped session's own subtree, not just the caller's own
  tree. Same O(n)-per-subtree tradeoff this function already had
  (pre-existing `TODO(Phase 4)` note), now applied N times instead of
  once.
- `CHUNK_UPLOAD`/`FILE_COMMIT`: quota resolution (§7.5). A scoped
  session's `CHUNK_UPLOAD` resolves the real owner directly (the scope's
  target's `owner_id`) instead of charging `user_id == 0`, which would
  otherwise silently create an unlimited-by-default quota record — a real
  byte-quota bypass for anonymous public-edit-link holders, independent
  of the write-count rate limit. For an authenticated grantee (whose
  eventual file/folder target isn't known until `FILE_COMMIT`), added
  `vw_storage_chunk_reattribute()` (`vw_storage.{h,c}`): at `FILE_COMMIT`,
  every committed chunk currently charged to the acting session gets its
  charge moved to the file's resolved real owner (a no-op for chunks
  attributed to someone else via dedup, which the acting session was
  never charged for). `FILE_COMMIT` also gained a new capability: when
  `file_id` names a *directory* the caller has EDIT on, it creates a new
  file under that folder (owned by the folder's owner, per the "creator
  does not become owner" rule) — this is what makes creating a file
  inside a shared folder possible at all, since path-based creation is
  strictly namespaced to the caller's own `owner_id` (see
  `handle_file_list`'s `list_owner_id` note) and could never reach a
  folder it doesn't own.
- `FILE_DELETE`/`FILE_MOVE`/`CHUNK_UPLOAD`/`FILE_COMMIT`: scoped-session
  write-count rate limit checked before any other processing (SEC.07
  finding).
- New `handle_file_move` (`FILE_MOVE`/`FILE_MOVE_ACK`, 0x020F/0x0210 —
  first-ever implementation; no payload was ever defined before this).
  Enforces EDIT on both current and destination parent (root, `dir_id ==
  0`, is treated as ownable only by its actual owner — no grant can ever
  target "root" itself, since grants always name a real `file_id`),
  `destination_parent.owner_id == file.owner_id`, and the directory
  move-into-own-descendant cycle check (both SEC.07 findings from
  `TASK-088`'s design phase).
- New `SHARE_GRANT`/`_REVOKE`/`_LIST` and `LINK_CREATE`/`_REVOKE`/`_LIST`
  handlers. `SHARE_GRANT`/`LINK_CREATE` cap the granted permission at the
  granter's own effective permission (§7.5). All four mutating messages
  reject a scoped (anonymous) session with `VW_ERR_PERMISSION` before any
  other logic (SEC.07 finding — otherwise a leaked link's holder could
  mint an independent grant/link surviving revocation of the one they
  used to get in). `SHARE_LIST_RESP`/`LINK_LIST_RESP` carry the shared
  item's leaf *name* (display-only), not a full path — path lookups are
  namespaced by `owner_id`, so a full path wouldn't resolve in a
  non-owner viewer's own namespace anyway; documented as an
  implementation note in `docs/PROTOCOL.md` §7.5 (which had specified
  `path`).
- `FILE_LIST_RESP`/`FILE_STAT_RESP`: `perm` byte now reflects the actual
  resolved permission (own → OWNER; via grant/scope → the grant's/scope's
  level) instead of the old hardcoded `VW_PERM_OWNER`.

**Wire compatibility**: no existing message's byte layout changed for any
existing client. Every `SHARE_*`/`LINK_*` message is newly used (the prior
`SUB_CREATE`/`SUB_DELETE` opcodes never had a handler). `FILE_MOVE` is a
first-ever payload for a previously unimplemented opcode. No protocol
version bump needed — see `docs/PROTOCOL.md`'s version-history row 10 for
the full reasoning.

**Two out-of-domain findings filed, not fixed here** (discovered while
writing this task's own integration tests): `TASK-104` (PRT.04 — no wire
message creates a directory at all, a general Phase 2 gap predating
sharing) and `TASK-105` (SRV.01, low priority — an unrecognized message
type on an authenticated connection hangs silently instead of erroring).
`TASK-104` in particular constrained this task's own integration-test
design to root-level files only (folder-sharing's ancestor-walk-up is
covered at the unit level instead, in `test_vw_share.c`, which builds
folder records directly via `vw_store_file_create`).

**Validation:**
- New `tests/unit/test_vw_share.c` (65 assertions): grant/link CRUD,
  ownership-gated revoke, permission resolution (grant walk-up, scoped
  walk-up, live revocation, expiry), scoped-session write-rate-limit, and
  LINK_ACCESS IP rate-limit.
- New `tests/integration/test_sharing.py` (12 tests) against a real
  running `vapourwaultd` over TLS (extended `vw_client.py` with
  `share_grant`/`_revoke`/`_list`, `link_create`/`_revoke`/`_list`/
  `_access`, `file_move`): VIEW-vs-EDIT enforcement, quota debited to the
  owner and not the editing grantee (verified via real `used_bytes`
  deltas across separate connections, not just a code-review claim),
  owner-only revoke, scoped-session root navigation, live revocation of an
  already-issued scoped session, unknown-token rejection, scoped session
  blocked from `SHARE_GRANT`/`LINK_CREATE`, `LINK_LIST_RESP`'s field set
  never includes a token, `FILE_MOVE` rename and EDIT-vs-VIEW enforcement.
  (This server's test config caps worker threads at 2 — every test in this
  file is deliberately written to never hold more than 2 simultaneous
  connections open, and to close each connection inside the same
  try/finally that opened it, after an early version of this file
  discovered the hard way — via TASK-105's finding — that exceeding the
  cap doesn't error, it hangs a connection forever with no GOODBYE ever
  sent, which starves every later test in the same module too.)
- Both new test files, plus the full existing unit + integration suites
  (`tests/unit/*`, `tests/integration/test_{auth,dedup,file_ops,gc,
  quota}.py`), pass clean on both platforms: GCC/WSL Ubuntu
  (`-Wall -Wextra -Wpedantic -Werror`) and MSVC `/W4 /WX` (env from
  `vcvars64.bat`). 13 CTest suites, 32 pytest integration tests, all
  green, no regressions.

Acceptance-criteria note: "round-trip correctly against a real client" is
satisfied via the Python reference protocol client
(`tests/integration/vw_client.py`), not `vapourwault-cli` — the real C
client's sharing support is `TASK-095`, not started yet. `TASK-097`'s
comprehensive scenario matrix (this task's own tests are TASK-094's
validation, not a substitute for that) should build on the same
`vw_client.py` extensions added here.

SEC.07 [2026-07-30]: Reviewed cross-user access control and the
public-link attack surface specifically (the acceptance criteria's
explicit ask), independent of SRV.01's own notes above.

- Confirmed the ordered permission rule (owner → grant walk-up → scope
  walk-up → deny) is applied consistently across every 0x02xx/0x03xx
  handler by re-reading each one, not sampling — `FILE_LIST`, `FILE_STAT`,
  `CHUNK_DOWNLOAD_REQ` (via `check_chunk_access`), `CHUNK_UPLOAD`,
  `FILE_COMMIT`, `FILE_DELETE`, `FILE_MOVE`, `VERSION_LIST`,
  `VERSION_RESTORE`, `VERSION_CHUNKS` all route through
  `effective_permission`/`require_permission` or an equivalent explicit
  check; none silently fell back to an owner-only check.
- Confirmed live revocation empirically, not just by code inspection: the
  integration test redeems a link, uses it successfully once, revokes it,
  and confirms the *same already-issued* scoped session is rejected on
  its very next request — this is the exact property that's easy to get
  wrong (caching the scope at redemption time instead of re-deriving it).
  `vw_share_resolve_permission`'s scope branch calls `vw_share_get_by_id`
  fresh every time; nothing caches `revoked`/`expires_at`.
  `check_chunk_access`'s scope branch does the same independently — this
  matters because it's a second, separate call site that could have
  drifted out of sync with the first.
- Confirmed the anonymous-scoped-session restriction on
  `SHARE_GRANT`/`_REVOKE`/`LINK_CREATE`/`_REVOKE` is checked *before* any
  other logic in all four handlers (`reject_if_scoped` is the first
  statement after `validate_session` in each), and verified this
  empirically via the integration test (leaked-EDIT-link holder attempts
  both `SHARE_GRANT` and `LINK_CREATE`, both rejected).
- Confirmed the scoped-session write-count rate limit is keyed by session
  token (not `share_id`), so distinct redeemers of the same public link
  get independent budgets — matches the spec's "per scoped session" (not
  "per link") wording exactly. Confirmed it's checked on all four write
  ops the spec lists (`FILE_COMMIT`, `CHUNK_UPLOAD`, `FILE_DELETE`,
  `FILE_MOVE`) and is independent of (checked in addition to, not instead
  of) the byte-quota check.
- Confirmed enumeration resistance on `LINK_ACCESS`: unknown, revoked, and
  expired tokens all produce the identical `AUTH_FAIL`/`BAD_CREDS`
  response via `vw_share_get_by_token`'s single `VW_ERR_NOT_FOUND` path
  (no separate "found but revoked" branch that could leak existence), and
  IP-based rate limiting on failures is in place mirroring `NODE_HELLO`.
- Confirmed quota reattribution's failure mode is safe: if the owner's
  quota can't absorb a reattributed chunk,
  `vw_storage_chunk_reattribute` leaves attribution unchanged (does not
  partially debit the acting session without crediting the owner) —
  checked the implementation directly, this is not just inferred from the
  doc comment.
- Confirmed no plaintext secret material is newly introduced by this
  task: `link_token` is the only new secret-shaped value, generated via
  the existing `vw_crypto_random` CSPRNG (same generator as session
  tokens), zeroed after use in `handle_link_create`
  (`vw_file_handlers.c`).
- **No blocking findings.** One advisory, already disclosed in SRV.01's
  notes rather than newly surfaced here: `check_chunk_access`'s per-grant
  BFS is O(number of active grants × subtree size) — a user with very
  many active grants pays a real linear cost per `CHUNK_DOWNLOAD_REQ`.
  Not a security issue (no cross-user leak, just a performance ceiling
  matching the pre-existing, already-acknowledged `check_chunk_ownership`
  tradeoff), so not blocking; worth a real index if sharing sees adoption
  at scale.

CQR.08 [2026-07-30]: Reviewed the full diff (not just the security-critical
paths SEC.07 focused on).

- `vw_share.c`: confirmed every `vw_fs_read_file`-returned buffer is freed
  on every path, including the early-return branches in
  `vw_share_resolve_permission`'s grant scan and `vw_share_scan`.
  Confirmed the slot-index-equals-share_id invariant
  (`vw_share_store_open`'s guard-slot write, `share_create_common`'s
  append-at-`nslots` behavior) is internally consistent and matches the
  existing `vw_store_files.c` convention exactly, including under the
  OOM-in-hash-table-insert path (durable on disk, index rebuilt on next
  open — same pattern `vw_invite_create` already uses).
- Confirmed `vw_session_record_t`'s new `scope_share_id` field lands on an
  8-byte-aligned offset without relying on implicit struct packing (the
  `_pad_align[6]` filler makes the compiler's alignment requirement
  explicit rather than accidental) and that every field before it keeps
  its original byte offset — genuinely backward-layout-compatible, not
  just size-compatible.
- Confirmed `vw_storage_chunk_reattribute` and the two spots that call it
  or its sibling logic (`handle_chunk_upload`'s direct-charge-to-owner for
  scoped sessions, `handle_file_commit`'s post-commit reattribution loop)
  don't double-count: the scoped-session path charges the owner directly
  at upload time (so reattribution at commit time is correctly a no-op
  for those chunks, since they're never attributed to `user_id == 0` in
  the first place).
- Confirmed `handle_file_move`'s cycle-check walk and
  `is_file_or_ancestor`'s walk (in `vw_share.c`) both bound their loops
  (2048 hops) against a corrupt/cyclic `parent_dir_id` chain hanging the
  request — consistent hardening applied in both places independently
  written for the same underlying tree-walk shape.
- No dead code, no naming or const-correctness issues, no premature
  abstraction. The `single_item`/`single_item_only` pair in
  `handle_file_list` needed a defensive `memset` to satisfy MSVC's
  uninitialized-variable analysis (`/W4` caught what GCC's `-Wall -Wextra`
  did not) — confirmed the fix doesn't change behavior, since the field is
  only read on the path that also sets `single_item_only = 1` immediately
  after fully populating it.
- **No blocking or advisory findings** beyond SEC.07's single advisory
  above (which CQR.08 independently agrees is real but non-blocking).
  Sign-off given.

ARCH.00 [2026-07-30]: SEC.07 and CQR.08 sign-off received, no blocking
findings. All acceptance criteria met, with the one explicitly-noted
adjustment: "round-trip against a real client" used the Python reference
protocol client rather than `vapourwault-cli`, since `TASK-095` (the real
C client's sharing support) hasn't started yet — reasonable and expected
given the task decomposition, not a shortfall. Closing as done.
`TASK-095`/`TASK-096` are now unblocked; `TASK-097` should build on this
task's `vw_client.py` extensions rather than re-inventing them.

QA.06 [2026-07-31]: `TASK-097` closed — extended `test_sharing.py` (this
task's own suite) to the full regression matrix, building on the
`vw_client.py` extensions from here as anticipated above. See `TASK-097`
for the five new tests and sign-off notes.
