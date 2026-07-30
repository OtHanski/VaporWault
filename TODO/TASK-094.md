---
id:          TASK-094
title:       Implement server-side sharing (grants + public links)
status:      todo
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
