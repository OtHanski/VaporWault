---
id:          TASK-170
title:       "Protocol: publish CLUSTER_RECORD_*/CLUSTER_CHUNK_* wire spec"
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-08-14
priority:    high
depends_on:  [TASK-169]
blocks:      [TASK-172]
review_by:   [CQR.08]
tags:        [protocol]
---

`TASK-169`'s design requires the replica pull loop (`vw_cluster.c`) to
fetch full records and chunk content, not just oplog notification bytes.
Per `CLAUDE.md`'s protocol-change routing rule, this spec must be
published in `docs/PROTOCOL.md` before `TASK-172` implements it.

## Work — REVISED (2026-08-14, before any implementation started)

Original plan below was "fetch the full record an oplog entry's bare id
points to." Abandoned after checking the actual `vw_oplog_append` call
sites (`vw_store_files.c:545`): `VW_OPLOG_FILE_CREATE`'s payload is
written with `&rec->owner_id` — appended to the oplog *before*
`file_id = fs->next_file_id` is even assigned a few lines later. The
payload isn't just terse, it's structurally incapable of identifying
which record to fetch (an owner can have many files; owner_id alone
doesn't disambiguate). Every other file/version op has the same shape.
Record-level fetch-by-id from oplog payloads is not viable — moved to a
whole-file-sync design instead, which sidesteps needing to interpret
oplog payload semantics at all (the entries are used only as a
turn-the-crank signal that something changed, never as a data source).

Free message-type range confirmed during `TASK-169`'s research:
`0x0708`–`0x07FE`.

Define, in `docs/PROTOCOL.md`'s existing cluster section:

- **Syncable metadata files** (fixed, tagged by a small enum — never a
  free-form path string, which would otherwise be a new path-traversal
  surface even though the replica is already admin-trusted per §7.9):
  `USERS` (`store/users.dat`), `QUOTAS` (`store/quotas.db`), `META`
  (`files/meta.dat`), `VERSIONS` (`files/versions.blob`), `SHARES`
  (`shares.db`), `VAULTS_DB` (`vaults.db`), `VAULTS_BLOB` (`vaults.blob`).
  Deliberately NOT synced: `sessions.dat` (per-server, meaningless
  cross-server — a failed-over client does a fresh `AUTH_REQUEST`/
  `vw_client_connect`, never `vw_client_resume`, against the fallback),
  `chunks/refcounts.db` (the replica derives its own from the file/vault
  records it holds, never copies the primary's raw refcounts), `invites.db`/
  `recovery.db` (not needed for this feature's read-only surface — list/
  stat/download/share-list/vault-list/version-list; invite redemption and
  password recovery are writes anyway, which stay primary-only/queued
  regardless).
- `CLUSTER_FILE_SYNC_LIST` (`0x0708`) / `_RESP` (`0x0709`): request is
  empty (bound to the authenticated connection); response is one entry
  per syncable file above — `{u8 file_tag, u64 size, bytes[32]
  content_sha256}` — letting the replica diff against its own last-synced
  hash per file and skip re-fetching anything unchanged.
- `CLUSTER_FILE_SYNC_FETCH` (`0x070A`) / `CLUSTER_FILE_SYNC_DATA`
  (`0x070B`): request `{u8 file_tag}`; response `{u8 file_tag, u64 size,
  bytes[size] data}` — the file's ENTIRE current content (these are small
  fixed-record tables at this project's personal-deployment scale, not
  the actual file content that lives in `chunks/`; whole-file replace via
  the replica's existing `vw_fs_atomic_write` primitive is simple, always
  correct — no incremental-diff logic to get subtly wrong — and doesn't
  need to distinguish an append from an in-place update, which a
  byte-range-only sync would).
- `CLUSTER_CHUNK_QUERY` (`0x070C`) / `_RESP` (`0x070D`): reuses the
  existing `CHUNK_QUERY`/`_RESP` bitmask-over-up-to-1024-hashes wire shape
  verbatim (same field layout, new message-type numbers only) — after
  refreshing `VERSIONS`, the replica asks which of the hashes it now
  references it's still missing locally.
- `CLUSTER_CHUNK_FETCH` (`0x070E`) / `CLUSTER_CHUNK_DATA` (`0x070F`):
  request `{32-byte hash}`; response raw chunk bytes (reuses
  `CHUNK_DOWNLOAD_REQ`/`CHUNK_DATA`'s shape) — or a "not found" sentinel,
  which should be rare, not a normal case to silently tolerate (see
  `TASK-171`'s GC-gating fix for why).

**Sync trigger**: after appending a pulled `OPLOG_DATA` batch to its own
oplog (unchanged from today), if `count > 0` the replica runs one
`CLUSTER_FILE_SYNC_LIST` pass, fetches whatever changed, then a chunk
sweep over `VERSIONS`' current hash set. A full rescan every time
something changed (rather than trying to know in advance exactly which
of the 7 files a given oplog batch touched) is deliberately simple and
correct over clever and fragile.

## Acceptance criteria

- `docs/PROTOCOL.md` documents all eight new message types
  (`CLUSTER_FILE_SYNC_LIST`/`_RESP`/`_FETCH`/`_DATA`,
  `CLUSTER_CHUNK_QUERY`/`_RESP`/`_FETCH`/`_DATA`) with exact wire field
  layouts, matching this task's own (revised) descriptions above (adjust
  during writing if a field turns out to need a different shape — this
  doc is the actual source of truth once published, not this task file).
- Version-skew note: these messages are cluster-internal (primary and
  replica are administered together, same operator) — no client/server
  version-negotiation concern beyond what `NODE_HELLO` already carries.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**PRT.04 [2026-08-14]:** Published in `docs/PROTOCOL.md` §7.7 (message
table + full per-message payload specs) and §7.9 (security properties —
handler-reachability boundary, and an explicit note that a compromised
replica's blast radius now includes every user's password hash/2FA
secret, not just the oplog). Design revised mid-task (see this file's
own "Work" section, kept rather than silently replaced, per this
project's own convention of recording how a decision was reached) after
discovering `VW_OPLOG_FILE_CREATE`'s payload is written before `file_id`
is assigned — a per-op-type "fetch the record this id points to" design
cannot work, since the oplog gives no usable id for several op types.
Settled on whole-file sync of the 7 small fixed-record metadata tables
(triggered by oplog activity, never reading oplog content) plus the
existing chunk-existence-bitmask primitive reused verbatim for content.
`TASK-172`'s own "Work" section was updated to match before any code was
written against the abandoned design.

CQR.08 self-review: confirmed the file-tag enum (not a free-form path)
closes off a path-traversal question before it could ever be asked;
confirmed `sessions.dat`/`refcounts.db`/`invites.db`/`recovery.db` are
each excluded for a stated, checkable reason (not just omitted) rather
than silently forgotten. No blocking findings.

**Correction [2026-08-14], found starting `TASK-172`'s implementation:**
this task's own "Work" section above (left as originally written, per
this project's append-only-notes convention — corrected here, not
silently edited there) undercounted the syncable files by one:
`files/versions.blob` is NOT the only file backing version data —
`vw_store_files.c` has a THIRD file, `files/versions.dat` (the fixed-size
`vw_version_record_t` array itself: `chunk_count`, `blob_offset`,
`vault_id`, wrapped-DEK offset/len), separate from `versions.blob` (the
variable-length chunk-hash arrays + wrapped-DEK bytes that
`versions.dat`'s `blob_offset` points into). Missed because the earlier
research pass's grep for path construction happened to only catch the
`.blob` call site, not the `.dat` one, in this one file. `docs/
PROTOCOL.md` §7.7 now lists 8 syncable files (tag 4 = `versions.dat`,
tag 5 = `versions.blob`, synced as a pair — `blob_offset` is only
meaningful relative to a `versions.blob` fetched at the same time), not
7 — verified against `vw_store_files.c`'s own header comment (`meta.dat`
/ `versions.dat` / `versions.blob`, one per line) this time, not just
its `open()` function's path-construction call sites, before re-closing
this correction.
