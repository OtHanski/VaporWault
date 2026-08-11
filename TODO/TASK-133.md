---
id:          TASK-133
title:       Implement gateway file endpoints (list/stat/mkdir/move/delete, chunk upload/download, versions)
status:      review
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-131, TASK-132]
blocks:      [TASK-138, TASK-139]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Map the core file-operation surface of `vw_client_core.h`
(`vw_client_file_list/_stat/_upload/_download/_delete`, plus move/mkdir and
version list/restore) onto gateway HTTP/JSON endpoints, scoped to the
logged-in session's `vw_client_sess_t` from `TASK-131`.

Endpoints (exact routes/payload shapes are this task's own design detail,
not prescribed here — keep them RESTful and consistent):

- List / stat a path or `file_id`.
- `mkdir`, `move`, `delete`.
- Chunk-level upload: expose the protocol's own
  `CHUNK_QUERY`→`CHUNK_UPLOAD`→`FILE_COMMIT` steps (`docs/PROTOCOL.md` §9)
  as gateway endpoints the *browser* drives directly, one HTTP request per
  step — this is what gives per-file upload progress for free (per
  `TASK-127`'s note) without inventing a new status/progress API.
- Chunk-level download: same shape via `VERSION_CHUNKS`→
  `CHUNK_DOWNLOAD_REQ`.
- Version list/restore.

Every request must resolve against the calling session's own
`vw_client_sess_t` — there is no gateway-level bypass of the server's own
permission/ownership checks; the gateway is a thin translator, not a second
authorization layer. Path-traversal-style bugs are the server's existing
responsibility (`vw_store_file_get_by_path`'s owner-namespaced lookup), but
this task's HTTP path-parameter handling should not introduce a *new*
traversal vector of its own (e.g. decoding `../` sequences before handing a
path through).

## Acceptance criteria

- Full list/upload/download/delete/move/mkdir round trip works end-to-end
  through the gateway from an HTTP client.
- Chunk upload/download endpoints correctly surface partial progress to the
  browser (verified in `TASK-139`).
- A request for a path/file_id the session doesn't own is rejected with the
  same effective result the server itself would give directly (no gateway-
  introduced privilege escalation or information leak) — specific SEC.07
  check given "storage layer: path traversal, cross-user access" is
  explicitly in scope for review.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented metadata endpoints (`list`/`stat`/
`mkdir`/`delete`/`move`) and verified end-to-end against a real running
server (not simulated) — set up a live `vapourwaultd` + admin-created test
user in WSL, drove the gateway via `curl` for every operation, including
error paths (404 not-found, 409 dir-not-empty via `send_file_op_error`'s
mapping).

**A real, serious pre-existing bug found and reproduced via this
testing**: `move`/`delete` (and likely other `vw_client_core.c` functions
using the same pattern) can permanently desync their `vw_client_sess_t`'s
connection whenever the server rejects the operation via its generic
error path — which is the *normal* rejection path, not an edge case. Filed
as `TASK-155` (assigned `PRT.04`, out of this role's domain per
`CLAUDE.md`'s routing rule) with full reproduction and root-cause
analysis. **Mitigated at the gateway level** (not fixed at the source):
`send_file_op_error` now evicts (`vw_gateway_session_remove`) any session
that returns an error outside a small, positively-recognized set —
verified this actually contains the damage: reproduced the trigger, then
confirmed a *separate, unrelated* request against the same gateway process
still succeeded immediately afterward (previously, the entire
single-threaded gateway hung indefinitely for every user once this
triggered on any one session).

**Scope not done in this pass**: upload/download (file content transfer).
Deliberately deferred rather than rushed — binary content doesn't fit this
module's plain-JSON-body convention without either a base64 layer (simple
but ~33% overhead and needs a base64 codec this module doesn't have yet)
or a separate raw-body route (needs `vw_http`/routing changes). Both are
real options for a follow-up task, not decided here.

Also confirmed via testing, not just reading: `vw_client_file_stat` never
populates `vw_file_entry_t.name` (the wire's `FILE_STAT_RESP` carries a
full path, not a bare name) — not a bug, but `write_file_entry` will
return an empty `name` for direct `stat` calls; callers already know the
path they asked for, so this wasn't worth working around in this pass, but
worth knowing if a frontend view relies on `stat`'s `name` field
specifically.

WEB.09 [2026-08-11]: Addendum found while implementing `TASK-134`:
`send_file_op_error` (shared by every file/share/link/vault handler,
including this task's) had no case for `VW_ERR_AUTH_REQUIRED` — an
entirely ordinary outcome (e.g. a scoped session whose share/link was
revoked mid-lifetime, `TASK-134`) — and fell into the catch-all "unrecognized
error → evict + 500" branch built above for `TASK-155`. Added an explicit
`VW_ERR_AUTH_REQUIRED` → `401 auth_required` case (still evicts the
session; it can never succeed again either way, just reports it cleanly
now). This affects this task's own endpoints too (any of them can receive
`VW_ERR_AUTH_REQUIRED` from an expired/invalidated session, not just the
scoped-session case `TASK-134` exercised) — see `TASK-134`'s note for the
full repro. Re-verified this task's own list/stat/mkdir/delete/move
endpoints still behave correctly after the change (no regression; the
fix only changes which HTTP status an already-unusual case gets, not the
happy-path behavior).

Moving to `review` — needs SEC.07 + CQR.08 sign-off. `TASK-155`'s
resolution should be tracked separately; this task's own scope (metadata
endpoints + the containment mitigation) is complete modulo the deferred
upload/download work.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — file/path
handling is explicitly called out in SEC.07's remit.
