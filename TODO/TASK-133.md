---
id:          TASK-133
title:       Implement gateway file endpoints (list/stat/mkdir/move/delete, chunk upload/download, versions)
status:      todo
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

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` — file/path
handling is explicitly called out in SEC.07's remit.
