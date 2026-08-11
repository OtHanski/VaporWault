---
id:          TASK-139
title:       Frontend upload/download with per-file progress
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-133, TASK-138]
blocks:      []
review_by:   [CQR.08]
tags:        [web]
---

Build upload/download against `TASK-133`'s chunk-level endpoints, driving
the `CHUNK_QUERY`→`CHUNK_UPLOAD`→`FILE_COMMIT` (upload) and
`VERSION_CHUNKS`→`CHUNK_DOWNLOAD_REQ` (download) steps directly from the
browser, one HTTP request per chunk step — per `TASK-127`'s note, this gives
real per-file byte progress without any new gateway-side status/polling API
(unlike the existing IPC protocol, which only ever exposes aggregate
pending counts, `vw_ipc.h`'s `VW_IPC_STATUS_RESP`).

Scope: file picker/drag-and-drop upload, progress bar per in-flight
transfer (bytes transferred / total, driven by the chunk loop's own
request/response cycle), resumable-on-reload behavior is out of scope for
this task unless trivial (flag as a follow-up if not).

## Acceptance criteria

- Uploading and downloading a multi-chunk file (>4 MiB) shows real
  incrementing progress, not a spinner.
- A dropped connection mid-upload fails cleanly with a retry option, rather
  than leaving a partial/corrupt commit.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave.
