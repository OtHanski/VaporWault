---
id:          TASK-139
title:       Frontend upload/download with per-file progress
status:      review
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

WEB.09 [2026-08-11]: This task was blocked on backend chunk-transfer
endpoints that `TASK-133` had deferred — implemented those first (see
`TASK-133`'s addendum note: `/api/chunks/upload`, `/api/files/commit`,
`/api/versions/chunks`, `/api/chunks/download`), then built this task's
frontend on top: `web/src/api.ts` gained `uploadFile`/`downloadFile`,
driving the chunk loop directly per this task's own design note (one
`fetch()` per chunk, real cumulative byte progress via a callback, no
gateway-side status/polling API). Hashing uses the browser's native
`crypto.subtle.digest("SHA-256", ...)` — no crypto library needed for
plaintext content. `web/src/main.ts` adds an Upload button (hidden file
input) and a per-file Download row action, both driving a shared
transfer-progress-list UI (`web/index.html`'s `#transfer-list`, styled in
`style.css`) with a live percentage bar per in-flight transfer.

**Both acceptance criteria verified against the real compiled output**,
not just type-checked — via throwaway Node scripts (not committed) that
import the actual compiled `web/dist/api.js` and drive it against the
live WSL gateway+server:
- *Real incrementing progress on a >4 MiB file*: uploaded and downloaded
  a 10 MiB file (3 chunks: 4+4+2 MiB), captured every progress callback
  value, confirmed each is a real intermediate byte count (not a single
  jump to 100%), and confirmed the downloaded bytes are byte-for-byte
  identical to the original.
- *A dropped connection mid-upload fails cleanly with a retry option*:
  killed the actual gateway *process* between chunk 1 and chunk 2 of a
  real upload (mid-flight, via the same WSL gateway used throughout this
  session), confirmed `uploadFile` throws immediately rather than
  continuing or silently swallowing the failure, confirmed via
  `files/list` that **no partial/corrupt file was ever committed** (this
  holds by construction: `FILE_COMMIT` is only ever sent after every
  chunk succeeds — a mid-upload failure just leaves whatever existed at
  that path untouched), restarted the gateway, and retried the *identical*
  `uploadFile` call from scratch — it completed successfully. The retry
  affordance itself (`main.ts`'s "Retry" button on a failed transfer item,
  which just re-invokes the same upload/download call) is a thin UI
  wrapper over this already-proven-safe retry semantics; the button's own
  click-handling hasn't been exercised in a real browser DOM (same
  no-browser-available caveat as `TASK-136`-`138`), but the underlying
  retry logic it calls has been.

Not implemented (explicitly out of scope per this task's own text):
resumable-on-reload (a reload restarts the whole file from chunk 1 — no
worse than before this task, and chunk-level server-side dedup means a
resumed upload doesn't re-transfer bytes the server already has, even
though the browser doesn't yet skip re-hashing/re-sending them itself).
Flagging as a reasonable follow-up rather than solving here.

Builds clean under `tsc --strict`.

Moving to `review` — needs CQR.08 sign-off.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave.
