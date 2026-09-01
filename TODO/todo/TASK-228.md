---
id:          TASK-228
title:       "On-demand SAF upload/download with UIDT/foreground-service transfer execution"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-226, TASK-227]
blocks:      [TASK-229]
review_by:   [CQR.08]
tags:        []
---

Implement the actual file transfer path. Per the scope decision recorded in
`ARCHITECTURE.md`, this is on-demand only (Drive-app style) — no continuous
background folder mirroring, so no `WorkManager`/periodic job is needed here.

Scope:
- Downloads: `Intent(ACTION_CREATE_DOCUMENT)` (single file) or a persisted SAF
  tree (`ACTION_OPEN_DOCUMENT_TREE` + `takePersistableUriPermission`) for
  "download to my folder." Write via
  `ContentResolver.openFileDescriptor()` — the native layer gets a raw fd for
  the user-visible destination, never a resolved path.
- Uploads: `ACTION_OPEN_DOCUMENT`/`_TREE` fd → read into the app's private
  cache dir (a real POSIX path — `vw_fs.c` needs no changes here) → chunk →
  send via `VwClient`.
- Folder transfers: recurse the chosen SAF tree (or remote folder) using
  `androidx.documentfile`'s `DocumentFile`, batching where possible since
  `DocumentFile.listFiles()` is slow for large trees.
- Execute an in-progress transfer as a User-Initiated Data Transfer job
  (`JobScheduler.setUserInitiated()`, API 34+) with a `dataSync`-typed
  foreground service + persistent notification as the pre-API-34 fallback.
- Progress reporting hook for the UI (TASK-229) to bind to.

## Acceptance criteria

- A user can pick a local file/folder and upload it, and pick a remote
  file/folder and download it to a chosen local destination, with visible
  progress and a persistent notification while in flight.
- Transfer survives the app being backgrounded (verified on both the UIDT
  path where available and the foreground-service fallback).
- No path-based access is attempted outside the app's private cache dir for
  anything the user didn't explicitly pick via SAF.

## Notes
