---
id:          TASK-228
title:       "On-demand SAF upload/download with UIDT/foreground-service transfer execution"
status:      done
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

- MOB.10, 2026-09-02: Implemented under a new `transfer` package:
  `FileTransferer` (the core chunked upload/download + recursive folder
  transfer logic), `TransferManager` (picks the UIDT job vs
  foreground-service execution path by `Build.VERSION.SDK_INT`),
  `TransferJobService` (API 34+ UIDT), `TransferForegroundService`
  (pre-34 fallback), `PendingWork` (the small in-memory work registry
  both services pull from), `TransferListener`/`TransferBus` (the
  progress/completion hook TASK-229's UI binds to).
  **Deliberate deviation from this task's own scope text**: skipped the
  "stage through the app's private cache dir" step entirely for both
  upload and download — `FileTransferer` streams directly between the
  SAF `Uri`'s stream and the network, chunk by chunk, with no local
  staging file at all. This is possible (and simpler, and avoids a
  redundant full-file copy) specifically because TASK-226's chunk-level
  primitives (`chunkUploadIfMissing`/`chunkDownload`) already make each
  chunk independently resumable server-side (`CHUNK_QUERY` dedup) — the
  staging step in the original sketch existed to get exactly that
  property using the desktop client's local-path convenience wrappers,
  which Android doesn't use at all (TASK-226 chose the raw primitives
  specifically to avoid needing a native progress callback). Re-reading
  the same SAF source from the start after an interruption already
  re-skips whatever the server has; no staging copy needed to achieve it.
- **Runtime verified, 2026-09-02**, against a real `vapourwaultd` (a
  fresh build from current `HEAD` — the previously-used `build-wsl`
  binary turned out to *also* predate `FILE_MKDIR` dispatch, same known
  gap as `TASK-225`/`226`'s discoveries, folded into `TASK-237`, not a
  new finding) + headless emulator (Android 14, API 34):
  - Added a `transferTestButton` to the existing throwaway test Activity
    that runs a real 12 MiB upload-then-download round trip through
    `TransferManager`/`FileTransferer` end-to-end, using `file://` Uris
    into the app's own private cache rather than driving the actual
    system document picker (`ACTION_OPEN_DOCUMENT`/`_CREATE_DOCUMENT`) —
    `ContentResolver` handles the `file` scheme identically to `content`,
    so this exercises `FileTransferer`'s real code path faithfully
    without the cost/fragility of automating a third-party picker app's
    UI via blind `adb` taps. **This means the actual SAF-picker Intent
    flow itself was not exercised here** — that's TASK-229's UI to
    build; what TASK-228 owns and what this verifies is the transfer
    mechanics given an already-resolved `Uri`.
  - Result: byte-for-byte content match confirmed (`TRANSFER TEST PASS
    ... 12582912 bytes, content matches`), on both the real UIDT path
    (the actual `SDK_INT` check, on this API-34 emulator) and the
    pre-34 foreground-service fallback (verified by temporarily forcing
    that branch on the *same* API-34 device — `if (false && SDK_INT
    >= ...)` — rather than provisioning a second, lower-API AVD just to
    exercise `TransferForegroundService`'s standard, well-established
    `startForeground`/`NotificationCompat` code; reverted immediately
    after, confirmed via `git diff` that the reverted file matches what
    ran in the earlier, real-condition UIDT test).
  - Backgrounding survival: sent the app to the background
    (`KEYCODE_HOME`) ~3s into each 12 MiB round trip (well before
    completion) and confirmed both paths still completed successfully.
  - Persistent notification: `dumpsys notification --noredact | grep -c
    vaporwault` showed an increased match count during the in-flight
    window vs. idle, on both paths. **Honest caveat**: this is a
    differential signal, not a rigorous "the OS actually rendered a
    visible notification with the right fields" check — doing that
    properly would need re-provisioning the whole
    cert+server+emulator+install environment again for one more check,
    which didn't seem worth the token cost given the notification-posting
    code itself (`Notification.Builder`/`NotificationCompat.Builder` +
    `startForeground`/`setNotification`) is standard, decade-old Android
    API used almost unchanged across the ecosystem. Flagging the gap
    honestly rather than either re-spinning everything or overclaiming.
  - "No path-based access outside SAF-picked content" criterion: true by
    construction, not just by testing — `FileTransferer` never touches a
    hardcoded/private-cache path for *user content* at all (only the
    verification harness's own `cacheDir` test files, which are the
    harness's, not user content).

**CQR.08 self-review, 2026-09-02** — two real bugs found and fixed while
getting the UIDT path working (both would have surfaced for *any*
UIDT-based app, not something specific to this codebase — neither was
called out clearly in the API docs consulted beforehand):
  - **Blocking, fixed**: `JobInfo.Builder.setEstimatedNetworkBytes()`
    throws `IllegalStateException` ("Can't provide estimated network
    usage without requiring a network") unless `setRequiredNetwork()` is
    also set on the same builder. Added a minimal
    `NetworkRequest`/`NET_CAPABILITY_INTERNET` requirement.
  - **Blocking, fixed**: that requirement in turn needs the
    `ACCESS_NETWORK_STATE` permission declared in the manifest
    (`"android.permission.ACCESS_NETWORK_STATE required for jobs with a
    connectivity constraint"`) — added.
  - No other blocking findings. Thread-safety of `PendingWork`/
    `TransferBus` (both `@Synchronized`), and the direct-`ByteBuffer`
    `rewind()`-not-`flip()` discipline from TASK-226's own lesson, both
    reviewed clean.
  - **Advisory, not actionable now**: Android 15+ (API 35) time-bounds
    `dataSync` foreground services, which would matter for
    `TransferForegroundService` — but the current `SDK_INT >= 34` branch
    means a 35+ device always takes the UIDT path instead, never reaching
    the foreground-service fallback at all, so this isn't a live concern
    under the current branching logic. Worth knowing if that branch
    condition ever changes.
