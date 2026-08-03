---
id:          TASK-113
title:       Shared-folder sync cannot self-heal a locally-created subdirectory with no remote counterpart
status:      todo
assignee:    CLI.02
created_by:  CLI.02
created:     2026-08-03
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [client, sync]
---

Surfaced by CQR.08's review of TASK-112. In `exec_action()`'s `ACT_UPLOAD`
handling for a shared folder (`src/client/vw_sync.c`), when a new file's
parent directory has no entry in `dirmap` (i.e. no server-side counterpart
exists yet for that subdirectory), the action is left un-actionable for
the cycle with a comment characterizing this as transient ("not
actionable yet").

CQR.08 traced this and found no mechanism in the sync engine that ever
creates the missing remote directory automatically — `vw_client_file_mkdir`
/ `VW_IPC_FILE_MKDIR_REQ` exists (TASK-104) but is only reachable via an
explicit user-issued `mkdir` CLI command, never invoked by
`sync_one_folder`/`compute_actions`. `dirmap` is populated purely from a
BFS over directories that already exist server-side
(`srv_collect_by_id`). So a user who creates a new subdirectory locally
inside a shared folder and adds files to it gets an upload that silently
fails to make progress on every single sync cycle, indefinitely, unless
they separately run `mkdir` for that path themselves — this is not
actually self-healing despite the existing comment's framing.

TASK-112 made this at least *visible* (it's now counted toward the
daemon's status `error_count`), but visibility isn't a fix — the
underlying UX gap is real: creating a subfolder inside a synced shared
folder should work the same way it does for an owned folder.

## Acceptance criteria

- Decide the intended behavior: either (a) the sync engine auto-issues
  `FILE_MKDIR` for an unresolvable parent directory when the grantee has
  sufficient permission (EDIT or above) on the share, ceding to a
  permission error path when it doesn't, or (b) some other explicit
  resolution — but "silently retries the same no-op forever" is not
  acceptable as the final behavior.
- If auto-mkdir is implemented: handle the permission-denied case
  distinctly from "will retry next cycle" so a VIEW-only grantee who
  creates a local subfolder gets a clear, distinct status/error rather
  than the same generic action-error count as everything else.
- Regression test: a new local subdirectory (with files) created inside a
  synced shared folder eventually syncs successfully (or, for a VIEW-only
  grant, surfaces a clear and distinct permission error) — not an
  indefinitely-repeating no-op.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-08-03]: Filed from CQR.08's TASK-112 review finding. Not
folded into TASK-112 itself — TASK-112's scope was narrowly "surface
existing per-action failures into status," and this is a materially
larger behavioral fix (new remote-mutation logic gated on permission
checks), not a status-reporting change. TASK-112 was updated to at least
count this case as an action error in the interim, so it is no longer
silently invisible while this task is open.
