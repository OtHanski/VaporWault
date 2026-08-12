---
id:          TASK-113
title:       Shared-folder sync cannot self-heal a locally-created subdirectory with no remote counterpart
status:      done
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

CLI.02 [2026-08-03]: Implemented option (a) — auto-mkdir.

Added `resolve_or_create_dir()` (`src/client/vw_sync.c`), called from
`compute_actions()` in place of the old plain `dirmap_lookup()` for a new
local file inside a shared folder. It recursively resolves (and, via
`vw_client_file_mkdir`, creates) however many missing ancestor directory
levels are needed, walking up from the immediate parent to the nearest
already-known directory (at worst the shared folder's own root, which
`srv_collect_by_id` always seeds into `dirmap` unconditionally) and back
down, pushing each newly-created directory into `dirmap` as it goes so a
second new file under the same brand-new subdirectory in the same cycle
doesn't re-attempt the mkdir.

Outcome classification:
- Success → `dirmap` gets the new id, the upload proceeds in the same
  cycle (mkdir-then-upload, not deferred to next cycle).
- `VW_ERR_PERMISSION` (grantee lacks EDIT) → counted via a **new**,
  **distinct** counter (`permission_denied_count` /
  `vw_sync_permission_denied_count()`), not folded into the existing
  `action_errors` — satisfies the acceptance criterion that this not read
  as a generic action failure. Surfaced through a new field on
  `VW_IPC_STATUS_RESP` (`src/client/vw_daemon.c`, `vw_ipc.h`) and a new
  `vapourwault-cli status` line, and logged distinctly
  (`vw_daemon.c`'s main loop). Deliberately does **not** count toward
  `error_count` and does **not** auto-pause the folder — this is a
  per-item problem, not a share-wide one (pausing the whole folder over
  one over-ambitious VIEW-only-created subfolder would be a worse
  regression than the silent no-op this task fixes).
- `VW_ERR_ALREADY_EXISTS` (benign create race) → left unresolved this
  cycle, not counted at all; the next cycle's normal BFS discovers it.
- A genuine network error → propagated verbatim so the whole sync cycle
  aborts/retries the same way any other network failure during sync does.
- Any other unexpected error → falls back to the existing
  `note_action_error()` counter.

Caught one subtlety while wiring the CLI's new status line: the legacy
`run_integration.py` IT-7 sub-test (just fixed in TASK-110/112) parses
`vapourwault-cli status` output positionally
(`line.split()[-2]` on the line containing "errors"). Appending
`permission-denied` to the *same* "Pending: ... errors" line would have
shifted that index and silently broken IT-7 again — put it on its own
line instead.

**Regression tests:** new `tests/integration/test_shared_sync_mkdir.c` (+
`.py` wrapper): an EDIT grantee's one-level *and* nested two-level new
subdirectories both land server-side in a single sync cycle (proving the
recursive ancestor creation); a VIEW-only grantee's equivalent attempt
returns cleanly, is counted via `permission_denied_count` specifically,
results in *no* unauthorized server-side write, and does *not* pause the
folder.

**Full verification:** `build-wsl-werror` (gcc, warnings-as-errors) clean
rebuild; full `ctest` (14/14, including IT-7 specifically re-checked
after the CLI status-line change); `pytest` across
`test_shared_sync{,_hardening,_mkdir}.py`, `test_quota.py`,
`test_sharing.py`, `test_dedup.py`, `test_gc.py`, `test_file_ops.py`,
`test_auth.py` — 47/47 pass.

Sent for review (CQR.08 per this task's `review_by`; not tagged
security-sensitive, so SEC.07 isn't required, though the permission-check
reliance is worth a second look given it gates a remote-mutation call).

CQR.08 [2026-08-03]: Reviewed. **One blocking finding**, three advisory.

**Blocking (fixed):** `resolve_or_create_dir()` already classifies and
counts every non-fatal outcome (permission denial, benign
`ALREADY_EXISTS` race, or genuine error) exactly once — but the
pre-existing TASK-112 fallback branch in `exec_action()` (`parent_dir_id
== 0` → `note_action_error(ctx)`) was never updated when
`resolve_or_create_dir` was added, so it *also* counted the same
already-classified outcome a second time on every call, directly
contradicting the acceptance criteria ("distinct... rather than the same
generic action-error count") and this task's own notes above. Confirmed
the existing test didn't catch it because neither scenario checked
`vw_sync_action_error_count()`. Fixed: removed the redundant
`note_action_error()` call from that branch (it's now purely a no-op
marker — `resolve_or_create_dir` is the sole source of truth for
counting) and rewrote its stale comment (it still referenced TASK-113 as
open). Verified by temporarily re-adding the redundant call and
confirming the strengthened test (see below) fails specifically on the
new exact-count assertion, then restoring the fix and re-verifying green.

**Advisory (addressed):** the reviewer also flagged that N sibling files
newly created under the same still-unresolved directory in one cycle
would each independently re-attempt `vw_client_file_mkdir` and
re-increment whatever counter applied — redundant RPCs and, combined
with the blocking bug above, redundant counting. Added a
`VW_DIRMAP_UNRESOLVABLE` sentinel: once `resolve_or_create_dir` gives up
on a directory this cycle (ancestor unresolved, permission denied, or a
genuine error — but deliberately NOT for the benign `ALREADY_EXISTS`
race, which should get a fair fresh lookup), it memoizes that outcome
into `dirmap` so subsequent lookups for the same path this cycle
short-circuit without a second RPC or a second count.

**Advisory (not separately actioned):** the reviewer's stale-comment
finding was fixed as part of the blocking fix above (same branch). The
"no ceiling on total mkdir attempts per cycle, unlike TASK-111's BFS cap"
point is addressed in spirit by the memoization above (the actual
amplification vector — redundant attempts for the *same* directory — is
now capped at one per directory per cycle); a raw ceiling on the number
of *distinct* new directories a cycle can attempt was judged
disproportionate to file, since (unlike TASK-111's BFS walk, which is
entirely owner-controlled data a grantee has no say over) the local
directories being created here are the grantee's own choice on their own
filesystem, and the server's existing
`vw_share_scoped_write_ratelimit_check` remains a backstop against actual
abuse.

**Test coverage (strengthened):** `test_shared_sync_mkdir.c`'s VIEW-only
scenario now creates two sibling files under the new directory (was one)
and asserts `vw_sync_permission_denied_count(...) == 1` (exact, was
`>= 1`) and `vw_sync_action_error_count(...) == 0` (new) — this exact
pairing is what caught the blocking bug above; the EDIT scenario gained
the matching `action_error_count == 0` check. Re-verified: full `ctest`
(14/14) and `pytest` sweep across
`test_shared_sync{,_hardening,_mkdir}.py`, `test_quota.py`,
`test_sharing.py` — 27/27 — after both fixes.

Review requirement satisfied. Marking done.
