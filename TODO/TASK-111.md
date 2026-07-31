---
id:          TASK-111
title:       Harden shared-folder sync: narrow revocation detection, cap tree walk size
status:      todo
assignee:    CLI.02
created_by:  CLI.02
created:     2026-07-31
priority:    low
depends_on:  [TASK-106]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [client, sync, security-sensitive]
---

Two advisory (non-blocking) findings from TASK-106's independent SEC.07/
CQR.08 review, deliberately not fixed as part of that task's closure since
neither is exploitable beyond what a legitimate share owner could already
do directly, but both are worth hardening.

## 1. Revocation-detection is coarser than "revocation," with a narrow
   delete-race false trigger

`sync_one_folder` (`src/client/vw_sync.c`) treats *any*
`VW_ERR_NOT_FOUND`/`VW_ERR_PERMISSION` from `srv_collect_by_id` — at any
BFS level, not just the root — as a revocation signal and permanently
pauses the whole sync folder. `vw_share_resolve_permission` is a pure
"max over all matching active grants" (permission can only be equal-or-
higher moving down an inherited subtree, never selectively restricted),
so there's no way for a *valid* share to have an inaccessible subtree
today — but there is a genuine TOCTOU: a subdirectory is enqueued using
the `file_id` discovered a moment earlier in the *same* BFS pass. If the
owner deletes exactly that subdirectory between discovery and the
subsequent `FILE_LIST_BY_ID` call on it, the resulting `NOT_FOUND` is
indistinguishable from a real revocation and pauses the entire folder for
an ordinary delete, not a grant change.

Fix: only treat a `NOT_FOUND`/`PERMISSION` from the **root** id (stable
across the whole cycle, resolved from the persisted `remote_dir_id`) as a
revocation signal; a same-cycle subdirectory disappearing should be
treated the way `srv_collect` already treats it for owned folders (skip
that branch, not fatal for the whole folder).

## 2. Unbounded client-side resource use walking an owner-shaped tree

`srv_collect_by_id`'s `dirmap_t`/`srv_list_t` (`src/client/vw_sync.c`)
have no cap on total directories or entries across the whole BFS — each
individual `FILE_LIST_BY_ID` call is capped server-side at 65535 entries,
but the number of *calls* (i.e. directories) is unbounded. Shared-folder
sync is the first feature where a client's sync engine walks a tree shape
it did not itself author: a folder owner who shares even at VIEW can grow
an arbitrarily large/deep tree under the shared root and force the
grantee's daemon into unbounded allocation/CPU/bandwidth on every sync
cycle once the grantee adds that share as a sync target.

Fix: a sane ceiling (total dirs/entries, or depth) that auto-pauses (with
a distinct status/reason, not conflated with revocation) rather than
growing without bound — mirroring the 65535-entry philosophy already
applied per-call server-side.

## Acceptance criteria

- Revocation auto-pause only fires on a root-id NOT_FOUND/PERMISSION; a
  same-cycle subdirectory deletion during the BFS no longer pauses the
  whole folder.
- A regression test proving the above: a subdirectory deleted between
  BFS discovery and its own listing call does not pause the folder,
  while an actual revocation still does.
- A configurable (or reasonably-chosen fixed) ceiling on total shared-
  folder BFS size, with a distinct pause reason/status when hit, and a
  regression test exercising it.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-07-31]: Filed from TASK-106's independent review findings #3
and #4 (see TODO/TASK-106.md's closing sign-off note for the full review).
Deliberately deferred rather than folded into TASK-106 itself — neither
finding is exploitable beyond what the share owner could already do
directly, and both deserve a proper regression test rather than a rushed
fix appended to an already-closing task.
