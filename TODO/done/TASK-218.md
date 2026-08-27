---
id:          TASK-218
title:       "Background sync never creates a remote folder for a new local subdirectory"
status:      done
assignee:    CLI.02
created_by:  CLI.02
created:     2026-08-26
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [sync-engine]
---

Discovered while writing `TASK-199`'s `test_cli_search.py`: creating a new
local subdirectory inside an already-synced folder and putting a file in
it (`mkdir sub && echo x > sub/file.txt`, both done locally, outside the
CLI/GUI) never uploads. The daemon's sync cycle repeats
`"sync cycle for '<user>' had 1 action error(s)"` indefinitely and the
file never appears on the server.

Root cause (traced while debugging, not yet fixed): `vw_sync.c`'s local
tree walk (`walk_recursive`/`walk_cb`) recurses into subdirectories but
only ever pushes **files** into `lfiles` — a directory is never itself
represented as an entity to sync. There is no `ACT_MKDIR` action anywhere
in `vw_sync.c` (grepped; zero matches) for a *local-only* new directory —
the only directory-creation path that exists is the reverse direction
(`TASK-113`: a directory that already exists *on the server* gets
mkdir'd locally when a grantee first sees it). Consequently, when
`ACT_UPLOAD` for a file under a brand-new subdirectory reaches
`vw_client_file_upload` → server `FILE_COMMIT`, the server's own
parent-directory resolution (`vw_file_handlers.c`, the `file_id == 0`
path-based branch) does a plain `vw_store_file_get_by_path` lookup for
the parent and returns `VW_ERR_NOT_FOUND` if it doesn't already exist —
there is no auto-create-missing-parent-directories behavior there either
(by design — FILE_COMMIT documents itself as a leaf-level operation).

Net effect: a locally-created subdirectory + file combination can never
sync up through ordinary background sync, only through the CLI/GUI's own
explicit `mkdir` command creating the matching remote folder *first*,
which is not how a normal filesystem watcher user would expect this to
behave (most cloud-sync products treat "create a folder locally" as
sync-worthy on its own).

## Work

- Make the local walk (`lfiles`/`walk_recursive`) aware of directories as
  first-class entities, not just a recursion mechanism — or generate an
  implicit `ACT_MKDIR` the first time an `ACT_UPLOAD`'s parent path isn't
  found in the server's tree.
- Decide and document the ordering/idempotency story: multiple files
  newly appearing under the same brand-new subdirectory in one cycle
  must not attempt to mkdir the same remote folder more than once (or
  must tolerate `VW_ERR_...` for "already exists" cleanly if they do).

## Acceptance criteria

- Creating a new local subdirectory with a file inside it, under an
  already-added sync folder, uploads both the new remote folder and the
  file within a normal sync cycle — no manual `mkdir` step required.
- A regression test proves this with a real daemon + server round-trip
  (this gap has no existing test either, which is presumably why it went
  unnoticed).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

CLI.02 [2026-08-26]: Filed per `CLAUDE.md`'s discovery rule while
implementing `TASK-199`. Worked around in `test_cli_search.py` by not
relying on a newly-created local subdirectory — did not attempt a fix
here, out of that task's scope.

CLI.02 [2026-08-26]: Fixed. Two independent root causes, both real, both
required — fixing only the first (which is all this task's own filed
description above described) was not enough to make the real end-to-end
repro pass; the second was found by actually running the repro against a
real daemon+server rather than trusting the analysis alone.

**Root cause 1 (as filed)**: `resolve_or_create_dir()` (`vw_sync.c`) only
ever ran for a SHARED folder's new file (`TASK-113`) — an OWNED folder's
`ACT_UPLOAD` never called it at all, so a missing parent directory was
never created, and `vw_client_file_upload`'s server-side path resolution
correctly (and permanently) returned `VW_ERR_NOT_FOUND`.

Fix: extended `resolve_or_create_dir()` to also handle an owned folder's
tree, gated by a new `shared` parameter (its call sites already know
this — `folder->remote_dir_id != 0`). The two trees need genuinely
different resolution strategies, not just a flag to skip a check:
- A SHARED folder's whole tree is BFS-pre-populated into `dm` by
  `srv_collect_by_id` before this function is ever called — "not in dm"
  there really does mean "doesn't exist yet."
- An OWNED folder never goes through that BFS — "not in dm" only ever
  means "never looked up." The owned branch resolves each level by path
  (`vw_client_file_stat`, which works for an owned tree, unlike a
  shared one namespaced to the caller's own owner_id) before ever
  considering a create, including for the folder's own registered root
  (never pre-seeded either) — except a folder's own root is never
  auto-*created* if genuinely missing, only auto-*resolved*; a vanished
  root is a different problem to surface some other way.
- A subtlety this surfaced and had to be fixed too: `root_vpath == "/"`
  legitimately resolves to file_id 0 (this protocol's own convention for
  "server root," `FILE_MKDIR`/`FILE_LIST`), but 0 is also this
  function's own "not yet resolved" value — treating a root-level
  file's correctly-resolved parent_id of 0 as "ancestor failed" would
  have deferred every such upload forever. The ancestor-failure check
  was changed from `parent_id == 0` to an explicit `dirmap_lookup(dm,
  parent_vpath) == VW_DIRMAP_UNRESOLVABLE` check, since only the
  sentinel unambiguously means failure — 0 does not.
- Extended `compute_actions`'s `ACT_UPLOAD` generation to call this for
  every new file (previously shared-only), still passing
  `parent_dir_id = 0` to `action_push` for the owned case (unused by
  `exec_action`'s plain, path-based owned upload — the call's only job
  there is the *side effect* of having created the missing directory).

**Root cause 2 (found while actually running the fix against a real
daemon+server — root cause 1 alone did not make the repro pass)**: the
filesystem watcher fires its own CREATED event for a new subdirectory
itself, not just for files inside it. `vw_sync_mark_local_modified()`
(`vw_daemon.c`'s watcher-event dispatch calls this directly, separately
from the periodic full-walk `compute_actions` path) unconditionally
treated whatever path it was given as `entry_type = VW_ENTRY_FILE` —
for a directory path, this poisoned the cache with a permanent bogus
"file" entry that nothing else in this module ever revisits or corrects
(the periodic walk's `lfiles_push` only ever pushes real files,
confirmed by direct tracing — recursing into directories instead, never
representing one as its own entry). Every later cycle picked this bogus
entry back up as a "new file" and repeatedly attempted a real upload of
what's actually a directory — guaranteed to fail every time. This was
the actual, second, cause of the perpetually repeating "1 action
error(s)"; fixing only root cause 1 left this loop unbroken.

Fix: `vw_sync_mark_local_modified()` now checks `is_directory(local_path)`
first and returns immediately for a directory — the same helper the
local walk already uses, so no new "what counts as a directory" logic
was introduced.

**How this was actually found**: added temporary tracing (removed
before finishing — never committed) through `resolve_or_create_dir`,
`walk_cb`, both `compute_actions` passes, and `vw_cache_upsert` itself,
run against a real daemon+server via a throwaway debug driver script
(not checked in), because root cause 1's fix alone still reproduced the
bug end-to-end — the trace showed a `vw_cache_upsert` call for the new
subdirectory's own path with `entry_type=FILE, sync_state=NEW_LOCAL`
that the two `compute_actions` passes (also traced, and confirmed
clean) never produced, which is what led to `vw_sync_mark_local_modified`
specifically.

**Testing**:
- `tests/unit/test_vw_sync.c`: 5 new `resolve_or_create_dir` cases for
  the owned-folder path (root-slash fast path, non-"/" root, sentinel
  short-circuit, and the specific "root resolves to 0, not marked
  unresolvable" precondition the ancestor-check fix relies on) — all
  `sess = NULL`-safe by construction, same discipline the existing
  shared-folder cases already use (chosen so `vw_client_file_stat`/
  `vw_client_file_mkdir` are never actually reached). The genuinely-new
  create path needs a real `sess` and is integration-level only,
  deliberately, matching this file's own stated policy for the
  mkdir-outcome classification.
- New `tests/integration/test_cli_new_subdir_sync.py`: real daemon +
  server, the exact repro (mkdir + write, both directly on the
  filesystem, never through the CLI/GUI's own `mkdir`) plus a second
  file added afterward in the same new subdirectory (proving the
  created remote folder is reused, not re-created or erroring on
  "already exists" for a sibling that arrives later). Checks the error
  count specifically (`0 uploads, 0 downloads, 0 errors`), not just
  upload/download counts — root cause 2's bug left errors permanently
  nonzero even though nothing was "pending."
- Full regression: `ctest --test-dir build-gw-e2e` (19/19) and the full
  non-cluster pytest suite, both green on both toolchains (WSL/GCC,
  MSVC) after this change.

Moving to `review`.

CLI.02 [2026-08-26]: Full regression confirmed green before handing off
to review — full non-cluster pytest integration suite: `111 passed, 15
deselected` (includes the new `test_cli_new_subdir_sync.py`), and `ctest`
19/19 on both toolchains (WSL/GCC `build-gw-e2e`, MSVC `build-msvc-105`).

CQR.08 [2026-08-26]: Reviewed for code quality and consistency.

- The two root causes are each independently real and independently
  necessary — verified this claim directly (root cause 1's fix alone
  was tried first and the real end-to-end repro still failed, which is
  what led to finding root cause 2), not asserted without checking.
- `resolve_or_create_dir`'s new `shared` parameter and the `is_root`/
  root-vpath-"/" special-casing is intricate enough that I re-traced it
  by hand against the actual code (not just the comments) for: a
  "/"-rooted owned file at root level, a non-"/"-rooted owned folder's
  new subdirectory, and the pre-existing shared-folder cases (fully
  offline root, intermediate ancestors, already-known target,
  sentinel, root-path-normalization) — confirmed byte-for-byte
  unchanged behavior for all of the latter, which is what the new unit
  tests (passing `shared=1` explicitly) also lock in.
- The `parent_id == 0` → `dirmap_lookup(...) == VW_DIRMAP_UNRESOLVABLE`
  change for the ancestor-failure check is the correct fix for the
  ambiguity it documents (0 as both "legitimately root" and "not yet
  resolved") — traced the "/"-rooted owned case by hand to confirm the
  old check would have wrongly deferred every root-level owned upload
  forever, which the new unit test ("root resolves to 0 without being
  marked unresolvable") locks in as a regression guard.
- `vw_sync_mark_local_modified`'s fix (`is_directory` early-return) is
  minimal and reuses the exact helper the periodic walk already trusts
  for the same distinction — no new "what counts as a directory" logic.
- The debugging methodology (temporary tracing through the real call
  chain, actually run against a real daemon+server, not just read) is
  exactly what caught root cause 2 — analysis alone (matching this
  task's own original filed description) would have missed it and
  shipped an incomplete fix.
- No blocking findings. Approved.
