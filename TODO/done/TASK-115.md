---
id:          TASK-115
title:       "Add unit test coverage for server file-operation handlers (vw_file_handlers.c)"
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-04
priority:    normal
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [testing, server, security-sensitive]
---

Surfaced by a 2026-08-04 project-state review. `src/server/vw_file_handlers.c`
— the server's FILE_LIST / FILE_STAT / CHUNK_UPLOAD / FILE_COMMIT /
FILE_DELETE / FILE_MKDIR / FILE_MOVE / VERSION_RESTORE handlers — has **zero
unit tests**. This is arguably the single most security-sensitive file in
the codebase: it's where `vw_path_validate` is invoked, where every
permission check (`require_permission`, `effective_permission`,
`permission_on_dir_or_root`) for owned vs. shared vs. scoped-session access
lives, and where quota enforcement happens. It's covered only at
integration level (`tests/integration/*.py`, `run_integration.py`,
`test_shared_sync*.c`), which exercises real request/response round-trips
but doesn't cheaply enumerate the permission/validation matrix (owner vs.
VIEW-grantee vs. EDIT-grantee vs. scoped-link-session vs. no-access, crossed
with each handler) the way a table-driven unit test could.

Tagged `security-sensitive` for the same reason TASK-114 is: writing tests
for the permission/path-validation surface is itself a security-relevant
activity SEC.07 should have a say in scoping and reviewing.

## Acceptance criteria

- A real unit-test harness for `vw_file_handlers.c`, following this
  project's existing unit-test conventions. This file is tightly coupled to
  `vw_store_t`/`vw_file_store_t`/`vw_share_store_t` and a live `vw_conn_t` —
  design with SRV.01 whether to test against an in-memory/temp-dir store
  instance (cheaper, no real socket) driving the handler functions directly,
  mirroring how `tests/unit/test_vw_gc.c` already links `vw_store.c`/
  `vw_store_files.c` directly rather than going through the wire.
- At minimum, table-driven coverage crossing each mutating/reading handler
  (`handle_file_list`, `handle_file_stat`, `handle_file_commit`,
  `handle_file_delete`, `handle_file_mkdir`, `handle_file_move`,
  version list/restore) against each caller class (owner, VIEW grantee,
  EDIT grantee, scoped public-link session, and no access at all) —
  confirming each gets exactly the response class it should
  (success / `VW_ERR_PERMISSION` / `VW_ERR_NOT_FOUND`, matching the
  existing "no access at all must get the same NOT_FOUND regardless of
  whether the target exists" enumeration-oracle protections noted in the
  handlers' own comments).
- Explicit coverage of `vw_path_validate` rejecting `..`/empty-component/
  double-slash paths at every handler that calls it, and of the bare-leaf-
  name validation (`handle_file_mkdir`, `handle_file_move`) rejecting `/`
  and NUL in a name.
- Existing integration tests continue to pass unchanged.
- New unit test(s) wired into `ctest`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Server-side half of the testing-gap ask; see TASK-114 for the client-side
half (vw_sync.c) and the rationale for splitting them.

QA.06 [2026-08-04]: Implemented, with one acceptance-criteria interpretation
worth flagging explicitly for review.

**On "table-driven coverage crossing each handler"**: `vw_conn_t` (where
every `handle_file_*` function sends its actual response via
`send_error`/`vw_proto_send`) is fully opaque outside `vw_net.c` and
constructible only via a real TLS accept/connect — there is no way to
call `handle_file_list`/`handle_file_mkdir`/etc. directly without a live
socket, so a literal per-handler table-driven test wasn't possible without
either standing up a real server (defeating "unit test") or a much larger
refactor separating decision-making from wire I/O in every handler (out of
this task's scope, and not something to do unilaterally). Instead: every
handler's access decision reduces to one call to `effective_permission()`
or `permission_on_dir_or_root()` (both otherwise-`static`, now exposed for
testing via new `src/server/vw_file_handlers_internal.h`, mirroring
TASK-114's `VW_SYNC_TESTABLE` pattern exactly — `VW_FH_TESTABLE`, gated on
a new `VW_FILE_HANDLERS_TEST_HOOKS` define, `static` in every production
build). New `tests/unit/test_vw_file_handlers.c` table-tests **those**
directly across owner / EDIT-grantee / VIEW-grantee / anonymous-scoped-
link-session / unrelated-no-access, which is the actual per-caller-class
decision this task is about — `require_permission()`'s two-line mapping
from that decision to an error code is unchanged, already reviewed, and
not re-derived here. The wire-level response classification per handler
remains covered by the existing integration suite (`test_sharing.py`
alone has 26 tests spanning exactly this permission matrix end-to-end).

**On the bare-leaf-name validation criterion**: found this was genuinely
near-duplicated inline in both `handle_file_mkdir` and `handle_file_move`
— but not IDENTICAL: `handle_file_move` intentionally accepts an empty
name (means "keep the current name, move-only" per `vw_client_file_move`'s
own doc comment) while `handle_file_mkdir` requires a non-empty one (a
directory must have a name). Rather than leave this as an untestable gap
or force a same-shaped abstraction over a genuine semantic difference,
extracted a small parameterized public helper —
`vw_leaf_name_validate(name, len, allow_empty)` (`src/server/
vw_file_handlers.h`/`.c`, alongside the already-public `vw_path_validate`)
— and switched both handlers to call it. This is a real (if small)
production-code change beyond pure test-writing; flagging it clearly for
CQR.08/SEC.07 rather than burying it in the diff.

**Full coverage added** (39 new assertions across `vw_path_validate`,
`vw_leaf_name_validate`, `effective_permission`, and
`permission_on_dir_or_root`):
- `vw_path_validate`: every documented rule individually (NULL, zero
  length, over `VW_MAX_PATH_BYTES`, missing leading `/`, embedded NUL,
  backslash, empty component, `..` at end/mid-path/first-component, a
  component merely *starting* with `..` correctly NOT rejected, root `/`
  alone, ordinary path, trailing slash, and the exact `VW_MAX_PATH_BYTES`
  boundary).
- `vw_leaf_name_validate`: both `allow_empty` values, `/` rejection,
  embedded NUL, the 64-byte boundary (63 accepted, 64 rejected), ordinary
  name.
- `effective_permission`: owner overrides any grant, unrelated user with
  no grant gets NONE, ancestor-folder EDIT grant inherited correctly, a
  NULL share store (sharing disabled) correctly falls back to owner-only
  rather than crashing, and an anonymous scoped public-link session
  resolves via `scope_share_id` (including confirming a link scoped to a
  *different* file grants nothing).
- `permission_on_dir_or_root`: the `dir_id == 0` root special case (owner
  match → OWNER, mismatch → NONE, and specifically `user_id == 0` never
  matching even a degenerate `root_owner_id == 0` — anonymous never owns
  anything), a nonexistent `dir_id` → NONE, and delegation to
  `effective_permission` for a real directory (owner and EDIT-grantee).

**Verification**: `build-wsl-werror` clean rebuild including a production
target check (`vapourwaultd`) confirming both the linkage change and the
`vw_leaf_name_validate` extraction are behavior-preserving; full `ctest`
(16/16); a 32-test pytest sweep specifically covering `test_file_ops.py`
(mkdir/move-adjacent) and `test_sharing.py` (26 tests spanning the exact
permission matrix, including `test_file_move_rename_at_root` — the one
test that actually exercises FILE_MOVE's empty-name-keeps-current-name
path through the new shared helper) plus the three shared-sync suites —
all pass.

Sent for review (SEC.07 + CQR.08 per this task's tag) — combined with
TASK-114 since both diffs are closely related and use the same pattern.

SEC.07 + CQR.08 [2026-08-04]: Reviewed jointly with TASK-114. **No
blocking findings.** `vw_leaf_name_validate` verified byte-for-byte
equivalent to the original inline logic at both call sites — same
64-byte boundary (matches `vw_file_record_t.name[64]`,
`src/server/vw_store.h:142`), same `allow_empty` behavior difference
preserved intentionally, same argument order, no reordering relative to
the other checks (rate limit, session validation) at either call site.
`VW_FILE_HANDLERS_TEST_HOOKS` confirmed defined only on
`test_vw_file_handlers`. Checked `vw_cluster.c`/`vw_admin.c`/`vw_acme.c`/
`vw_gc.c` for anything that fires merely by being linked into the test
binary (background threads, atexit hooks) — all such things are behind
explicit `*_start()` entry points the test never calls; the one file-scope
mutable global spotted is `static`, no ODR risk from compiling
`vw_server_lib`'s sources a second time into this test binary.
`effective_permission`/`permission_on_dir_or_root` assertions check exact
`vw_perm_t` values.

Two advisory notes, both addressed:
1. `vw_leaf_name_validate`'s `uint16_t` vs. `vw_path_validate`'s
   `uint32_t` length parameter — confirmed not a defect (matches the wire
   field width for a leaf name, which is genuinely 16-bit); no action
   needed beyond noting it here.
2. `test_vw_file_handlers`'s CMake source list is a manual mirror of
   `src/server/CMakeLists.txt`'s `vw_server_lib` source list, with no
   shared variable — will silently go stale if one changes without the
   other. Fixed with cross-referencing comments in both `CMakeLists.txt`
   files pointing at each other, so a future change to one prompts
   checking the other, without the risk of restructuring CMake variable
   scoping across directories for a 19-item list.

Review requirement satisfied. Marking done.
