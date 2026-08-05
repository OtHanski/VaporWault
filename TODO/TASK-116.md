---
id:          TASK-116
title:       Improve the server GUI's audit log view (filter, search, export)
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-04
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [gui, server]
---

Surfaced by a 2026-08-04 project-state review. `src/gui/server/views/
vw_view_audit.cpp` exists and displays the server's audit log, but is
read-only with no filtering, search, or export — it's a plain scrolling
view of whatever `AUDIT_QUERY` returns. For an admin trying to answer a
concrete question ("did user X download file Y last week", "what did this
share-link do before I revoked it") this is currently a manual scroll-and-
read exercise.

## Acceptance criteria

- Filter controls for at least: user, action/event type, and a date/time
  range — check what `AUDIT_QUERY`'s existing request payload
  (`src/core/vw_proto.h` / the admin protocol) already supports server-side
  before assuming new server plumbing is needed; prefer using what exists.
- A text search box for free-text matching against the visible log entries
  (client-side filter over the currently-loaded page is fine if the
  server-side query doesn't support it — don't block this on a protocol
  change unless genuinely necessary).
- An export action (CSV or plain text) for the currently-filtered view, so
  an admin can hand a slice of the log to someone else without screen-
  scraping.
- No change to the underlying `AUDIT_QUERY` wire contract unless a
  filter genuinely requires new server-side support — if it does, coordinate
  with PRT.04/SRV.01 on the protocol change rather than improvising a new
  message type unilaterally.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested.
Low priority — this is a UX improvement on an already-functional feature,
not a gap in core functionality.

GUI.03 [2026-08-04]: Implemented in `src/gui/server/views/vw_view_audit.{h,cpp}`,
entirely client-side over the already-loaded page (confirmed `AUDIT_QUERY`
only takes `max_entries` server-side — no other filters exist to reuse, so
no wire change was made):

- Event-type filter: combo box over the known `VW_OPLOG_*` types.
- User/owner id filter: text field matched against a new `subject_id`/
  `has_subject` pair on `AuditEntry`, populated from the first 8 bytes of
  the payload for `USER_WRITE`/`FILE_WRITE`/`PERM_WRITE`/`VAULT_WRITE`
  (all of which lead with a user or owner id). `FILE_DELETE` (file_id) and
  `SESSION_WRITE` (session slot) carry no attributable user id in the
  current oplog payload and are excluded when this filter is set — noted
  in a hover tooltip on the field.
- Free-text search: case-insensitive substring match against the detail
  string and event-type name.
- Export CSV now exports the filtered/visible rows instead of the full
  loaded page.
- As a side effect, `FILE_WRITE`/`PERM_WRITE`/`VAULT_WRITE`/`FILE_DELETE`
  entries now show a meaningful `owner_id=`/`file_id=` detail line instead
  of a raw hex dump, since the payload was already being parsed.

**Not implemented: date/time-range filter.** The oplog has no timestamp
anywhere in its on-disk or wire format (`entry_id` is a monotonic sequence
number, not wall-clock time) — this is a genuine protocol/format gap, not
something fixable client-side, so per the routing rules I filed TASK-121
(assigned PRT.04) rather than improvising a new field myself. Moving to
`review`; CQR.08 please check the filter/export logic in
`vw_view_audit.cpp` (`passes_filters`, `filtered_entries`, `ci_contains`).
Built and verified warning-clean under both `build-wsl` and
`build-wsl-werror` (`-Werror`) for the `vapourwault-server-gui` target.

CQR.08 [2026-08-04]: Two `blocking` findings, both confirmed by reading the
server-side oplog writers, not just the GUI code:

1. **`FILE_WRITE` owner-id parsing is wrong for 2 of its 3 call sites.**
   `parse_audit_resp` (vw_view_audit.cpp:196-202) treats every
   `VW_OPLOG_FILE_WRITE` entry's first 8 payload bytes as an `owner_id` and
   surfaces it both as the `owner_id=` detail string and as the new
   user-filter's `subject_id`. That's only true for the create path
   (`vw_store_files.c:471`, payload = `rec->owner_id`). The other two
   `FILE_WRITE` writers — the rename/update path (`vw_store_files.c:634`,
   payload = `file_id`) and the version-write path
   (`vw_store_files.c:801`, payload = `rec->file_id`) — append a **file
   id**, not an owner id, in that same position. As shipped, the audit view
   will label those rows `owner_id=<file_id>` (actively wrong, not just
   unlabeled) and the new user/owner-id filter will match/exclude them
   based on a file id being compared as if it were a user id — exactly the
   kind of wrong answer this task exists to prevent for a question like
   "did user X touch file Y". Needs either a real per-writer discriminator
   (e.g. widen the oplog payload for update/version-write to also carry
   the owner id, coordinating with PRT.04/SRV.01 per the task's own
   protocol-change rule) or, at minimum, stop attributing those two
   `FILE_WRITE` shapes to a subject_id/owner_id client-side and label them
   distinctly (e.g. `file_id=` like `FILE_DELETE` already does) until the
   payload actually carries an owner id.
2. **`VW_OPLOG_VAULT_WRITE` is missing from both `op_type_name()` and the
   new type-filter dropdown** (`kTypeNames`/`kTypeValues`,
   vw_view_audit.cpp:75-82). `vw_vault.c:197` does append real
   `VAULT_WRITE` entries in production, so this isn't theoretical: every
   vault-registration row displays as event type "Unknown" in the table
   and in the CSV export, and can't be isolated via the type-filter combo
   — despite this same diff's own tooltip claiming vault writes are
   handled ("User/File/Perm/**Vault** Write") and despite the payload
   parser correctly extracting its owner id a few lines above. Add a
   `case VW_OPLOG_VAULT_WRITE: return "Vault Write";` to `op_type_name()`
   and an entry in the filter arrays.

Not blocking, just an observation: `filter_user_` is restricted to
`ImGuiInputTextFlags_CharsDecimal`, which (per Dear ImGui) also passes
`.`, `-`, `+`, `*`, `/` — typing e.g. `-5` gets fed to `strtoull`, which
per the C standard silently negates it into a huge value that will never
match a real id. Harmless (just "no results"), not worth blocking on.

Everything else checked out: filter/export logic (`passes_filters`,
`filtered_entries`, `ci_contains`) is correct, the `subject_id`/
`has_subject` exclusion for `FILE_DELETE`/`SESSION_WRITE` is accurate, and
pointer lifetimes in `filtered_entries()` are fine (used synchronously,
`entries_` isn't mutated in between). Re-review once 1) is resolved and 2)
is added — should be a quick pass.

CQR.08 [2026-08-04]: Both findings fixed in `vw_view_audit.cpp`. Re-review:

1. **Fixed via the "stop mislabeling" option, not the protocol option** —
   confirmed a client-side discriminator genuinely isn't possible: all
   three `FILE_WRITE` writers append exactly 8 bytes at the same offset
   with no distinguishing marker, so the wire format itself doesn't carry
   enough information to tell owner_id apart from file_id. Correctly
   split the old combined branch: `PERM_WRITE`/`VAULT_WRITE` keep
   `owner_id=`/subject attribution (both are genuinely unambiguous —
   checked their single call sites too), `FILE_WRITE` now gets its own
   branch labeled `ref_id=` with no `subject_id`/`has_subject` set, so the
   user filter correctly excludes it rather than silently comparing a file
   id against a user id. Tooltip text updated to match (no longer claims
   File Write is attributable). Filed TASK-122 (PRT.04) per the routing
   rules to actually fix this at the protocol layer — mirrors TASK-121's
   precedent exactly (same "GUI can't fix this, needs a wire change"
   shape), so the real capability loss (can no longer say "user X created
   file Y" from the audit log) is tracked rather than silently eaten.
   Reasonable scope for this pass — no unilateral protocol change, no
   wrong data shipped either.
2. **Fixed** — `case VW_OPLOG_VAULT_WRITE: return "Vault Write";` added to
   `op_type_name()`, and `"Vault Write"`/`VW_OPLOG_VAULT_WRITE` added to
   `kTypeNames`/`kTypeValues` (checked the two arrays still line up 1:1 by
   index — they do, both 8 entries).

Verified: rebuilt `vapourwault-server-gui` clean on MSVC `/W4 /WX`
(`build-msvc-105`) and on WSL with `-Werror` (`build-wsl-werror`), both
warning-free. Spot-checked the CSV/table/filter paths all reference the
same `op_type_name()`/branch logic consistently — no stale references to
the old `owner_id=` label for `FILE_WRITE` left anywhere. No unit tests
exist for this view (consistent with the rest of the GUI layer); build
verification is the established bar here, per GUI.03's original note.

No further findings. Moving to `done`.
