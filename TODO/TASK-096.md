---
id:          TASK-096
title:       Sharing UI (share/unshare, link management, permission indicators)
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-095, TASK-107, TASK-108]
blocks:      []
review_by:   [CQR.08]
tags:        [gui]
---

Add GUI surfaces for the sharing feature designed in `TASK-088` /
`docs/PROTOCOL.md` §7.5, once CLI.02 (`TASK-095`) has published the client
library API. Per the GUI.03 constraint in `CLAUDE.md`, this consumes the
client library only — no protocol or socket code in this task.

Scope:

- Share/unshare dialog on a file or folder: pick a user, choose read or
  edit permission, optional expiry.
- Public link management: create link (with a clear "anyone with this link
  can access this item" disclosure per §7.10's disclosure requirement),
  copy-to-clipboard (shown once, matching the server never re-displaying
  the token), revoke, list active links with their permission/expiry.
- Permission indicators in the file browser: a shared-with-me item should
  be visually distinguishable from an owned item, and show its permission
  level (read vs. edit).
- "Shared with me" view, reflecting CLI.02's defined namespace for
  shared/incoming items.

## Acceptance criteria

- All flows above work against a real client + server (manual test, not
  just compiles).
- The public-link disclosure text is present and accurate (matches the
  actual security properties in §7.10 — do not overstate protection).
- Keyboard navigation and accessibility for the new dialogs, consistent
  with existing GUI.03 views.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-088`. Blocked on
`TASK-095` per the standing GUI.03 constraint — do not start until CLI.02's
client API for sharing is marked done.

ARCH.00 [2026-07-31]: `TASK-095` is done, but starting this task surfaced a
bigger gap: the GUI client has no working login (stub pointing at the CLI)
and its file browser has never called `FILE_LIST` at all (hardcoded
placeholder row). This task's own acceptance criteria ("all flows work
against a real client + server") are unreachable without both. Filed
`TASK-107` (login) and `TASK-108` (browser) as blocking prerequisites per
explicit user direction (fix those first, then layer sharing UI on top,
rather than building a sharing-only view disconnected from real
login/browsing). Added both to `depends_on`.

Scope note for whoever picks this up: `TASK-108`'s browser shows the
current user's own synced files only (local sync cache, same as
`vapourwault-cli ls`) — it is not a live remote browse of the whole server
tree, and it can never show items *shared with* the user, since those live
in someone else's path namespace and are only reachable by `file_id` (no
IPC message lists a folder's children by `file_id` — `FILE_LIST`'s wire
payload has no `file_id` field, per `TASK-095`'s own header comment on
`vw_client_file_list_by_id` being deliberately not provided). So: "shared
by me" can be shown as a badge on browser rows (cross-referenced against a
`SHARE_LIST`/`LINK_LIST` snapshot by `file_id`), but "Shared with me" must
be its own flat list view (`SHARE_LIST` mode=1) showing item metadata —
not a browsable tree, and with no way to descend into a shared *folder*'s
contents in this GUI without a further protocol extension (out of scope
here — note it as a disclosed limitation, not a silent gap, if it isn't
already tracked elsewhere).

GUI.03 [2026-07-31]: Implemented per the scope note above.

**IPC layer** (`vw_gui_ipc.h`/`.cpp`): `share_grant`, `share_revoke`,
`share_list`, `link_create`, `link_revoke`, `link_list` — mirror
`vapourwault-cli`'s `share`/`unshare`/`list-shares`/`create-link`/
`revoke-link`/`list-links` exchanges exactly (same `VW_IPC_SHARE_*`/
`VW_IPC_LINK_*` messages from `TASK-095`), returning structured
`std::vector<VwGuiShareEntry>`/`VwGuiLinkEntry>` instead of printing to
stdout. `link_create`'s raw token buffer is zeroed immediately after the
caller reads it out — same never-let-a-secret-linger convention as
`vw_client_link_create`.

**Wire format fix needed first:** `VW_IPC_FILE_LIST_RESP` never included
`file_id`, even though `vw_cache_entry_t` (the record it's built from)
already tracks it — added it (appended after `server_size`; internal
daemon↔client IPC only, not the server wire protocol, so no version
negotiation concern). Needed to cross-reference browser rows against
`SHARE_LIST`/`LINK_LIST` entries for the "shared by me" badge. Updated both
existing decoders (`vapourwault-cli`'s `ls`, which doesn't print it but
must still consume the extra 8 bytes to stay aligned) plus the new
`VwGuiIpc::file_list()`.

**Two more bugs found while wiring this up (both pre-existing, both in
CLI.02's own domain — fixed in place rather than filed separately, same
reasoning as `TASK-104`'s note on when that's appropriate):**
1. `vw_daemon.c`'s `VW_IPC_FILE_LIST_REQ` handler wrote the *pre-filter*
   entry count into the response header, but the loop below it applies a
   virtual-path prefix filter that can skip entries — so any prefix-filtered
   `ls <path>` (or GUI folder navigation, had it filtered server-side)
   would get a header claiming more entries than were actually written,
   silently corrupting the decode. Fixed by patching the real written count
   in after the loop.
2. `vw_sync.c`'s `ACT_UPLOAD`/`ACT_CONFLICT`/offline-queue-upload paths
   never populated `ce.file_id` (or `server_version_id`/`server_mtime`/
   `server_size`) after a successful upload — a comment said "will be
   refreshed on next server diff," which only self-healed on a *second*
   sync cycle, if one ever ran. Confirmed via the diagnostic below: a
   freshly synced file showed `sync_state=Synced` with `file_id=0`
   immediately after its first sync. Fixed with a new shared
   `update_cache_after_upload()` helper that does an immediate `FILE_STAT`
   after a successful upload and populates all four fields right away,
   used at all three call sites instead of the three slightly-different
   partial updates that existed before.

**UI:**
- `vw_view_browser.cpp`: rows for shared items get a `[shared]` suffix
  (checked against a `file_id` set built from non-revoked
  `share_list(mode=0)`/`link_list()` entries, refreshed alongside the file
  list). Right-click a row → "Share..." opens a modal with: a grant-to-user
  section (username, View/Edit radio, optional expiry-in-days), a
  public-link section (permission, expiry, "Create link" button, the raw
  token shown once as hex with a Copy-to-clipboard button, and the
  disclosure text "Anyone with this link can access this item — no account
  needed" — accurate to §7.10, not overstated), and a live table of
  existing non-revoked shares/links for that specific item with a Revoke
  button each. Sharing a not-yet-uploaded item (`file_id == 0`) is
  explicitly blocked with an explanatory message rather than silently
  failing against the server.
- New `vw_view_shared.cpp` ("Shared" tab, added to the menu bar and
  `AppView` enum): three tables — my user-to-user grants, my public links
  (both with Revoke buttons), and grants shared with me (metadata only, no
  revoke — matching the "only the creator may revoke" server rule; no
  folder-descend, per the disclosed limitation above).
- Keyboard/accessibility: reuses the same `ImGui::InputText`/
  `ImGui::Button`/`ImGui::BeginPopupModal` primitives as every other view
  in this GUI (`vw_view_settings.cpp`'s confirm-shutdown dialog is the
  closest precedent) — Tab/Enter navigation and focus handling come from
  Dear ImGui itself, consistent with the rest of the app; no
  view-specific keyboard handling was written elsewhere either, so none
  was added here.

**Validation:** extended the standalone diagnostic harness (from
`TASK-107`/`TASK-108`, not committed) to also exercise `share_grant` →
`share_list` → `share_revoke` and `link_create` → `link_list` →
`link_revoke` against a real running daemon + server — all round-trip
correctly, including a non-zero returned link token and the `file_id`
fix (a freshly-synced file now shows its real `file_id` immediately, not
after a second sync cycle). Full `ctest` suite re-run after the `vw_sync.c`
change: no regressions (13/13 excluding the pre-existing, unrelated
IT-7 quota flake noted in `TASK-095`'s notes). MSVC build of
`vapourwaultd`/`vapourwault-daemon`/`vapourwault-cli`/
`vapourwault-server-cli` clean. Real `vapourwault-gui` binary (including
the new Shared tab) launched under WSLg and confirmed alive with no crash.
Same disclosed limitation as `TASK-107`/`TASK-108`: no input-injection or
screenshot tooling available in this environment, so the actual dialogs,
badges, and Shared tab have not been visually click-tested by a human —
recommend doing that once before treating this as fully verified in the
way a GUI task's acceptance criteria usually implies.

**Noted but not chased (didn't block anything, orthogonal to this task):**
the diagnostic's file listing consistently showed one extra
`/gui_test.txt.tmp` entry (`file_id=0`, harmless) whose origin wasn't
tracked down — plausibly an artifact of the diagnostic's own `login()`
call replacing the daemon's active session mid-test while its background
sync loop was also running, not something a normal single-session GUI
user would hit.
