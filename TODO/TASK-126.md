---
id:          TASK-126
title:       Client GUI's "Conflict" popup is dead code and cites a CLI command that doesn't exist
status:      todo
assignee:    GUI.03
created_by:  GUI.03
created:     2026-08-05
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [gui, client]
---

Discovered while writing `docs/CLIENT_GETTING_STARTED.md` (`TASK-120`) and
researching how the client GUI actually surfaces sync conflicts to a user.

`src/gui/client/views/vw_view_browser.cpp` has:

```cpp
if (ImGui::BeginPopupModal("Conflict##browser", nullptr,
        ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::Text("A conflict copy exists for this file.");
    ImGui::Text("Resolve via CLI: vapourwault-cli resolve <path>");
    ...
```

Two problems:

1. **This modal is unreachable.** Nothing in the file (or anywhere else
   grepped) ever calls `ImGui::OpenPopup("Conflict##browser")`. It's dead
   code — the `BeginPopupModal` call always returns `false` and the body
   never executes.
2. **Its text is wrong regardless.** `vapourwault-cli` has no `resolve`
   subcommand (confirmed via `src/client/vw_client_cli.c`'s full command
   list: `status`, `sync`, `pause`, `resume`, `add-folder`,
   `add-shared-folder`, `remove-folder`, `list-folders`, `ls`, `conflicts`,
   `login`, `share`, `unshare`, `list-shares`, `create-link`,
   `revoke-link`, `list-links`, `shutdown` — no `resolve`). If this modal
   were ever wired up, it would tell users to run a command that doesn't
   exist.

For context: conflicts don't actually need manual resolution at all.
`vw_sync.c`'s `ACT_CONFLICT` handling (see `make_conflict_path` and its
caller) automatically keeps the local file as the new server version and
saves the previous server version alongside it as
`<name>.conflict.<timestamp>.<ext>` — this is already fully automatic and
matches `ARCHITECTURE.md`'s "Last-write-wins + auto-history" decision. The
`vapourwault-cli conflicts` command exists (lists files currently in
`VW_SYNC_CONFLICT` state) but there's no separate "resolve" action to take
because the sync engine already resolved it by the time a user could see it.

## Acceptance criteria

- Either remove the dead modal entirely (nothing calls it, and per the
  above there's nothing for a user to actually resolve), or — if a
  conflict-notification popup is still wanted — rewrite it to describe
  what actually happens (local kept, server version saved as a
  `.conflict.*` file) instead of pointing at a nonexistent command, and
  wire up an actual `OpenPopup` call somewhere (e.g. when a row's
  `sync_state` transitions to `VW_SYNC_CONFLICT`).
- No functional/behavior change either way — this is dead/cosmetic code,
  not a bug affecting real sync behavior.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-05]: Filed while writing `TASK-120`'s end-user tutorial —
wanted to describe conflict handling accurately and found the in-app text
would have told users to run a command that doesn't exist, had it ever
actually been shown. Low priority: it's unreachable, so no user has ever
actually seen this wrong text in practice.
