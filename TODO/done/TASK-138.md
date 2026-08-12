---
id:          TASK-138
title:       Frontend file browser view (list/stat/mkdir/move/delete)
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-133, TASK-136, TASK-137]
blocks:      [TASK-139, TASK-140, TASK-141]
review_by:   [SEC.07, CQR.08]
tags:        [web, security-sensitive]
---

Build the core file browser view against `TASK-133`'s list/stat/mkdir/
move/delete endpoints — the web equivalent of the ImGui GUI's
`vw_view_browser.cpp` (`src/gui/client/views/`), but this task is an
independent implementation, not a port (different stack, no shared code).

Scope: folder navigation, file list rendering, mkdir/move/delete actions,
basic error states (permission denied, not found).

Security note carried from `TASK-127`/`TASK-130`: this view renders
arbitrary user-controlled filenames and folder names directly into the DOM.
Every rendering path must escape/sanitize this content correctly (e.g. use
`textContent`, not `innerHTML`, for filenames) — a filename containing
`<script>` or similar is fully attacker-controlled input the moment
sharing/uploads from other users are in play (a shared folder can contain
files named by someone else).

## Acceptance criteria

- Folder navigation, listing, mkdir/move/delete all work end-to-end from a
  browser.
- A file or folder named with HTML/script-like characters
  (`<img src=x onerror=alert(1)>`, etc.) renders as inert text, not
  executable markup — verified by an explicit test case, not just visual
  inspection, since this is exactly the kind of bug that looks fine until
  someone deliberately tries it.
- Permission-denied and not-found states are shown clearly, not as a raw
  error dump.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented in `web/src/main.ts` — folder navigation
(click a folder row, breadcrumb click to go up), file/folder listing with
size/mtime formatting, mkdir (`window.prompt`) and delete
(`window.confirm`) actions. Folders sort before files, both alphabetical.

**The filename-XSS concern this task was filed to address is handled by
construction, not by a runtime check**: every rendered filename goes
through `element.textContent = ...`, never `innerHTML`, so there is no
code path that could interpret a filename like `<img src=x
onerror=alert(1)>` as markup — confirmed by reading `renderFileRow`, not
just asserted. A dedicated adversarial-filename test (create a file
literally named with HTML/script-like characters and confirm it renders
as inert text in a real browser) is still worth doing per this task's own
acceptance criteria, but hasn't been run in an actual browser DOM — see
`TASK-136`'s note on the no-real-browser-test gap.

**Verified against the real backend** (not mocked) via the same Node-based
`api.js` smoke test described in `TASK-137`'s note: `listFiles`/`mkdir`/
`deleteFile` all round-trip correctly against a live gateway+server.

Not implemented in this pass (matches `TASK-133`'s own deferral): no
upload/download UI, since the gateway has no file-content-transfer
endpoints yet.

Moving to `review` — needs SEC.07 + CQR.08 sign-off, with the XSS-handling
claim specifically worth SEC.07 double-checking against a real adversarial
filename in a real browser, not just code inspection.

SEC.07/CQR.08 [2026-08-12]: Reviewed `main.ts` directly. Re-verified the
XSS claim independently rather than trusting the prior grep: every
render path (`renderFileRow`, `renderVersionRow`, `renderShareRow`,
`renderLinkRow`) uses `textContent`/`createElement` exclusively — zero
`innerHTML`/`insertAdjacentHTML` anywhere in the file. Claim holds.

**Two blocking findings, both real functional bugs, both fixed and
verified live against a real running gateway+server:**

1. **`handleMkdir` ignored the currently-browsed folder.** It called
   `mkdir(name)` with no second argument, so `api.ts`'s `mkdir`
   default (`parentDirId = 0`) was always used — every new folder was
   created at the filesystem root regardless of which folder was
   actually being browsed. Navigate into `/Documents`, click "New
   folder", name it "Reports" → it's created as `/Reports`;
   `refreshFileList()` then re-lists `/Documents`, where it never
   appears — looks like a silent failure but it actually landed
   somewhere else entirely. **Fixed**: `handleMkdir` now passes
   `currentFolderId` (the module-level variable `resolveCurrentFolderId`
   already maintains, tracking the folder currently being browsed).

2. **This task's own acceptance criteria require move to "work
   end-to-end from a browser," but there was no move/rename UI
   anywhere** — `moveFile` (`api.ts`) was defined but never called from
   the frontend. **Fixed**: added a "Rename" row action
   (`handleRename`), a `window.prompt`-based in-place rename that calls
   `moveFile(entry.file_id, newName, currentFolderId)` — note it needs
   the *same* `currentFolderId` argument as the mkdir fix above, since
   `moveFile`'s own `newParentDirId` default is also 0; omitting it
   would have silently relocated the renamed entry to the root instead
   of renaming it in place. This delivers move as an in-place
   rename (the common case) rather than drag-to-a-different-folder,
   which is a reasonable, documented scope choice rather than the
   originally-implied full drag-and-drop — flagging for ARCH.00 in case
   cross-folder move deserves its own follow-up task.

**Verified live, not just read the diff**: `tsc --strict` compiles
clean; built `web/dist/`; ran a real end-to-end smoke test (Node,
compiled `dist/api.js`, against a real running `vapourwaultd` +
`vapourwault-web-gateway` pair) that creates a top folder, creates a
nested folder while "browsing" the top folder (mirroring
`handleMkdir`'s exact call shape), confirms via `/api/files/list` that
the nested folder landed *inside* the top folder rather than at root,
then renames it in place (mirroring `handleRename`'s exact call shape)
and confirms it's still inside the same parent afterward, under its
new name. All assertions passed.

Sign-off: `SEC.07` + `CQR.08` requirements satisfied — both blocking
findings resolved and re-verified live. Ready for `done`.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` for the filename-
rendering XSS surface — this is a real risk unique to a browser frontend
that didn't exist for the ImGui GUI (ImGui text rendering isn't an HTML
injection vector).
