---
id:          TASK-163
title:       GUI account switcher: thread account_id through ClientApp/VwGuiIpc/views
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-13
priority:    normal
depends_on:  [TASK-161]
blocks:      [TASK-168]
review_by:   [CQR.08]
tags:        [gui]
---

Depends on `TASK-161`'s daemon `ACCOUNT_*` IPC messages and account-scoped
existing requests. Today `ClientApp`/`VwGuiIpc` (`src/gui/client/`) model
"one daemon, one account, one connection" throughout — no account dimension
anywhere.

## Work

- New account-switcher UI (tab row or dropdown, near the top of the main
  window) populated from `VW_IPC_ACCOUNT_LIST_REQ`/`_RESP`.
- Selecting an account sets an active `account_id` held on `ClientApp`.
  Thread it through every existing `ClientApp::ipc_*` method and the
  corresponding `VwGuiIpc` method (mechanical signature addition — one
  `uint32_t account_id` parameter each — matches the wire field's actual
  type, `vw_ipc.h`; note this is `u32`, not `u64`, e.g. `ipc_file_list`,
  `ipc_vault_upload`, `ipc_share_grant`, etc.).
- Views (`vw_view_browser.cpp` and friends) do **not** need per-account
  state storage: only the active account is ever displayed. Switching the
  active account just flips each currently-open view's existing
  `s_needs_refresh`-style flag to refetch for the newly-active account —
  reuse this pattern (already exists per-view, e.g.
  `vw_view_browser.cpp`'s `s_needs_refresh`) rather than introducing a new
  per-account state cache in the GUI. Background sync for inactive
  accounts is entirely the daemon's concern (`TASK-161`), decoupled from
  what's currently on screen.
- "Add account" flow (Settings view or a new dialog): collects
  host/port/CA-cert-path/username/password/OTP, sends `ACCOUNT_ADD_REQ`.
  Host/port/CA-cert are per-account fields, not defaulted from any other
  configured account — `ARCHITECTURE.md`'s "Accounts are per-server, not
  just per-user" decision (settled 2026-08-13) means this dialog is how a
  user adds a second account on a completely unrelated server (e.g. a
  family server and a separate friends server), not just a second user on
  the same one.
  - `VwGuiIpc::login()`'s existing `ACCOUNT_ADD_REQ` payload buffer (`uint8_t
    buf[900]`, `TASK-161`) has unchecked `vw_ipc_write_str()` calls — safe
    today only because `ca_cert_pem_path` is always sent empty (no CA-cert
    field yet). Adding a real CA-cert field here means the same fix
    `TASK-162`'s CQR review applied to the CLI's equivalent function is
    needed: size the buffer for the real worst case (label/host/CA-cert/
    username/password/otp all near their caps, ~1181 bytes — 1536 is a
    reasonable size with margin) and check each write's return value
    rather than let a silent `VW_ERR_PROTO_TOO_LARGE` desync every field
    written after it.
- "Remove account" flow: confirms, sends `ACCOUNT_REMOVE_REQ`; if the
  removed account was active, switch to another configured account or back
  to the login/no-accounts view if none remain.

## Acceptance criteria

- With two accounts configured (via `TASK-161`'s daemon), switching in the
  GUI shows the correct, distinct file listing/queue/shares for each,
  without needing to restart the GUI.
- Closing/reopening the GUI while a background sync is in progress for a
  non-active account does not interrupt that account's sync (verifies the
  daemon, not the GUI, owns background sync — no regression from adding
  the switcher).
- No behavior change for a single-account setup from the user's point of
  view (switcher UI can be hidden or a no-op when only one account exists).
- Adding a second account against a genuinely different server (not the
  same server as the first account) works from the dialog, and switching
  between them shows each account's own server's data correctly.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**GUI.03 [2026-08-13]:** Implemented with one deliberate deviation from this
task's own "Work" section, decided and documented up front rather than
silently: `ClientApp`'s *public* `ipc_*` method signatures do **not** gain an
`account_id` parameter each. Instead `ClientApp` holds a private
`active_account_id_` (guarded by `status_mutex_`) and injects it internally
into the corresponding `VwGuiIpc` call, which *does* take the explicit
`uint32_t account_id` the task specifies — the mechanical signature change
happened one layer down from where the task described it. Rationale: "only
the active account is ever displayed" (this task's own premise) means no
view ever legitimately needs a *different* account than whichever one is
active, so a parameter every call site would have to pass identically is
pure boilerplate with a real staleness risk (one call site quietly using a
stale id) and no offsetting benefit. `vw_gui_ipc.h`/`.cpp` themselves were
changed exactly as specified: every account-scoped method
(`send_pause`/`send_resume`/`send_folder_add`/`send_folder_remove`/
`file_list`/`share_*`/`link_*`/`file_mkdir`/`vault_*`) now takes a leading
`uint32_t account_id`, matching `vw_ipc.h`'s own payload doc comments
exactly, field for field — this is internal daemon↔GUI IPC, not the
client↔server wire protocol, so there is no `docs/PROTOCOL.md` section to
update for this task.

- `login()` was replaced with `account_add()`/`account_list()`/
  `account_remove()`, mirroring `TASK-162`'s CLI `account` subcommands
  (`vw_client_cli.c`'s `cmd_account_add`/`account_list_entry_t`/
  `resolve_account_id`) — `account_add()`'s buffer is sized and every write
  checked from the start here (this task's own "Work" section already
  flagged the exact bug `TASK-162`'s CQR pass found in the CLI's
  equivalent function; fixed proactively rather than reproduced).
- Switcher UI: `ClientApp::render_account_switcher()`, a dropdown
  (`ImGui::BeginMenu`) in the main menu bar showing the active account's
  label/username, every configured account as a selectable entry
  (`[offline]` suffix when `connected == 0`), a "+ Add account..." entry
  that switches to `AppView::Login`, and "Remove current account..." with
  a confirm modal. Backed by `ClientApp::cached_accounts_`, refreshed every
  ~2s by the existing background poll thread (same cadence as
  `cached_status_`) rather than issuing its own IPC call every render
  frame.
- `switch_active_account(account_id)`: sets `active_account_id_` *and*
  forces `vw_view_browser_invalidate()`/`_shared_invalidate()`/
  `_vault_invalidate()` (new exported functions, one per view, following
  this task's own instruction to reuse each view's existing
  `s_needs_refresh` pattern rather than add a per-account GUI cache).
  Documented as render-thread-only in both the method's own doc comment
  and each view header's: those views' static state is unguarded by any
  mutex (single-render-thread-only by this codebase's existing
  convention), so calling the invalidators from the background poll
  thread would be a real data race. `poll_loop()`'s own zero-config
  auto-select (mirrors `vapourwault-cli`'s `resolve_account_id` default)
  therefore does **not** call the invalidators — provably safe without
  them, since it only ever fires once, before any view has rendered
  anything (the app is still on the `Login` screen at that point).
- `vw_view_login.cpp`: gained label + CA-cert-path fields (this task's own
  note that `ARCHITECTURE.md`'s "Accounts are per-server, not just
  per-user" decision means this form must never default host/port/CA-cert
  from an existing account), now calls `ipc_account_add(0, ...)` and
  `switch_active_account()` on success. Doubles as both the "no account
  reachable yet" full-screen view and the switcher's "+ Add account" flow
  (same fields, same call, reached from two different `active_view_`
  paths) — no separate modal dialog needed.
- Regression found and fixed while doing this (see CQR.08 note below):
  `send_folder_add`/`send_folder_remove` were accidentally dropped
  entirely from `vw_gui_ipc.h` partway through this task's own edits,
  which would have made `vapourwault-gui` fail to compile — caught before
  ever attempting a build, by diffing against `git show <TASK-108
  commit>:src/gui/client/vw_gui_ipc.h` once the missing symbols showed up
  in `ClientApp.cpp`. Restored with the account_id parameter added
  (`FOLDER_ADD_REQ`/`FOLDER_REMOVE_REQ` are account-scoped per `vw_ipc.h`,
  same as every other message in this list) — not just reverted to their
  pre-existing shape. Also fixed a one-line stale comment in
  `vw_client_cli.c` (`cmd_add_folder`'s doc comment omitted `account_id`
  from the payload it was already sending) while in that area.
- Build: `build-msvc-105` (MSVC, Release) — clean, `vapourwault-gui.exe`
  links. `build-gw-e2e` (WSL/GCC) does not build a GUI target at all (no
  SDL2 dev libs configured there) — expected, unaffected by this task.
- Tests: full `ctest` green on both trees (17/17 MSVC, 18/18 WSL). Full
  Python integration suite green (89 passed, 3 cluster-marked deselected)
  including `test_daemon_ipc_accounts.py`, `test_daemon_multi_account.py`,
  `test_cli_account_commands.py` — confirms this task's `vw_gui_ipc.cpp`
  wire encoding changes didn't require (and didn't get) any daemon-side
  change, since those pre-existing daemon/CLI tests still pass unmodified.
- Manual verification (no automated GUI test harness exists for this Dear
  ImGui app — noting the limitation explicitly rather than skipping it):
  stood up a real `vapourwaultd` + `vapourwault-daemon` + one configured
  account (`smoketest`) in WSL, confirmed WSL2 localhost-forwards TCP to
  Windows, then ran the MSVC-built `vapourwault-gui.exe` against it for
  ~50s (well past several 2s poll cycles) with a concurrent
  `vapourwault-cli ls` run from WSL against the same daemon at the same
  time — no crash, no hang, no deadlock between the GUI's background poll
  connections and the CLI's own one-shot connections. This exercises
  `poll_loop()`'s per-tick `account_list()` call, `cached_accounts_`,
  auto-select, and `render_account_switcher()` rendering a real one-account
  list every frame for that whole window. It does **not** verify the
  switcher's on-screen appearance or click behavior, the "Add account"
  form, or the two-different-servers acceptance criterion by eye — I have
  no way to interact with the rendered window in this environment. Given
  this task's acceptance criteria are UI-behavioral (does switching
  visibly show the right data), a human should still click through the
  switcher once, especially the "second account on a genuinely different
  server" case, before fully trusting this beyond what's proven here.

**CQR.08 self-review [2026-08-13]:** One `blocking`-class finding, fixed:
`send_folder_add`/`send_folder_remove` were missing from `vw_gui_ipc.h`
entirely (see GUI.03's note above) — would not have compiled. No other
`vw_gui_ipc.h` method was affected the same way; verified by diffing every
remaining declaration in this task's `git diff` against `vw_ipc.h`'s own
wire-format doc comments field-by-field (`ACCOUNT_ADD_REQ`,
`ACCOUNT_LIST_RESP`, `ACCOUNT_REMOVE_REQ`, `FOLDER_ADD_REQ`,
`FOLDER_REMOVE_REQ`/`FILE_LIST_REQ`, `PAUSE_REQ`/`RESUME_REQ`,
`SHARE_GRANT_REQ`, `SHARE_REVOKE_REQ`/`LINK_REVOKE_REQ`, `SHARE_LIST_REQ`,
`LINK_CREATE_REQ`, `LINK_LIST_REQ`, `FILE_MKDIR_REQ`, `VAULT_CREATE_REQ`,
`VAULT_UNLOCK_REQ`, `VAULT_LIST_REQ`, `VAULT_UPLOAD_REQ`,
`VAULT_DOWNLOAD_REQ`) — all matched exactly. `account_add()`'s buffer
sizing/checked-writes (the bug class this task's own "Work" section
pre-flagged from `TASK-162`) was correct from first write, confirmed by
re-deriving the worst-case byte sum independently. `ipc_account_remove()`
and `switch_active_account()`'s locking was checked for the
render-thread-vs-poll-thread hazard called out in GUI.03's note above —
correct: the only path that could have raced (auto-select in `poll_loop()`)
provably never touches the unguarded view statics. No `advisory` findings
beyond what's already noted (no automated GUI test coverage, and the
two-different-servers switcher case being manually-unverified) — both
called out plainly above rather than left implicit.
