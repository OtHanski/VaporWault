---
id:          TASK-210
title:       "GUI: notification-preferences panel"
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  [TASK-209]
blocks:      []
review_by:   [CQR.08]
tags:        [gui]
---

Blocked on `TASK-209` (GUI consumes client/daemon API only).

## Work

- `vw_view_settings.cpp`/`.h`: a "Notifications" section with one
  checkbox per user category (`share_received`, `quota_warning`,
  `new_login`, `account_security_change`), each with a short description
  of what it means.

## Acceptance criteria

- Toggling a checkbox round-trips through the daemon and reflects the
  server's actual stored state on next load (not just local UI state).
- Keyboard-navigable per the existing accessibility bar.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

GUI.03 [2026-08-27]: Implemented. GUI consumes the client/daemon API only,
per this project's constraint — no protocol/socket code added here.

- `vw_gui_ipc.h`/`.cpp`: `VwGuiIpc::notify_prefs_get`/`_set`, each opening
  its own one-shot connection (`one_shot()`, this class's existing
  pattern — matches `vw_daemon.c`'s one-request-per-connection IPC model,
  the same thing `TASK-209` had to fix its own CLI code for).
- `ClientApp.h`/`.cpp`: `ipc_notify_prefs_get`/`_set` thin wrappers,
  locking `status_mutex_` and using `active_account_id_` — identical
  shape to every other `ipc_folder_*`/`ipc_*` wrapper in this class.
- `vw_view_settings.cpp`: new "Email notifications" section, one
  `ImGui::Checkbox` per category with a short description alongside
  (`NOTIFY_CATEGORIES[]` — a local table mirroring `vapourwault-cli`'s
  own array by name/bit/description, so the two surfaces can't drift).
  Toggling immediately calls `ipc_notify_prefs_set` with the flipped
  bitmask and updates local display state from the ACK's echoed-back
  value (never assumes the write succeeded); on failure, re-fetches from
  the server rather than leaving the checkbox showing a value that was
  never actually stored.
- **Keyboard navigation**: no special handling needed or added —
  `ImGui::Checkbox` is natively Tab/Space-navigable, and
  `ImGuiConfigFlags_NavEnableKeyboard` is already set globally
  (`main.cpp`), same as every other interactive widget in this
  application. Verified by reading `main.cpp`'s IO config, not assumed.
- **Found and filed, not fixed here** (`TASK-221`): the Settings view's
  static, always-open window state (`s_folders`/now `s_notify_prefs`) is
  never invalidated on an account switch — a pre-existing gap for
  folders that this task's own new state inherits by following the
  surrounding code's existing convention, rather than silently fixing
  only the new half.

## Acceptance criteria

- **Round-trips through the daemon and reflects real server state, not
  just local UI state**: verified at the wire/IPC level — `VwGuiIpc`'s
  new methods send the exact same `VW_IPC_NOTIFY_PREFS_GET/SET_REQ`
  messages `TASK-209`'s `vapourwault-cli notify` already exercises
  end-to-end in a real integration test
  (`test_cli_notify_prefs.py`, 2 tests, both green) against the real
  daemon/server. **Not independently re-verified through the actual
  compiled GUI** — this project has no GUI/browser automation
  infrastructure (confirmed by checking; same disclosed limitation as
  `TASK-200`'s search-bar GUI work) — what was actually verified instead:
  clean compile on both toolchains, and manual code-level tracing of
  `ipc_notify_prefs_get/set` → `VwGuiIpc::notify_prefs_get/set` → the
  same wire messages, confirming byte-for-byte the same request/response
  shapes the CLI's already-passing integration test exercises. A human
  should still click through this once before considering it fully
  verified, same caveat `TASK-200`/`TASK-216` recorded for their own GUI
  work.
- Keyboard-navigable: satisfied by ImGui's existing global nav
  configuration, not new code — verified by reading, not assumed.

**Testing**:
- Full rebuild on both toolchains: WSL/GCC (`build-gw-e2e`) and MSVC
  (`build-msvc-105`), both clean.
- Full `ctest`: 20/20 (WSL/GCC).

Moving to `review`.

CQR.08 [2026-08-27]: Reviewed for code quality and consistency.

- `VwGuiIpc::notify_prefs_get/_set` and `ClientApp`'s wrappers correctly
  mirror every existing sibling method's shape (one-shot connection per
  call, `status_mutex_` locking, `active_account_id_` usage) — spot
  checked against `folder_list`/`folder_set_excludes` side by side.
- The checkbox handler updating local state from the ACK's echoed value
  (not assuming the write applied) and re-fetching on failure is the
  correct defensive shape — matches this task's own stated design intent
  and this project's general "never assume a write succeeded" posture
  elsewhere (e.g. `TASK-207`'s own SET_ACK echo-back rationale).
  `NOTIFY_CATEGORIES[]` mirroring the CLI's own table by name/bit is a
  good anti-drift choice, same reasoning `TASK-209` used for its own copy.
- The keyboard-navigation claim was verified by the agent reading
  `main.cpp`'s IO config rather than asserted from memory — appropriate
  rigor for a claim this cheap to actually check.
- `TASK-221`'s filing is honest and correctly scoped — a real,
  pre-existing gap this task's new state inherits, not invented busywork
  or a silent fix that would have expanded this task beyond notification
  prefs.
- The disclosed GUI-testing limitation is specific (names exactly what
  was and wasn't verified, and how) rather than a vague hedge.
- No blocking findings. Approved.

Moving to `done`.
