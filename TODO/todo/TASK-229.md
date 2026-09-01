---
id:          TASK-229
title:       "File browser, login/2FA, and transfer queue UI (Views)"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-226, TASK-227, TASK-228]
blocks:      [TASK-231, TASK-232]
review_by:   [CQR.08]
tags:        []
---

Build the core "Drive-like" UI using classic Android Views (RecyclerView),
not Jetpack Compose, per the recorded UI-toolkit decision.

Scope:
- Login activity (username/password, 2FA challenge/response via `VwClient`),
  wired to TASK-227's account registry (add/switch/remove profile).
- File browser: RecyclerView-based list + breadcrumb navigation, backed by
  `FILE_LIST_RESP`; tap-to-navigate into folders, long-press/menu for
  file-op actions (delete/move/rename via the ops added in TASK-226).
- Transfer queue screen: shows in-flight/completed uploads/downloads from
  TASK-228's transfer service, with progress and cancel.
- Empty/error/offline states handled without crashing (no network, expired
  session, server unreachable).

Vault UI, sharing/link UI, and account self-service UI are separate tasks
(TASK-230/231/232) — this task is the base browse/login/transfer experience
they all build on top of.

## Acceptance criteria

- A fresh install can log in, browse the remote file tree, upload a file,
  download a file, and see it complete in the transfer queue, entirely
  through the UI (no dev-only debug hooks required).
- 2FA challenge flow works end-to-end for an account with email OTP enabled.
- Manual test pass recorded against a real `vapourwaultd` per the plan's
  verification section (emulator + `adb reverse`, throwaway TLS cert via
  `tests/integration/gen_test_cert.sh`).

## Notes
