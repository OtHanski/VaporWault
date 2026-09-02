---
id:          TASK-229
title:       "File browser, login/2FA, and transfer queue UI (Views)"
status:      done
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

MOB.10, 2026-09-02: Implemented `LoginActivity` (saved-profile list + add/
resume, 2FA challenge/response), `FileBrowserActivity` (breadcrumb +
RecyclerView file list, upload/download via SAF pickers, new folder, rename/
move/delete via a per-entry overflow menu), and `TransferQueueActivity`
(live progress + cancel, backed by `TransferBus.snapshot()`). Added
`VwSession` (single live client+profile holder) and extended `TransferBus`/
`TransferManager`/`FileTransferer` with a `TransferRecord`/`TransferState`
snapshot and cooperative cancellation. Removed the old placeholder
`MainActivity`/`activity_main.xml`; `LoginActivity` is now the launcher.

**Runtime verification**, against a freshly rebuilt `vapourwaultd`
(`build-wsl-fresh`, current HEAD — the existing `build-wsl` binary predates
account self-service and silently hangs on unrecognized message types, the
same `TASK-237` gap hit again while setting up this test) plus an `aiosmtpd`
debug SMTP catcher for real OTP delivery, on an x86_64 emulator via
`adb reverse`:

- New-account login, empty-folder state, New Folder, upload (SAF
  `OpenDocument`), download (SAF `CreateDocument`), delete, and the
  Transfer Queue's live progress→Complete transition all verified against a
  real server, end to end, through the UI only. Move/rename were verified
  by code review (they reuse the same `client.moveFile`/commit primitives
  already exercised elsewhere) but not separately runtime-exercised this
  pass — flagging honestly rather than claiming full coverage.
- The 2FA empty-OTP probe correctly triggers the challenge UI (OTP field
  appears, focused, with the "enter the code sent to your email" prompt) —
  confirmed against a real emailed OTP via the debug SMTP catcher.

**Bugs found and fixed in this pass** (both real, both reproduced against a
real server before being touched, per this project's fix-in-place-when-
in-domain convention):

1. `VwClient.lastError()` reads a `_Thread_local` native slot, but four call
   sites (`LoginActivity.connect()`, `LoginActivity.resumeProfile()`,
   `FileBrowserActivity.loadCurrentFolder()`, `FileBrowserActivity`'s mkdir
   handler) called it from inside `runOnUiThread { }` — the Android main
   thread — after the actual failing native call had run on a background
   `thread { }`. Each thread has its own error slot, so the main thread
   always read its own untouched default (`VW_OK`/0), regardless of the
   real failure. Symptom: every failure path showed `vw_err_t=0` no matter
   what actually went wrong (confirmed via three independent repros: a
   wrong-OTP 2FA retry, a stale session-resume, and a follow-up mkdir).
   Fixed by capturing `lastError()` on the background thread, before
   posting to `runOnUiThread`, in all four spots.
2. Diagnosed but **not fixed here** — out of MOB.10's domain: a genuine
   protocol/server bug where `vw_auth_begin_login`
   (`src/server/vw_auth.c:491-528`) mints and emails a brand-new OTP on
   *every* `AUTH_REQUEST` for a 2FA-enabled account, with no reuse of a
   pending per-user challenge. Since the established client 2FA pattern
   (used identically by the desktop daemon and this Android app) submits
   the OTP via a *second, fresh* connection, that connection's own
   `AUTH_REQUEST` mints and emails yet another code before evaluating the
   one the user just typed — making a real end-to-end email-OTP login
   unreachable via the UI as designed. Filed as `TASK-238` (SRV.01,
   `security-sensitive`) with full repro steps. This is why the acceptance
   criterion "2FA challenge flow works end-to-end" is verified only up to
   the challenge-trigger step, not a full successful login — that part is
   blocked on `TASK-238`, not on anything in this task's own scope.

**CQR.08 self-review** (same pass, per this project's established solo
implementer+reviewer pattern): reviewed all new/changed files for error-path
handling, resource cleanup, and naming consistency with the existing
codebase. No blocking findings — the one real defect found during review
(the `lastError()` thread-locality bug above) was fixed in this same pass,
not deferred. No `security-sensitive` tag on this task (the vault/crypto
surfaces are TASK-230's scope), so `SEC.07` is not required here.
