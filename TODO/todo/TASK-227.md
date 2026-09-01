---
id:          TASK-227
title:       "AndroidKeyStore-backed credential storage + multi-profile account registry"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-225]
blocks:      [TASK-228, TASK-229]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive]
---

Genuinely new capability, not a port: today's desktop/native client has no OS
keychain integration anywhere (session/login tokens are plain mode-0600
files). Android should do better, not just match desktop.

Scope:
- Raw `AndroidKeyStore` usage (`KeyGenParameterSpec`, hardware-backed where
  available) to wrap the session-resume token and stored login token;
  ciphertext kept in a private app file. No wrapper library — explicitly not
  `androidx.security-crypto`'s `EncryptedSharedPreferences` (deprecated 2025;
  its replacement, Tink + proto DataStore, is a heavier dependency, not a
  lighter one — see `ARCHITECTURE.md`'s Architectural Decisions table).
- A private Kotlin account registry (not Android's system `AccountManager`
  framework) listing saved profiles, each with its own `AndroidKeyStore`-
  wrapped credential entry and its own native session handle via `VwClient`
  (TASK-226) — the mobile analogue of `vw_daemon.c`'s multi-account model,
  reimplemented in Kotlin since the daemon's actual C code (fork,
  round-robin scheduling, IPC dispatch) has no Android equivalent to port.
- Add/remove/switch-active-profile UI hooks (the screens themselves are
  TASK-229's job).

## Acceptance criteria

- Credentials are never stored in plaintext anywhere on disk.
- App restart resumes a saved session without re-prompting for a password
  (using the existing `SESSION_RESUME` message via `VwClient`).
- Multiple profiles can be added, each independently authenticated and
  switchable, without cross-contamination of credentials or sessions.
- SEC.07 has reviewed the `AndroidKeyStore` usage specifically (key
  generation parameters, exportability, behavior when hardware backing is
  unavailable) before this closes.

## Notes
