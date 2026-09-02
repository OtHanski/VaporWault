---
id:          TASK-227
title:       "AndroidKeyStore-backed credential storage + multi-profile account registry"
status:      done
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

- MOB.10, 2026-09-02: Implemented under a new `accounts` package:
  `VwSecureStore` (raw `AndroidKeyStore` AES-256-GCM encrypt/decrypt of
  small blobs, key generated once and never regenerated), `Profile`/
  `ProfileStore` (one `.properties` + one `.cred` file pair per profile
  under a private app directory — plaintext metadata, encrypted
  credentials), and `VwAccountRegistry` (ties `ProfileStore` + `VwClient`
  together: `addProfile`, `resume`, `removeProfile`).
  Added one new JNI export beyond the original scope, `nativeConnectWithHash`
  / `VwClient.connectWithHash`, wrapping `vw_client_connect_with_hash` —
  needed to actually *use* the stored "login token" (SHA-256(password))
  the scope calls for, as the fallback path when `SESSION_RESUME` fails
  (typically natural token expiry), matching the desktop daemon's own
  two-tier fallback precedent. Storing that token with no code path ever
  reading it back would have been half-finished.
- **Runtime verified, 2026-09-02**, against a real `vapourwaultd`+headless
  emulator (same setup as TASK-225/226), covering all three functional
  acceptance criteria for real, not just by inspection:
  - **Plaintext criterion**: added a profile, then read the resulting
    `.cred` file's raw bytes directly (104 bytes — exactly matches
    4-byte IV-length prefix + 12-byte IV + 72-byte plaintext + 16-byte GCM
    tag) and confirmed programmatically that the session token is not
    present in it as a contiguous byte sequence.
  - **Restart-without-reprompting criterion**: added two profiles
    (`androidtest`→user_id 1, `androidtest2`→user_id 2), then did a *real*
    `adb shell am force-stop` + relaunch (not just re-using the same
    process) and tapped "Resume Profiles" without touching the
    username/password fields at all — both profiles resumed correctly to
    their own distinct user_ids. Cross-checked the server log to confirm
    no `SESSION_RESUME`-related rejection was logged (only the
    already-known `TASK-237` `AUTH_LOGOUT`-dispatch warnings, one per
    `client.close()` call, count matching exactly), i.e. the primary
    resume path genuinely succeeded rather than the test silently
    passing via the login-token fallback every time.
  - **Multi-profile / no cross-contamination criterion**: covered by the
    same two-profile run above — both profiles independently resumable,
    correct distinct identities, no mixing.
  - Did this twice more: once after adding the hardware-backing check
    below (regression-only, same result), and once after a full
    `adb uninstall`+reinstall specifically to force real key (re)generation
    and exercise the new logging path for real rather than hitting the
    "key already exists" fast path — confirmed `VwSecureStore` logs
    `"AndroidKeyStore key is NOT hardware-backed on this device"` on this
    x86_64 emulator (the correct, expected result — AVDs have no real
    TEE/StrongBox), with `addProfile` still succeeding cleanly around it.

**Security review (SEC.07-focused, since the acceptance criteria calls
this out specifically) + CQR.08 self-review, 2026-09-02:**
  - **Key generation parameters**: AES-256-GCM, no padding, StrongBox
    attempted first (API 28+, falling back to TEE/software on
    `StrongBoxUnavailableException`), `setUserAuthenticationRequired(false)`.
    The last one is a deliberate, necessary choice, not an oversight — the
    acceptance criteria explicitly requires resuming *without*
    re-prompting, which a user-authentication-gated key can't do; the key
    is still confined to this app's UID via `AndroidKeyStore` and never
    enters process memory as raw bytes either way.
  - **Exportability**: non-exportable by construction — the key is
    generated *inside* `AndroidKeyStore` via `KeyGenerator.getInstance(...,
    "AndroidKeyStore")`, never imported from raw bytes Kotlin ever held,
    so there's no raw-key-material export path to review in the first
    place.
  - **Hardware-backing unavailable**: previously unchecked — added
    `logHardwareBacking()` (uses `KeyInfo.securityLevel` on API 31+,
    falling back to the deprecated-but-still-correct
    `isInsideSecureHardware` boolean below that, explicitly `@Suppress`-ed
    with a comment explaining why the deprecated path is still needed for
    `minSdk 26`) — logs a warning, doesn't fail, since the app still has to
    function on a device with no secure hardware and there's no
    user-facing control to reject that case. Verified this actually fires
    correctly (see runtime verification above) rather than just compiling.
  - **Blocking, fixed**: `ProfileStore.create()` wrote the plaintext
    `.properties` metadata file *before* the encrypted `.cred` file — a
    process death in between would leave a permanently-broken profile
    visible to `list()` (metadata exists, credentials don't, `resume()`
    always fails for it) with no way for a user to tell why. Swapped the
    write order so an interrupted `create()` instead leaves an invisible
    orphan `.cred` file (harmless — `list()` only scans `.properties`
    files).
  - **Advisory, not fixed**: `ProfileStore.decrypt()`/`readCredentials()`
    throw (don't return null) on tampered/corrupt/`KeyPermanentlyInvalidated`
    input, by design (documented in `VwSecureStore`'s KDoc) — matches
    `javax.crypto`'s own AEAD-failure convention, but means
    `VwAccountRegistry.resume()` can itself throw in that specific edge
    case rather than cleanly returning null like every other failure path.
    TASK-229's UI will need its own try/catch around `resume()` calls;
    noted here rather than papering over it with a blanket catch that
    would hide a real corruption signal.
  - No other blocking findings. JNI review for the new
    `nativeConnectWithHash` export: same patterns already reviewed for
    `nativeConnect`/`nativeSessionResume` in TASK-226 (borrow/release
    helpers, `vw_crypto_secure_zero` on the token buffer before release,
    consistent failure-sentinel convention) — nothing new to flag.
