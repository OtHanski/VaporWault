---
id:          TASK-234
title:       "Security review: Android TLS verification, AndroidKeyStore, vault parity, SAF fd handling"
status:      todo
assignee:    SEC.07
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-227, TASK-228, TASK-230]
blocks:      [TASK-235, TASK-236]
review_by:   [CQR.08]
tags:        [security-sensitive]
---

Dedicated security pass across the whole Android client, since it's new
externally-reachable-credential surface (mirrors the review rigor the web
gateway got in `TASK-127`'s wave).

Scope:
- TLS verification/pinning strategy on Android — confirm the JNI bridge
  never allows `VW_CERT_VERIFY_NONE`-equivalent behavior in a release build,
  matching the gateway's own hardened requirement.
- `AndroidKeyStore` usage correctness (TASK-227): key generation parameters,
  behavior when hardware backing is unavailable, exportability guarantees.
- Vault crypto parity (TASK-230): confirm the KDF parameter floor and
  per-chunk nonce derivation match the desktop/web implementations exactly,
  and that passphrase material never persists or logs.
- SAF fd-handling (TASK-228): confirm no path-traversal-equivalent issue is
  possible through a maliciously-named SAF document, and that only
  user-explicitly-granted URIs are ever touched.
- Auth token transport: confirm the Android client's `AUTH_REQUEST.auth_token`
  derivation matches what the live server actually expects — `docs/PROTOCOL.md`
  §8.1 and `src/client/vw_client_core.c`'s comment disagree about whether this
  is Argon2id or `SHA-256(password)`; verify against the real server code path
  (`vw_auth.c`) before shipping, don't trust either comment.

## Acceptance criteria

- Every finding is tagged `blocking` or `advisory` per the routing rules;
  `blocking` findings resolved (with MOB.10) before this closes.
- Findings feed TASK-235's regression test list.

## Notes
