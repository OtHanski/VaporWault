---
id:          TASK-141
title:       In-browser vault crypto (WASM Argon2id + SubtleCrypto AES-256-GCM) and vault UI
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-127, TASK-135, TASK-138]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [web, crypto, security-sensitive]
---

Implement the in-browser half of the vault's zero-knowledge design
(`TASK-127`'s decision, `ARCHITECTURE.md`'s E2EE model from `TASK-089`):
passphrase → Argon2id → KEK → unwrap/wrap VK → per-file DEK → AES-256-GCM,
entirely in the browser. Nothing here goes through the gateway except
opaque ciphertext and wrapped-key blobs (`TASK-135`).

Scope:

1. **Argon2id in the browser**: compile the project's existing vendored
   Argon2 reference source (`third_party/`, pulled via `FetchContent`,
   pinned 20190702 per `ARCHITECTURE.md`'s dependency table) to WASM via
   Emscripten, rather than pulling in a separate JS/WASM Argon2 package —
   reuses the same primitive the native client uses, keeping parameters
   (`ARCHITECTURE.md`: `m_cost >= 19456` KiB, `t_cost >= 2`,
   `parallelism = 1`, per `TASK-089`'s design) consistent across native and
   web clients rather than risking drift between two implementations.
2. **AES-256-GCM**: use the browser's native `SubtleCrypto` API — no need
   to compile/vendor anything for this half, it's a Web Crypto API
   built-in.
3. Key hierarchy logic in TypeScript: derive KEK from passphrase +
   Argon2id, unwrap the vault's VK (fetched as an opaque blob via
   `TASK-135`'s `VAULT_KEY_FETCH` passthrough), derive/unwrap per-file DEKs,
   decrypt downloaded ciphertext / encrypt before upload. Match the nonce
   scheme settled in `docs/PROTOCOL.md` §7.11 (`TASK-089`'s design:
   deterministic `nonce = HKDF(DEK, "vw-chunk-nonce" || chunk_index)[0:12]`)
   exactly — a nonce-derivation mismatch between native client and web
   client would be a correctness bug at best and a GCM nonce-reuse
   vulnerability at worst.
4. Vault UI: create/unlock/browse flows, plus the same disclosures the
   native GUI already requires (`TASK-100`'s acceptance criteria) —
   passphrase-loss warning, metadata-scope disclosure (filenames/folder
   structure/sizes are still server-visible), and the delta-sync/bandwidth
   tradeoff note (full-file re-upload on every edit to an encrypted file,
   per `TASK-089`'s accepted tradeoff in §7.11.5) — do not silently drop any
   of the three just because this is a different frontend stack.
5. Passphrase handling: never stored (matching the native client's
   in-memory-only policy — no persistence, no `localStorage`), held only
   for the duration of an unlock session in browser memory, cleared on
   logout/tab close where feasible.

## Acceptance criteria

- Vault create/unlock/upload/download round-trips correctly, byte-identical
  plaintext after decrypt.
- Two different files in the same vault with identical plaintext produce
  different ciphertext (verifies per-file DEK uniqueness, matching
  `TASK-101`'s equivalent native-client test requirement from `TASK-089`'s
  SEC.07 review).
- Nonce derivation matches the native client's HKDF scheme exactly (cross-
  verify against `vw_vault.c`'s implementation, not just this task's own
  derivation).
- All three required disclosures (passphrase-loss, metadata-scope,
  delta-sync/bandwidth) are shown in the vault setup/unlock UI.
- Structural check: the passphrase is never included in any HTTP request to
  the gateway (verify by inspecting network traffic during testing, not
  just code review) — this is the load-bearing guarantee for the whole
  zero-knowledge design.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive`/`crypto` — highest
crypto-correctness risk in this feature, comparable to how `TASK-099` was
flagged as the vault feature's highest-risk task. Expect real SEC.07 review
time here, not a rubber-stamp, per the standing practice `TASK-089`'s
closing note established.
