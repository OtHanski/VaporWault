---
id:          TASK-141
title:       In-browser vault crypto (WASM Argon2id + SubtleCrypto AES-256-GCM) and vault UI
status:      review
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

WEB.09 [2026-08-12]: Implemented across four new/changed pieces:

1. **Argon2id in WASM** (`web/wasm/`): `vw_vault_kdf_wasm.c` wraps
   `argon2id_hash_raw` with the exact same parameter floor as
   `vw_crypto_vault_derive_kek` (`VW_VAULT_ARGON2_MIN_MEM_KB`/
   `_MIN_TIME_COST`/`_PARALLELISM`, deliberately duplicated as constants
   rather than shared, since importing `vw_crypto.h` here would pull in
   mbedTLS types this module has no other use for). `build.sh` vendors the
   *same pinned Argon2 tag* (`20190702`) as `third_party/CMakeLists.txt`
   via its own shallow clone (no dependency on a native CMake build having
   run first), compiled with `ARGON2_NO_THREADS` — safe because the
   vault's pinned `parallelism=1` already makes Argon2's reference
   `core.c` run strictly sequentially in that configuration (confirmed by
   reading `core.c`'s `#if defined(ARGON2_NO_THREADS)` branch, not
   assumed), so this only removes an unused pthread dependency rather than
   changing behavior. Emscripten SDK installed via `emsdk` in WSL for this
   session (not committed — a toolchain, not a project dependency); the
   *output* (`web/wasm/dist/*.js/.wasm`) is committed like any other
   prebuilt web asset (see `build.sh`'s own note on that call, flagged for
   `TASK-142` to weigh in on long-term).

2. **`web/src/vault-crypto.ts`**: KEK derivation (via the WASM module),
   VK/DEK wrap-unwrap (`SubtleCrypto` AES-256-GCM), and the deterministic
   per-chunk nonce (`SubtleCrypto` HKDF-SHA256). A `Uint8Array<ArrayBufferLike>`
   vs. `BufferSource` friction point from TypeScript 5.7+'s stricter
   typed-array generics needed one centralized, documented cast helper
   (`asBufferSource`) — real values are always plain `ArrayBuffer`-backed
   here, never `SharedArrayBuffer`, so this reflects that guarantee rather
   than working around an actual runtime risk.

3. **Gateway extension**: `/api/files/commit` (`TASK-133`/`139`) gained
   optional `vault_id`/`wrapped_dek` fields, passed through to
   `vw_client_file_commit_raw` unchanged — it was hardcoded to a
   plaintext-only commit before this task needed the encrypted path.

4. **`web/src/api.ts`/`main.ts`**: vault registry wrappers
   (`vaultCreate`/`_KeyFetch`/`_list`), `uploadFileEncrypted`/
   `downloadFileEncrypted` (same per-chunk HTTP loop as the plaintext
   path, TASK-139, but every chunk is encrypted/decrypted client-side
   first), and a vault UI (toolbar "Make this folder a vault" action, a
   banner with Unlock/Lock, all three required disclosures shown via
   `confirm()` before vault creation — passphrase-loss, metadata-scope,
   delta-sync/bandwidth, matching `TASK-100`'s native-GUI equivalent
   word-for-word in substance).

**Every cryptographic primitive was cross-verified byte-for-byte against
the native implementation before being trusted, not assumed compatible
just because both sides claim to implement a named standard** — this
task's own acceptance criteria call this out explicitly, and it's why the
verification below is this detailed:
- Argon2id: WASM output vs. a small C harness calling
  `vw_crypto_vault_derive_kek` directly — byte-identical for the same
  passphrase/salt/params.
- HKDF-SHA256 chunk nonce: `SubtleCrypto`'s HKDF (`salt` = empty
  `ArrayBuffer`) vs. a C harness calling `vw_crypto_vault_chunk_nonce`
  (`mbedtls_hkdf`, `salt=NULL`) — byte-identical across 3 different
  chunk indices, confirming RFC 5869's "absent salt = zero-filled
  hash-length salt" is handled the same way by both implementations.
- AES-256-GCM wrap blob format: a C harness produced a real
  `nonce||ciphertext||tag` blob via `vw_crypto_aes256gcm_encrypt`;
  `SubtleCrypto.decrypt` recovered the exact original plaintext from it
  unmodified, and a fresh `SubtleCrypto.encrypt` round-trip confirmed the
  60-byte layout (`12+32+16`) matches `vw_vault.c`'s `wrap_key`/
  `unwrap_key` exactly.

**Full end-to-end verification against the real gateway+server** (not
mocked), replicating exactly what `main.ts`'s `handleCreateVault`/
`handleUnlockVault` do, via the compiled `web/dist/*.js`:
- Created a vault on a real folder, listed it back, unlocked it with the
  correct passphrase (VK recovered), confirmed a *wrong* passphrase is
  rejected.
- Uploaded two files with **identical plaintext** into the vault and
  confirmed their ciphertext-hash lists differ (`versions/chunks`) —
  proves per-file DEK uniqueness, this task's own acceptance criterion,
  not just "it encrypts something."
- Downloaded both and confirmed byte-identical reconstruction of the
  original plaintext.
- Structurally confirmed **the passphrase was never sent to the
  gateway** by intercepting every request made during the entire test
  run and asserting none of their bodies contained the passphrase
  string — this is an actual network-level check, not just "no code path
  reads a passphrase field" reasoning.

**Two real, pre-existing bugs found and fixed during this task's testing
(both in shared gateway code from earlier tasks, not new to this one)**:
- `VW_ERR_ALREADY_EXISTS` (e.g. `mkdir` on a name that already exists)
  and `VW_ERR_RATE_LIMITED` had no case in `send_file_op_error`
  (`TASK-133`'s helper) and fell into the same "unrecognized error →
  evict + 500" catch-all built for `TASK-155` — exactly the same class
  of gap as the `VW_ERR_AUTH_REQUIRED` fix from `TASK-134`'s testing.
  Fixed: `409 already_exists` and `429 rate_limited` respectively, no
  eviction (both are completely ordinary outcomes). Re-verified: a
  duplicate `mkdir` now returns a clean `409` and the session survives to
  serve the next request — previously it returned a `500` and evicted the
  caller's own session for making an entirely reasonable request.
- Filed `TASK-156` (assigned `PRT.04`, out of this role's domain): a
  real, separate discovery — `FILE_LIST_RESP` never actually carries
  `vault_id` per entry at all (confirmed by reading
  `recv_file_list_resp`), despite the field existing and being documented
  as "so a caller can show a lock icon." Worked around in this task's own
  UI by keying off "is the containing folder a registered vault" instead
  of the per-entry field (correct for anything this UI itself uploads,
  since every file it commits into a vault folder carries that vault's
  id) — see `main.ts`'s `currentFolderVaultId` doc comment for the full
  reasoning and its limits. Not fixed at the source; that's a wire-format
  change outside this role's domain.

Builds clean under both MSVC `/W4 /WX` and GCC for the gateway change;
`tsc --strict` for the frontend.

**Not verified in a real browser**: the vault UI's actual DOM/dialog
interaction (the toolbar button, `confirm()`/`prompt()` sequencing, the
banner's Unlock/Lock toggle) — same no-browser-available caveat as every
other frontend task this session (`TASK-136`-`140`). Every piece of
*logic* the UI calls (crypto, API calls, the encrypted upload/download
loop) has been verified through the compiled output against the real
backend, which is the part with actual correctness risk; the DOM
plumbing on top of it is comparatively low-risk and follows the exact
same patterns already used (and flagged) in `TASK-137`/`138`/`140`.

Moving to `review` — needs SEC.07 + CQR.08 sign-off. Given this task's
own framing ("highest crypto-correctness risk... expect real SEC.07
review time, not a rubber-stamp"), SEC.07 should specifically re-derive
or independently re-verify at least the AES-GCM wrap-blob and HKDF-nonce
cross-checks rather than take this note's word for them, and confirm the
passphrase-never-sent check by running their own network capture during
manual testing rather than relying solely on this task's scripted check.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive`/`crypto` — highest
crypto-correctness risk in this feature, comparable to how `TASK-099` was
flagged as the vault feature's highest-risk task. Expect real SEC.07 review
time here, not a rubber-stamp, per the standing practice `TASK-089`'s
closing note established.
