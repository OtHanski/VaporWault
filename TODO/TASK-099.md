---
id:          TASK-099
title:       Client vault module (passphrase/KEK/DEK, encrypt-before-upload)
status:      todo
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-089, TASK-098]
blocks:      [TASK-100, TASK-101]
review_by:   [SEC.07, CQR.08]
tags:        [client, crypto, security-sensitive]
---

Implement the client side of the E2EE design published in
`docs/PROTOCOL.md` §7.11 (`TASK-089`): all actual cryptography lives here,
never server-side.

Scope:

- New `vw_vault` module: vault setup (generate VK, derive KEK from an
  encryption passphrase via Argon2id — reuse the already-vendored Argon2id
  primitive, do not add a second implementation), wrap/unwrap VK (AES-256-
  GCM), upload the wrapped-VK blob via `VAULT_CREATE`.
- New-device unlock: fetch a vault's wrapped-VK blob via `VAULT_KEY_FETCH`,
  prompt for the encryption passphrase, re-derive KEK, unwrap VK locally.
- Upload path integration: for a file under an encrypted vault, generate a
  fresh random DEK **per file, never per-vault** (a per-vault DEK would
  silently make identical plaintext across files produce identical
  ciphertext — see the DEK-scoping guardrail in §7.11.2), and never reuse a
  DEK across versions (a new version of an encrypted file gets a brand-new
  DEK). Encrypt each 4 MiB chunk with AES-256-GCM before it reaches
  `CHUNK_UPLOAD`, using **`nonce = HKDF(DEK, "vw-chunk-nonce" || chunk_index)[0:12]`**
  (revised 2026-07-29 per SEC.07 finding — do **not** implement the
  earlier random-prefix + counter scheme; a retried upload restarting the
  counter under that scheme causes a real GCM nonce collision, which this
  deterministic derivation avoids since re-deriving the same chunk index's
  nonce on retry is safe as long as that chunk's plaintext is unchanged,
  which holds for a resumed upload of the same version). Wrap the DEK with
  the vault's VK and send it alongside `FILE_COMMIT` per the storage
  plumbing TASK-098 defines.
- Download path integration: after `CHUNK_DOWNLOAD`, unwrap the file's DEK
  (using the already-unlocked vault's VK) and decrypt each chunk before it
  reaches the sync engine / local cache.
- Passphrase handling: must reuse secure-memory handling already used for
  the account login credential (per CLI.02's existing "credential storage"
  responsibility) — zero the passphrase and derived KEK from memory as soon
  as they're no longer needed, matching the SEC.07-flagged fix already made
  to the login path in `TASK-087` (zeroing partial secrets on early-return
  paths).
- **Structural passphrase/login separation (SEC.07 advisory, added
  2026-07-29)**: give `derive_login_token()` (§8.1) and this module's
  `derive_kek()` distinct, non-interchangeable function signatures/types so
  they cannot be pointer-substituted or copy-pasted into each other
  undetected — a structural guardrail, not just a review checklist item.
- **Argon2id parameter floor (SEC.07 advisory, pinned in §7.11.5, added
  2026-07-29)**: at minimum `m_cost >= 19456` KiB, `t_cost >= 2`,
  `parallelism = 1` for the vault-wrapping KDF — do not ship below this
  floor.

## Acceptance criteria

- A file placed under an encrypted vault round-trips (upload → download →
  byte-identical plaintext) using a real client + server.
- Confirmed via code review (not just testing) that the encryption
  passphrase and any value derived directly from it (other than the final
  wrapped-VK ciphertext) never appears in any wire message — specifically
  confirm this code path does not accidentally reuse the login
  password-hashing function from §8.1, which *intentionally* sends a
  derived token to the server.
- A new version of a previously-uploaded encrypted file gets a genuinely
  new DEK (verified by inspecting the wrapped-DEK blob differs between
  versions, not just that content differs).
- Two different files under the same vault with identical plaintext
  produce different ciphertext (confirms DEK uniqueness is per-file, not
  per-vault).
- An interrupted/retried upload of the same version does not produce a
  nonce collision (verify by simulating a dropped connection mid-upload and
  confirming the retry succeeds and decrypts correctly).
- SEC.07 signs off on the passphrase-handling, DEK-freshness, and nonce-
  derivation properties before this moves to `done`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-089`. This is the
highest-risk implementation task of the two design tasks closed today — the
entire "true E2EE, not server-recoverable" property depends on this module
getting passphrase/key handling right, so budget real SEC.07 review time
before marking done, not just a rubber-stamp pass.
