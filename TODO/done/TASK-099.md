---
id:          TASK-099
title:       "Client vault module (passphrase/KEK/DEK, encrypt-before-upload)"
status:      done
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

CLI.02 [2026-07-31]: Implementation complete. Summary of what shipped:

1. **Wire gap closed** (flagged in `TASK-098`'s own notes, §7.11.4):
   `VERSION_CHUNKS_RESP` now carries optional trailing `vault_id`(u64) +
   `wrapped_dek`(string) fields, mirroring `FILE_COMMIT`'s extension exactly
   — absent/zero for an unencrypted version. Implemented in
   `handle_version_chunks` (`src/server/vw_file_handlers.c`); documented in
   `docs/PROTOCOL.md` §7.3 and version-history row 13. A downloading client
   already calls `VERSION_CHUNKS` right before fetching chunks, so the
   wrapped DEK rides along on that round-trip instead of needing a new one.

2. **Crypto primitives** in `src/core/vw_crypto.h`/`.c`:
   - `vw_crypto_vault_derive_kek()` — Argon2id KEK derivation taking an
     explicit `vw_vault_kdf_params_t {mem_cost_kib, time_cost, parallelism}`
     struct, a genuinely different type from `vw_crypto_argon2id_hash`'s
     implicit `VW_ARGON2_*` constants (satisfies the SEC.07 structural-
     separation guardrail — verified below). Enforces the pinned floor
     (`m_cost >= 19456` KiB, `t_cost >= 2`, `parallelism == 1` exactly) with
     `VW_ERR_INVALID_ARG` below it.
   - `vw_crypto_aes256gcm_encrypt`/`_decrypt` — wrappers over
     `mbedtls_gcm_crypt_and_tag`/`_auth_decrypt` (both mbedTLS modules were
     already enabled in `third_party/mbedtls_config.h`, no new dependency).
     Decrypt zeroes output on auth failure and returns a deliberately
     generic `VW_ERR_CRYPTO` — callers add caller-specific meaning.
   - `vw_crypto_vault_chunk_nonce()` — the mandated deterministic scheme:
     `HKDF-SHA256(ikm=dek, salt=NULL, info="vw-chunk-nonce" || chunk_index
     as 8-byte LE)[0:12]`.
   - 15 new test cases / 83 total assertions in `tests/unit/test_vw_crypto.c`
     (KDF floor rejection ×3, KDF determinism ×2, GCM round-trip, GCM
     tamper detection ×4 independently for tag/ciphertext/key/AAD, nonce
     determinism ×3, and a direct retry-safety test: re-deriving the nonce
     and re-encrypting the same chunk twice with the same dek+index gives
     byte-identical (nonce, ciphertext, tag) both times).

3. **`vw_client_core.h`/`.c`** extended with wire-only primitives (no key
   material touches this file): `vw_client_file_commit_raw` (renamed/
   extended `send_file_commit`), `vw_client_chunk_upload_if_missing`,
   `vw_client_version_chunks_raw`, `vw_client_chunk_download_raw`,
   `vw_client_vault_create/_key_fetch/_list`, and `vw_client_file_mkdir`
   (a genuine gap: `FILE_MKDIR` has existed on the wire since `TASK-104`
   but had no client-library wrapper — needed here because
   `vw_vault_upload_file`'s create-new-file path requires its target to be
   a real `VW_ENTRY_DIR`, not merely an owned file_id — see point 6).
   `download_by_entry` was refactored to use the new raw primitives
   (behavior-preserving: full existing unit + pytest suite green after).

4. **New module `src/client/vw_vault.h`/`.c`** (distinct from
   `src/server/vw_vault.h`/`.c`, TASK-098's server-side storage module):
   `vw_vault_setup`/`_unlock`/`_close`, `vw_vault_upload_file`/
   `_download_file`. Fresh per-file DEK, deterministic per-chunk nonce,
   `VW_VAULT_PLAINTEXT_CHUNK_BYTES = VW_CHUNK_SIZE_DEFAULT -
   VW_AES_GCM_TAG_BYTES` chunking (a full ciphertext+tag chunk then lands
   at exactly the server's `CHUNK_UPLOAD` size ceiling instead of
   overflowing it by 16 bytes — a real constraint found during
   implementation, not a hypothetical one). Own minimal cross-platform
   file reader (`vault_reader_*`) rather than reusing
   `vw_fs_chunk_open`/`_next`, which are hardcoded to a 16-byte-larger
   chunk size with no way to shrink it.

5. **Integration test**: `tests/integration/test_vault_e2ee.c` (new,
   28 assertions) + `test_vault_e2ee.py` (pytest wrapper). Deliberately
   NOT a self-hosted-server test like `test_auth_handshake.c` — it connects
   to a real, already-running `vapourwaultd` spawned by the pytest
   wrapper's reuse of `conftest.py`'s `server`/`admin_client` fixtures, the
   same server-lifecycle code every other integration test uses. This was
   an explicit user decision after I flagged the tradeoff (see the earlier,
   now-superseded checkpoint in this file's edit history): self-hosting a
   server thread here would have meant hand-wiring a full `vw_server_ctx_t`
   (file/share/vault stores, storage) to reproduce `vw_server_main.c`'s
   real per-connection dispatch loop, which `test_auth_handshake.c`'s
   pattern never exercises (it only wires up the auth handshake). Covers:
   byte-identical round-trip, wrapped_dek differs per version, identical
   plaintext across two files in the same vault produces different
   ciphertext, chunk-upload-retry idempotency, unlock-from-scratch
   (new-device simulation) via the real `VAULT_KEY_FETCH` wire round-trip,
   and wrong-passphrase rejection. **First run caught a real bug**: my
   initial test used a plain file (not a real directory) as
   `vault_setup`'s `folder_file_id`; `VAULT_CREATE` accepts that (no
   `entry_type` check), but `FILE_COMMIT`'s "create a new file under this
   folder" branch requires `entry_type == VW_ENTRY_DIR` (see
   `handle_file_commit` in `vw_file_handlers.c`) — so both test files
   silently overwrote the same anchor file instead of being created as
   distinct files. Fixed by adding `vw_client_file_mkdir` (point 3) and
   using a real `FILE_MKDIR`-created directory. This is exactly the kind
   of bug a real end-to-end test catches and a unit test or a
   protocol-level Python test (treating vault fields as opaque bytes)
   would not — validates the standalone-C-binary test approach.

SEC.07 [2026-07-31]: Reviewed the three items this task's acceptance
criteria call out explicitly, plus the two SEC.07 advisories recorded
above by ARCH.00 on 2026-07-29.

- **Passphrase never on the wire** (CONFIRMED by direct code inspection,
  not just testing): `passphrase`/`passphrase_len` appear in
  `src/client/vw_vault.c` in exactly two functions (`vw_vault_setup`,
  `vw_vault_unlock`), and in both, the only thing done with them is a
  local call to `vw_crypto_vault_derive_kek()` (pure Argon2id, no I/O).
  The KEK it produces is likewise never transmitted — it's used only to
  locally `wrap_key`/`unwrap_key` (local AES-256-GCM calls) and is zeroed
  via `vw_crypto_secure_zero()` immediately after each use, on every exit
  path including early error returns. Nothing derived from the passphrase
  reaches `vw_client_vault_create`, `vw_client_file_commit_raw`, or any
  other wire-facing call except the final wrapped-VK/wrapped-DEK
  ciphertext, which is exactly what the design allows.
- **Structural login/vault KDF separation** (CONFIRMED): `vw_crypto_
  vault_derive_kek(const void *passphrase, size_t, const uint8_t salt[16],
  const vw_vault_kdf_params_t *, uint8_t out_kek[32])` vs. `vw_crypto_
  argon2id_hash(const void *password, size_t, const uint8_t *salt, uint8_t
  out_salt[16], uint8_t out_hash[32])` — the `vw_vault_kdf_params_t *`
  parameter is a distinct struct type with no implicit conversion to/from
  `uint8_t out_salt[16]`; a copy-paste or pointer substitution between the
  two call sites fails to compile rather than silently misbehaving. This
  is the guardrail requested, not merely a naming convention.
- **DEK freshness per version / per file, never per vault**: verified at
  both the unit level (`test_vw_crypto.c`'s nonce-determinism-per-dek
  tests) and the integration level (`test_vault_e2ee.c` checks #14 and
  #20: wrapped_dek differs between two versions of the same file, and
  between two different files with identical plaintext in the same
  vault). `vw_vault_upload_file` generates a fresh `vw_crypto_random` DEK
  on every call with no caching or vault-level reuse path — confirmed by
  reading the function: `dek` is a stack-local array, filled once per
  call, never stored on the `vw_vault_t` handle.
- **Nonce-derivation / retry-safety**: the deterministic
  `HKDF(dek, "vw-chunk-nonce" || chunk_index)` scheme means encrypting the
  same chunk index under the same dek always reproduces the same
  (nonce, ciphertext, tag) — proven directly in `test_vw_crypto.c`'s
  "same dek re-encrypting the same chunk index is retry-safe" test, which
  is the strongest form of this property a test can show (byte-identical
  output on repeat, not just "no crash"). Combined with fresh-DEK-per-
  file/version above, no (key, nonce) pair is ever reused across two
  different plaintexts.
- No advisory or blocking findings beyond the two already resolved during
  design (`TASK-089`'s nonce-scheme revision and the Argon2id floor,
  both already reflected in this task's own scope section above).

Sign-off: acceptance criteria met. No blocking findings. Approved for `done`.

CQR.08 [2026-07-31]: No findings. Naming/structure is consistent with the
rest of `vw_client_core.h`/`.c` (raw-primitive functions grouped and
doc-commented the same way sharing/link functions already are); error-path
cleanup (`goto cleanup_upload` / early frees) matches the existing
`upload_chunks`/`download_by_entry` idiom in the same file; secure-zeroing
of key material follows the established `vw_crypto_secure_zero` convention
used throughout `vw_client_core.c`'s auth path.

ARCH.00 [2026-07-31]: SEC.07 and CQR.08 sign-offs recorded above; all
acceptance criteria satisfied. Closing `TASK-099` as `done`. `TASK-100`
(GUI vault UI) and `TASK-101` (E2EE regression tests) are now unblocked.

QA.06 [2026-07-31]: `TASK-101`'s regression suite exercises every
`vw_vault.c`/`vw_client_core.c` API this task added, beyond this task's own
acceptance-test coverage (`test_vault_e2ee.c`):
- **Key-loss scoping** (not previously tested): three vaults — two
  different passphrases, plus a third reusing one of those passphrases'
  exact text but with its own independently-generated VK. Confirmed a
  wrong-passphrase unlock (simulating a forgotten passphrase) on one vault
  has no effect on any other vault's accessibility, including the one
  sharing the same passphrase text — proving passphrase reuse across
  vaults never creates cross-vault access.
- **Cross-vault dedup-defeat** (this task's own test only checked
  same-vault): identical plaintext uploaded plain + into two different
  vaults produces three pairwise-distinct chunk hashes, not just two.
- **Multi-chunk round-trip** (a real gap: every test until now used
  single-chunk content only): a file spanning two real
  `VW_VAULT_PLAINTEXT_CHUNK_BYTES` chunks uploads, downloads, and decrypts
  byte-identical across the chunk boundary.
- **Retry/nonce-safety at realistic (~4 MiB) scale** (this task's own test
  only checked a synthetic 64-byte chunk): encrypting a full-size chunk
  twice with the same DEK+chunk_index reproduces the identical nonce,
  ciphertext+tag, and content hash, and re-uploading it is idempotent —
  the direct regression test for the nonce-reuse gap `HKDF(DEK,
  chunk_index)` exists to close.
All pass; no regressions found in this task's implementation.

SEC.07 [2026-07-31, independent review]: An independent adversarial review
(a fresh reviewer, not the original implementer) of `TASK-099`–`TASK-101`
found two real issues in this task's code, both now fixed:

1. **(High, functional) `vw_vault_unlock()` never populated
   `vault->folder_file_id`**, so `vw_vault_upload_file`'s create-new-file
   path (`file_id == 0`) had nowhere to point for any vault handle that
   came from unlocking rather than creating — the server's
   `handle_file_commit` would reject the resulting bare-leaf-name commit
   as an invalid absolute path. Neither this task's nor `TASK-101`'s test
   suite caught it because every test that called `vw_vault_unlock` only
   used the resulting handle for downloads, never a new upload. Fixed by
   extending `VAULT_KEY_FETCH_RESP` with the vault's `folder_file_id`
   (docs/PROTOCOL.md §7.11.4, purely additive, same pattern as every
   other trailing-field extension) and threading it through
   `vw_client_vault_key_fetch`/`vw_vault_unlock`. Added a regression check
   to `test_vault_e2ee.c` that specifically creates a new file through an
   unlock-derived handle.
2. **(Medium, comment correctness, not a vulnerability)** `wrap_key`'s
   doc comment claimed every wrapping key is used exactly once, which is
   true for KEK→VK but false for VK→DEK (the same VK wraps every file's
   DEK for the vault's lifetime). The actual security property still
   holds — NIST SP 800-38D's birthday bound for independent random 96-bit
   GCM nonces under a fixed key, safe to ~2^32 wraps — but the comment
   was rewritten to state that correctly rather than the wrong "never
   reused" claim, since a future change trusting the wrong reasoning
   could introduce a real bug.

Also addressed as defense-in-depth (not blocking, but worth fixing while
here): `vault_registry_put` (`vw_daemon.c`) leaked an unwrapped VK on its
OOM path despite documenting "takes ownership unconditionally" — now
actually unconditional. `vw_vault_setup` had no minimum passphrase length
enforced below the GUI layer — added `VW_VAULT_MIN_PASSPHRASE_BYTES` (8),
enforced only at creation, deliberately never at unlock (must not lock
a user out of their own already-weakly-passphrased vault). GUI passphrase
buffers (`vw_view_vault.cpp`) weren't zeroed when a dialog was dismissed
via the window's native close button rather than Cancel/Create/Unlock —
fixed via an open→closed transition check.

Full GCC/WSL and MSVC rebuilds clean; full suite re-verified green after
all fixes.
