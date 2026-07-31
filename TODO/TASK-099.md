---
id:          TASK-099
title:       Client vault module (passphrase/KEK/DEK, encrypt-before-upload)
status:      in_progress
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

CLI.02 [2026-07-31]: In-progress checkpoint — implementation and unit-level
verification are done; integration testing against a real server has not
started yet (paused mid-design-decision, see bottom of this note). Status
still `todo` in the frontmatter deliberately, since nothing below is signed
off yet. Recording exact state in detail per explicit instruction, in case
this session is interrupted before the task can be closed out normally.

**Done and verified (GCC/WSL, `-Wall -Wextra -Wpedantic -Werror`, full unit +
pytest integration suite green):**

1. **Wire gap closed** (this was flagged as an open item in `TASK-098`'s own
   notes, §7.11.4): `VERSION_CHUNKS_RESP` (`docs/PROTOCOL.md` §7.3) now
   carries optional trailing `vault_id`(u64) + `wrapped_dek`(string) fields,
   mirroring `FILE_COMMIT`'s existing extension exactly — absent/zero for an
   unencrypted version, so old clients/servers are unaffected. Implemented in
   `handle_version_chunks` (`src/server/vw_file_handlers.c`). This is a
   SRV.01-domain wire change made *within* this task rather than filed as a
   separate out-of-domain task, because TASK-098 explicitly deferred it
   pending a real consumer, and this task is that consumer — see
   `docs/PROTOCOL.md` version-history row 13 for the same rationale recorded
   there. Covered by a new integration test,
   `test_version_chunks_surfaces_vault_id_and_wrapped_dek` in
   `tests/integration/test_vault.py` (passes), plus a Python client helper
   `version_chunks_ex()` in `tests/integration/vw_client.py`.

2. **New crypto primitives** in `src/core/vw_crypto.h`/`.c`:
   - `vw_crypto_vault_derive_kek()` — Argon2id KEK derivation with an
     explicit `vw_vault_kdf_params_t {mem_cost_kib, time_cost, parallelism}`
     parameter struct, deliberately a **different type** from
     `vw_crypto_argon2id_hash`'s implicit `VW_ARGON2_*` constants — satisfies
     the SEC.07 structural-separation guardrail: the two derivation paths
     cannot be pointer-substituted or copy-pasted into each other without a
     compile error. Enforces the pinned floor (`m_cost >= 19456` KiB,
     `t_cost >= 2`, `parallelism == 1` — exactly 1, not merely "at least 1",
     since higher parallelism *reduces* Argon2id's effective memory-hardness
     for a fixed total budget) with `VW_ERR_INVALID_ARG` below it.
   - `vw_crypto_aes256gcm_encrypt`/`_decrypt` — thin wrappers over
     `mbedtls_gcm_crypt_and_tag`/`mbedtls_gcm_auth_decrypt`. Both mbedTLS
     modules (`MBEDTLS_GCM_C`, `MBEDTLS_HKDF_C`) were already enabled in
     `third_party/mbedtls_config.h` — no new dependency. Decrypt zeroes its
     output buffer on auth failure (mbedTLS may write unauthenticated
     plaintext before the tag check completes) and returns a deliberately
     generic `VW_ERR_CRYPTO` — see the doc comment for why the primitive
     itself doesn't guess whether the caller's context makes that "wrong
     passphrase" or "corrupted chunk"; `vw_vault.c` adds that meaning.
   - `vw_crypto_vault_chunk_nonce()` — the mandatory deterministic scheme
     from `docs/PROTOCOL.md` §7.11.3: `HKDF-SHA256(ikm=dek, salt=NULL,
     info="vw-chunk-nonce" || chunk_index as 8-byte LE)[0:12]`.
   - 15 new unit test cases / 83 assertions total in `tests/unit/test_vw_crypto.c`
     covering: KDF floor rejection (mem_cost, time_cost, parallelism != 1),
     KDF determinism, GCM round-trip, GCM tamper detection (tag/ciphertext/
     key/AAD each independently), nonce determinism across (dek, index)
     pairs, and — directly exercising the acceptance criterion about retried
     uploads — a test that re-derives the nonce and re-encrypts the same
     chunk twice with the same dek+index and asserts byte-identical
     (nonce, ciphertext, tag) both times.

3. **`vw_client_core.h`/`.c` extended** with wire-level primitives that move
   bytes but touch no key material (crypto stays entirely in `vw_vault.c`):
   - `vw_client_file_commit_raw()` — `send_file_commit` renamed, exported,
     and extended with optional `vault_id`/`wrapped_dek` params (0/NULL for
     the three existing plaintext callers, unchanged behavior).
   - `vw_client_chunk_upload_if_missing()` — one-at-a-time
     CHUNK_QUERY-then-upload, deliberately not reusing `upload_chunks`'s
     batched pass1/pass2 (which re-reads the plaintext file from disk for
     pass2 — meaningless for ciphertext that only exists transiently in
     memory as it's produced). Documented as a deliberate efficiency
     tradeoff scoped to the vault path only.
   - `vw_client_version_chunks_raw()` / `vw_client_chunk_download_raw()` —
     extracted from `download_by_entry`'s inlined logic so both the
     plaintext download path and `vw_vault.c`'s decrypt path share one
     wire-decoding implementation. `download_by_entry` itself was refactored
     to call these two (behavior-preserving — full existing test suite,
     including all sharing/file-ops/dedup/quota pytest suites, still green
     after the refactor).
   - `vw_client_vault_create/_key_fetch/_list()` — straightforward wrappers
     around `VAULT_CREATE`/`VAULT_KEY_FETCH`/`VAULT_LIST`, treating
     `wrapped_vk`/`kdf_params` as opaque bytes exactly as the server does.

4. **New module `src/client/vw_vault.h`/`.c`** (distinct from
   `src/server/vw_vault.h`/`.c`, which is TASK-098's server-side storage
   module — same name, different directories, deliberately, matching the
   project's client/server module-naming convention elsewhere):
   - `vw_vault_setup()` / `vw_vault_unlock()` / `vw_vault_close()` — generate-
     or-fetch + derive KEK + wrap/unwrap VK; `vw_vault_unlock` maps a GCM
     auth failure specifically to `VW_ERR_AUTH_BAD_CREDS` (wrong passphrase)
     since at that call site a decrypt failure has only one plausible cause.
   - `vw_vault_upload_file()` / `vw_vault_download_file()` — fresh per-file
     DEK, deterministic per-chunk nonce, `VW_VAULT_PLAINTEXT_CHUNK_BYTES`
     (`= VW_CHUNK_SIZE_DEFAULT - VW_AES_GCM_TAG_BYTES`) chunking so that a
     full ciphertext+tag chunk lands at exactly the server's
     `CHUNK_UPLOAD` size ceiling rather than overflowing it by 16 bytes —
     this was a real constraint discovered while implementing (the server's
     `handle_chunk_upload` rejects `data_len > VW_CHUNK_SIZE_DEFAULT`, and a
     naive same-size-as-plaintext chunking would have every full chunk
     rejected). Uses its own minimal cross-platform sequential file reader
     (`vault_reader_*`, mirroring `vw_fs_chunk_open`/`_next`'s exact
     `CreateFileA`/`ReadFile` vs. `open`/`read` idiom) rather than
     `vw_fs_chunk_open`/`_next` directly, since those are hardcoded to read
     `VW_CHUNK_SIZE` (4 MiB) per call — 16 bytes larger than this module's
     chunk size — with no parameter to shrink it.
   - Compiles clean under GCC `-Wall -Wextra -Wpedantic -Werror`. Watched
     specifically for the `small`/`hyper`/`far`/`near`/`huge` Windows-SDK-
     macro-collision gotcha found earlier in `TASK-098` (this file does
     `#include <windows.h>` under `_WIN32`) — no colliding identifiers used.
     MSVC build not yet attempted for this module (see below).

**Not yet done:**

- **Integration testing against a real server** (acceptance criteria:
  byte-identical round-trip, DEK differs per version, same-plaintext
  different-ciphertext across files, retry-safety, code-review confirmation
  that the passphrase never appears on the wire). I raised this to the user
  as a design fork rather than picking silently, because the two natural C
  test patterns already in this repo don't fit cleanly:
    - `test_auth_handshake.c`'s self-hosted-server-thread pattern only wires
      up the auth handshake (`vw_server_conn_handle`); the real per-connection
      file-op message loop (`vw_server_dispatch_file_op`, called repeatedly
      from `handle_connection` in `vw_server_main.c`) is never exercised by
      it, and hand-wiring a full `vw_server_ctx_t` (file store, share store,
      vault store, storage) to reproduce that loop for this one test
      duplicates a meaningful slice of `vw_server_main.c`.
    - The alternative — a small standalone C test binary (links
      `vw_client_core.c` + `vw_vault.c`, takes host/port/cert/credentials as
      argv, connects to a *real* `vapourwaultd` spawned by the existing
      `conftest.py` `server` fixture, same as every Python integration test)
      run via a thin pytest wrapper — reuses real server lifecycle code and
      exercises the actual production client code, but is a new test
      pattern for this repo (existing C integration tests are fully
      self-contained; existing pytest tests drive the pure-Python
      `vw_client.py`, never a compiled C client binary).
    - A third option (reimplementing the crypto in Python inside
      `vw_client.py`, testing the wire/server the way `test_vault.py`
      already does) was also on the table but explicitly rejected as
      insufficient by itself: it would prove the wire protocol can carry
      real crypto, but would never call or verify `vw_vault.c` at all.
  Paused here awaiting ARCH.00/user direction on which pattern to commit to
  before writing ~1 more test file. (User asked mid-decision to checkpoint
  progress in this file first, in case the session is interrupted — hence
  this note.)

  **Decision (user, 2026-07-31): standalone C binary + pytest wrapper.**
  Proceeding with: `tests/integration/test_vault_e2ee.c` (new executable,
  links `vw_client_core.c` + `vw_vault.c` + `vw_core`, takes host/port/
  cert-path/username/password as argv, connects to a real already-running
  `vapourwaultd`, runs the acceptance-criteria assertions, exits 0/1) plus
  `tests/integration/test_vault_e2ee.py` (thin pytest wrapper: reuses the
  existing `server`/`admin_client` fixtures from `conftest.py` to spawn the
  real server and create a test user, then runs the compiled C binary as a
  subprocess and asserts its exit code).
- MSVC build/test of `vw_vault.c` and the new `vw_crypto.c` functions (GCC/
  WSL only so far).
- SEC.07 sign-off note (blocking `done` per this task's own acceptance
  criteria) — not written yet; depends on the integration tests above
  existing first, since sign-off should cover verified behavior, not just
  code that compiles.
- `status:` frontmatter left at `todo` (not `in_progress`) is stale relative
  to actual progress; should be updated to `in_progress` regardless of which
  way the integration-test decision goes — noting here rather than editing
  now, to keep this checkpoint a pure addition.
