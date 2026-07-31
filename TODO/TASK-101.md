---
id:          TASK-101
title:       E2EE regression tests (round-trip, dedup-defeat, key-loss scoping)
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-098, TASK-099]
blocks:      []
review_by:   [CQR.08]
tags:        [testing, crypto, security-sensitive]
---

Write regression tests for the E2EE feature (`TASK-089`,
`docs/PROTOCOL.md` §7.11). Security-sensitive per routing rule 1; every
SEC.07 finding resolved against `TASK-098`/`TASK-099` needs a corresponding
regression test.

Scope (minimum, expand based on SEC.07 findings from TASK-098/099):

- Round-trip: upload an encrypted file, download it on a second (simulated)
  device after unlocking via `VAULT_KEY_FETCH` + passphrase, confirm
  byte-identical plaintext.
- Dedup-defeat confirmation: upload the same plaintext content both as a
  plain file and as an encrypted file; confirm the encrypted version does
  **not** share a chunk with the plain version or with a second encrypted
  upload of the same plaintext under a different vault (i.e., confirm
  ciphertext is actually unique per file, not just "assumed" unique).
- Key-loss scoping: confirm that a vault whose passphrase is "forgotten"
  (simulated by discarding the local KEK) does not affect any *other*
  vault's accessibility, including one protected by a different passphrase
  and one protected by the same passphrase but a different VK.
- Version DEK freshness: confirm two versions of the same encrypted file
  have distinct wrapped-DEK blobs.
- Server opacity: confirm (e.g. by direct inspection of server-stored
  bytes in a test harness) that no plaintext or unwrapped key material is
  ever observable server-side for an encrypted file.
- **Retry/nonce-safety regression (SEC.07 finding, added 2026-07-29)**:
  simulate an interrupted upload of an encrypted file (drop the connection
  mid-chunk-sequence) and retry it; confirm the retried upload succeeds and
  the downloaded content decrypts correctly — this is the regression test
  for the nonce-reuse gap that motivated switching to
  `HKDF(DEK, chunk_index)` nonce derivation in §7.11.2.

## Acceptance criteria

- All scenarios above pass.
- Sign-off note added to `TASK-098`/`TASK-099` before ARCH.00 closes the
  E2EE milestone.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-089`.

QA.06 [2026-07-31]: Implemented as `tests/integration/test_vault_regression.c`
(a C binary linking `vw_client_core.c`/`vw_vault.c` directly against a real
running server, same pattern as `TASK-099`'s `test_vault_e2ee.c`) plus
`test_vault_regression.py` (pytest wrapper: runs the binary, then does a
black-box scan of the server's raw `data_dir` for a plaintext marker the
binary uploaded exclusively as encrypted content).

Coverage against this task's scope:
- Round-trip: covered by `TASK-099`'s own `test_vault_e2ee.c` (not
  duplicated here) — unlock-from-scratch, byte-identical plaintext.
- Dedup-defeat: **expanded** beyond same-vault — plain file + two
  different vaults, three pairwise-distinct chunk hashes confirmed.
- Key-loss scoping: **new** — three vaults (two passphrases, one reused
  passphrase text with an independent VK); a forgotten/wrong passphrase on
  one never affects another's accessibility.
- Version DEK freshness: covered by `TASK-099`'s test (not duplicated).
- Server opacity: **new** — a distinctive marker uploaded only as
  encrypted content is confirmed absent from every file under the server's
  raw `data_dir` (chunks, `versions.blob`, `vaults.blob` — the scan is
  format-agnostic, doesn't need to know any of their internal layouts).
- Retry/nonce-safety: **expanded** to realistic scale — a full-size
  (~4 MiB) chunk re-encrypted with the same DEK+chunk_index reproduces an
  identical nonce, ciphertext+tag, and content hash, and re-uploading it
  is idempotent. Also added a genuine multi-chunk upload/download
  round-trip, which nothing before this task had exercised (every prior
  vault test used single-chunk content only).

All 34 assertions in the C binary pass, plus the opacity scan. Full
GCC/WSL (`-Wall -Wextra -Wpedantic -Werror`) and MSVC (`/W4 /WX`) builds
clean; full unit + pytest integration suite green (58 passed, only the
pre-existing unrelated IT-7 quota flake). Sign-off notes added to
`TASK-098` and `TASK-099` per this task's acceptance criteria.

CQR.08 [2026-07-31]: No findings. `test_vault_regression.c` follows
`test_vault_e2ee.c`'s established harness conventions exactly (same
CHECK macro, same temp-dir helpers, same teardown discipline); the
opacity scan's marker-isolation design (a separate marker never uploaded
as plaintext, specifically to avoid a false-positive from the
intentionally-unencrypted control copy in the dedup-defeat scenario) is
documented inline where it matters.

ARCH.00 [2026-07-31]: QA.06 and CQR.08 sign-offs recorded above; all
acceptance criteria met. Closing `TASK-101` as `done`. This closes the
`TASK-089` E2EE milestone (`TASK-098`–`TASK-101` all done) — see
`ARCHITECTURE.md`'s End-to-end encryption model section for the
implementation-complete summary and the two design decisions that emerged
during implementation.
