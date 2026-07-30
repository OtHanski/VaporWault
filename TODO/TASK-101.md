---
id:          TASK-101
title:       E2EE regression tests (round-trip, dedup-defeat, key-loss scoping)
status:      todo
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
