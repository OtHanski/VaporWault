---
id:          TASK-098
title:       Server-side vault storage (wrapped keys, opaque encrypted chunks)
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-29
priority:    normal
depends_on:  [TASK-089]
blocks:      [TASK-101]
review_by:   [SEC.07, CQR.08]
tags:        [server, storage, protocol, security-sensitive]
---

Implement the server side of the E2EE design published in
`docs/PROTOCOL.md` §7.11 (`TASK-089`). The server's role here is
deliberately narrow: store opaque key-wrapping blobs and treat encrypted
chunk content exactly like any other chunk. No content decryption or key
material ever exists server-side.

Scope:

- New vault storage table (`vaults/vaults.db`): vault_id, owner_id,
  folder_file_id, wrapped_vk blob, kdf_salt, kdf_params, created_at.
  Fixed-size record + variable-length blob area for the wrapped key,
  matching this codebase's existing pattern (e.g. `versions.blob`).
- Implement `VAULT_CREATE`/`_ACK`, `VAULT_KEY_FETCH`/`_RESP`, `VAULT_LIST`/
  `_RESP` handlers per §7.11.4. The server must treat `wrapped_vk`/
  `kdf_salt`/`kdf_params` as fully opaque bytes — no parsing, no validation
  beyond size limits.
- Extend `vw_version_record_t` to carry `vault_id` + a reference (offset/
  length into `versions.blob`) to the file's wrapped DEK, reusing the
  existing `_reserved[32]` bytes. Finalize the exact byte layout and get a
  CQR.08 on-disk-compatibility review, matching how `TASK-090`'s
  `deleted_at` reuse was reviewed (confirm `_Static_assert(sizeof(...) ==
  80)` still holds, confirm pre-existing records read back sane defaults).
- Confirm (and note in review) that crash-recovery/oplog replay for
  encrypted files needs zero special-casing — it already operates on
  opaque chunk bytes for every file today.
- Confirm dedup requires no code changes (§7.11.2) — encrypted chunks
  naturally never collide given unique per-file ciphertext. Do not add an
  explicit "is this file encrypted, skip dedup" branch; if you find
  yourself writing one, that's a sign the DEK/nonce scheme upstream (CLI.02,
  `TASK-099`) isn't actually producing unique ciphertext and should be
  flagged back to CLI.02, not worked around server-side.

## Acceptance criteria

- `VAULT_*` messages round-trip correctly against a real client.
- `_Static_assert` confirms `vw_version_record_t`'s size is unchanged; a
  pre-existing (pre-encryption-feature) version record reads back with
  `vault_id == 0` (meaning "not encrypted") cleanly.
- SEC.07 confirms no code path anywhere logs, caches, or otherwise persists
  unwrapped key material or plaintext — the server's crypto-blindness is
  the property being verified here, not just "some encryption happens
  somewhere."

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-29]: Filed as part of decomposing `TASK-089` once its
design was settled and published in `docs/PROTOCOL.md` §7.11.
