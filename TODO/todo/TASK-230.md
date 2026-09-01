---
id:          TASK-230
title:       "Vault support: JNI exposure of vw_vault, passphrase UI, vault browser"
status:      todo
assignee:    MOB.10
created_by:  ARCH.00
created:     2026-08-31
priority:    high
depends_on:  [TASK-226, TASK-229]
blocks:      [TASK-234]
review_by:   [SEC.07, CQR.08]
tags:        [security-sensitive]
---

Bring E2EE vault support (create/unlock/browse) to the Android client, in
scope for the first milestone per the user's explicit decision.

Scope:
- Extend the JNI bridge (built on `vw_client_core.c`/`vw_vault.c`, already
  compiled into `libvaporwault_jni.so` per TASK-225) with `VAULT_CREATE`,
  `VAULT_KEY_FETCH`, `VAULT_LIST`, and the `FILE_COMMIT`/
  `VERSION_CHUNKS_RESP` optional `vault_id`/`wrapped_dek` fields.
- Passphrase-entry UI feeding straight into
  `vw_crypto_vault_derive_kek`/`vw_vault.c` through the bridge — the
  passphrase must be held only as a `CharArray` on the Kotlin side, zeroed
  after use, never logged, never persisted, never passed as a Java `String`
  (which the JVM cannot reliably zero).
- Verify byte-for-byte parity with the desktop implementation: Argon2id
  floor `m_cost >= 19456 KiB`, `t_cost >= 2`, `parallelism == 1` exactly, and
  the deterministic per-chunk nonce derivation
  (`HKDF-SHA256(ikm=DEK, info="vw-chunk-nonce" || chunk_index_LE64)`) — cross-
  check against `src/core/vw_crypto.c`/`src/client/vw_vault.c` directly,
  the same way the web frontend's `vault-crypto.ts` documents having done
  (see its header comment).
- Vault browser UI: create a vault, unlock an existing one, browse its
  contents through the same file-browser components TASK-229 built.

## Acceptance criteria

- A vault created on desktop (or web) can be unlocked and browsed from
  Android with the same passphrase, and vice versa — real interop, not just
  "Android's own vaults work with Android."
- The passphrase never appears in a log, crash report, or persisted file at
  any point.
- SEC.07 has reviewed the KDF parameter and nonce-derivation parity, and the
  passphrase-handling lifecycle, before this closes.

## Notes
