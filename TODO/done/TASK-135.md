---
id:          TASK-135
title:       "Implement gateway vault registry endpoints (create/key-fetch/list)"
status:      done
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-131, TASK-132]
blocks:      [TASK-141]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, crypto, security-sensitive]
---

Map `vw_client_core.h`'s vault registry surface (create/key-fetch/list) onto
gateway HTTP/JSON endpoints. This task is registry plumbing only — it moves
opaque wrapped-key blobs between the browser and server through the gateway.
**It must never decrypt, derive, or even parse the meaning of a wrapped
key or passphrase** — that happens entirely in the browser (`TASK-141`),
per `TASK-127`'s design decision preserving the vault's zero-knowledge
property (`ARCHITECTURE.md`'s E2EE model, `TASK-089`).

Endpoints:

- `VAULT_CREATE` passthrough — browser derives KEK/VK and wraps client-side,
  sends only the wrapped-VK blob; gateway forwards it to the server
  unmodified.
- `VAULT_KEY_FETCH` passthrough — gateway fetches the wrapped-VK blob from
  the server and returns it to the browser unmodified for local unwrap.
- `VAULT_LIST` — vault metadata listing (no key material).

## Acceptance criteria

- End-to-end vault create/list/key-fetch works through the gateway.
- Structural verification (not just behavioral): no code path in this
  task's endpoint handlers deserializes, logs, or otherwise touches a
  passphrase field or an unwrapped key — the gateway's JSON schema for
  these endpoints should not even *have* a passphrase field, so there's
  nothing to receive by construction. `TASK-143` adds the corresponding
  integration-test assertion for this.
- Wrapped-key blobs pass through byte-for-byte (base64 or equivalent
  encoding round-trips exactly) — a corrupted wrapped-key blob is a vault
  the user can never unlock.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

WEB.09 [2026-08-11]: Implemented in `src/gateway/vw_gateway_api.c`:
`POST /api/vault/create`, `/api/vault/key_fetch`, `/api/vault/list` over
`vw_client_vault_create/_key_fetch/_list`. `wrapped_vk`/`kdf_salt`/
`kdf_params` all move as lowercase-hex JSON string fields (same convention
as `link_token`, `TASK-134`) — capped at `VW_GATEWAY_MAX_WRAPPED_VK_BYTES`
(2048 raw bytes / 4096 hex chars) and `VW_GATEWAY_MAX_KDF_PARAMS_BYTES`
(512/1024) as a sanity bound against a malicious/broken caller sending an
absurdly large blob, not because either field is expected to approach
those sizes in practice (a real wrapped VK is on the order of 60 bytes:
32-byte VK + 12-byte nonce + 16-byte tag).

**Structural no-passphrase check, not just behavioral**: grepped this
task's three handlers and the shared JSON field-decoding helpers they use
— no code path reads a JSON key named anything passphrase-shaped, and
there is no function in this file that calls into `vw_crypto_vault_derive_kek`
or any KEK/decrypt primitive. The gateway's vault JSON schemas structurally
cannot carry a passphrase because no field-extraction call for one exists.

Verified against the real gateway+server (not mocked): alice creates a
folder, registers it as a vault with a random 60-byte wrapped-VK blob +
16-byte salt + 12-byte params (all `/dev/urandom`, opaque to both ends by
construction — nothing about the *content* matters to this test, only
that it round-trips), fetches it back via `key_fetch` and confirms all
three fields plus `folder_file_id` match byte-for-byte, then confirms
`vault/list` shows the vault with no key material present in the listing.

Shares the `send_file_op_error` helper with `TASK-133`/`TASK-134` — the
`VW_ERR_AUTH_REQUIRED` mapping fix documented in `TASK-134`'s note applies
here too (an expired/invalidated session on any of these three endpoints
now gets a clean `401` instead of falling into the generic-error/evict
catch-all), though it wasn't separately triggered in this task's own
testing.

Builds clean under both MSVC `/W4 /WX` (`build-gw-test`) and GCC
(`build-gw-e2e`, WSL).

Not implemented/verified: no frontend vault UI yet (`TASK-141`, the
biggest remaining piece — in-browser Argon2id-to-WASM for the KEK
derivation this endpoint set deliberately never touches). This task is
registry-plumbing-only per its own scope.

Moving to `review` — needs SEC.07 + CQR.08 sign-off; SEC.07's primary
question per this task's own note ("does this code path ever see a
passphrase") is answered no by construction, worth confirming
independently rather than taking WEB.09's word for it.

SEC.07/CQR.08 [2026-08-12]: Reviewed alongside `TASK-133` (see that
task's note for the full `vw_gateway_api.c` pass). Independently
confirmed by direct code read, not taking the implementation note's
word for it: no function in `handle_vault_create`/`_key_fetch`/`_list`
calls any KEK/decrypt primitive, and no field-extraction call for a
passphrase-shaped key exists anywhere in this file — the "does this
code path ever see a passphrase" question is answered no by
construction. One advisory, not blocking: `handle_vault_key_fetch`
hex-encodes the returned `wrapped_vk`/`kdf_params` into fixed
4097/1025-byte stack buffers with no explicit length check against
`VW_GATEWAY_MAX_WRAPPED_VK_BYTES` before encoding — safe today only
because the real wrap format is ~60 bytes; a defensive bound check
would be more robust than relying on the create-side cap holding for
every possible writer of that data. Not fixed in this pass (no current
path can trigger it) — worth a follow-up if this format ever changes.
No blocking findings.
Sign-off: `SEC.07` + `CQR.08` requirements satisfied. Ready for `done`.

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive`/`crypto` — this is
the endpoint set most directly responsible for preserving (or accidentally
breaking) the vault's zero-knowledge guarantee; SEC.07 should treat "does
this code path ever see a passphrase" as the primary review question, not
just standard input-validation checks.
