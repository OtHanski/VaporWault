---
id:          TASK-135
title:       Implement gateway vault registry endpoints (create/key-fetch/list)
status:      todo
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

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive`/`crypto` — this is
the endpoint set most directly responsible for preserving (or accidentally
breaking) the vault's zero-knowledge guarantee; SEC.07 should treat "does
this code path ever see a passphrase" as the primary review question, not
just standard input-validation checks.
