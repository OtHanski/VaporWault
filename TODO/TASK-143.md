---
id:          TASK-143
title:       Integration tests for the web gateway + browser client
status:      todo
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-10
priority:    high
depends_on:  [TASK-132, TASK-133, TASK-134, TASK-135, TASK-137, TASK-138, TASK-139, TASK-140, TASK-141]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [test, gateway, web, security-sensitive]
---

Per `CLAUDE.md`'s Step 7 (integration testing), write and run tests against
the assembled web gateway + browser client feature before ARCH.00 can close
`TASK-127`'s milestone. This mirrors `TASK-097`/`TASK-101`'s role for the
sharing and vault features.

Required coverage:

1. **End-to-end round trips** through the actual gateway + nginx (not just
   the gateway directly): login (+2FA) → file list → upload → download →
   delete; version list/restore; share grant/revoke; public link create/
   redeem/revoke.
2. **Vault zero-knowledge verification** — not just "decryption works," but
   a structural check that the gateway process never observes plaintext or
   the passphrase: inspect gateway-side logs/memory or network capture
   during a vault create/unlock/upload/download test run and assert no
   passphrase field or unwrapped-key material ever appears gateway-side
   (per `TASK-135`/`TASK-141`'s acceptance criteria).
3. **Multi-session concurrency** — two simulated browser sessions logged in
   simultaneously against one gateway process, confirming session isolation
   (`TASK-131`'s acceptance criteria) — one session's actions must not
   affect or leak into the other.
4. **Regression tests for every SEC.07 finding** that comes out of
   `TASK-144`'s review pass, per standing project policy (every resolved
   SEC.07 finding gets a regression test, `CLAUDE.md`'s QA.06 responsibilities).
5. Malformed/adversarial HTTP input against `TASK-129`'s `vw_http` layer
   (truncated headers, oversized bodies) and malformed JSON against
   `TASK-130`'s `vw_json` layer — confirm clean rejection, not a crash.

## Acceptance criteria

- All coverage above passes against a real running server + gateway +
  nginx stack, not mocked.
- Sign-off note added to this task before ARCH.00 closes the `TASK-127`
  milestone, per `CLAUDE.md`'s Step 7/Step 8 workflow.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Depends on the full initial implementation set
since it's an end-to-end pass across the whole feature, matching how
`TASK-097`/`TASK-101` closed out the sharing/vault features. Tagged
`security-sensitive` since it must positively verify the vault's zero-
knowledge property, not just functional correctness.
