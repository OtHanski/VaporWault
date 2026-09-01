---
id:          TASK-235
title:       "Integration tests: Android client against a real vapourwaultd"
status:      todo
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-31
priority:    normal
depends_on:  [TASK-229, TASK-230, TASK-231, TASK-232, TASK-233, TASK-234]
blocks:      [TASK-236]
review_by:   [CQR.08]
tags:        []
---

Automate the manual verification path recorded in the Android design plan:
build via Gradle, run on an emulator/device, point at a local `vapourwaultd`
using the same throwaway-TLS-cert approach
`tests/integration/gen_test_cert.sh` already uses, with `adb reverse` tying
the emulator's loopback to the host-run server.

Scope:
- Instrumented/Espresso UI tests for login → 2FA → browse → upload →
  download → vault create/unlock → share/link, covering the same ground the
  manual pass in TASK-229/230/231 exercised by hand.
- A regression test for every `blocking` finding TASK-234 resolved.
- Wire into a CI-runnable convenience target analogous to the existing
  `vw_integration_test` CMake target, adapted to drive `adb` instead of a
  local process (coordinate with BLD.05/TASK-233 on where this lives).

## Acceptance criteria

- Automated tests cover the full login→browse→transfer→vault→share path.
- Every SEC.07 finding from TASK-234 has a corresponding regression test.

## Notes
