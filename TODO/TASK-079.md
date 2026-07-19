---
id:          TASK-079
title:       Add lockout window-reset/expiry test coverage (no time-mocking infra)
status:      todo
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-19
priority:    low
depends_on:  [TASK-075]
blocks:      []
review_by:   [CQR.08]
tags:        [test-coverage, auth]
---

CQR.08 noted while reviewing TASK-075: `tests/unit/test_vw_auth.c` has no
time-mocking infrastructure, so the new lockout logic's window-reset and
expiry behavior (`lockout_remaining`'s auto-clear when `now >=
locked_until`, and the failure-count reset when the window elapses) is
untested — only the threshold-triggering and anti-enumeration paths are
covered.

## Acceptance criteria

- Add test coverage (via a time-injection seam, a mockable clock, or an
  integration-level test with a short-enough window to observe expiry
  directly) for: lockout expiring after its duration elapses, and the
  failure counter resetting after the window elapses without reaching
  the threshold.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Filed from CQR.08's TASK-075 review advisory. Low
priority test-coverage gap, not a functional bug — doesn't block CI
green.
