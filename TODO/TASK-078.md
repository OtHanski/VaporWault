---
id:          TASK-078
title:       Lockout table evicts by slot index, not by soonest-expiry — unfair eviction under load
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-19
priority:    low
depends_on:  [TASK-075]
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [hardening, security, auth]
---

SEC.07 and CQR.08 both flagged this (advisory, non-blocking) while
reviewing TASK-075's brute-force lockout implementation.

`lockout_find_or_evict` in `src/server/vw_auth.c` evicts the oldest
*slot index* (ring-buffer cursor order), not the entry with the
soonest-expiring lockout or oldest failure window. On any deployment with
more than `LOCKOUT_TABLE_SIZE` (256) active accounts, or under an
attacker deliberately touching 256+ distinct existing usernames, a
legitimately-locked account's entry can be evicted early, clearing its
lockout ahead of schedule. This degrades the lockout's effectiveness
("brute force is somewhat easier than intended") but is not an
enumeration or confidentiality break.

## Acceptance criteria

- Eviction preferentially clears entries that are not currently locked,
  or are closest to expiry, before evicting an active lockout.
- Consider whether table size should scale with expected user count
  instead of a fixed 256.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Filed from SEC.07/CQR.08's TASK-075 review
advisories. Low priority hardening, not a functional/security-critical
bug — doesn't block CI green.
