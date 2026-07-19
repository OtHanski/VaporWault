---
id:          TASK-077
title:       Use secure_zero (not plain memset) for secrets in vw_admin.c
status:      todo
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-19
priority:    low
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [hardening, security]
---

CQR.08 noted while reviewing TASK-073: `src/server/vw_admin.c` uses plain
`memset()` file-wide to clear secrets (password hashes, salts, the new
`pw_token` buffer), not the `secure_zero` wrapper that `docs/STYLE.md`
§15 requires (a compiler-fence memset variant that defeats dead-store
elimination — see the pattern already used in `src/server/vw_auth.c`:
`static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;`
`#define secure_zero(p, n) ((void)(g_memset_fn)((p), 0, (size_t)(n)))`).
A sufficiently aggressive optimizer can prove a `memset` immediately
followed by `free`/return is dead and elide it, leaving secrets in
freed/stack memory.

This is pre-existing (predates TASK-073's change) and not a regression —
non-blocking, filed as a follow-up hardening task.

## Acceptance criteria

- All `memset(..., 0, ...)` calls on secret material (password hashes,
  salts, tokens) in `vw_admin.c` use the same `secure_zero` pattern as
  `vw_auth.c`.
- No behavior change other than the zeroing mechanism.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-19]: Filed from CQR.08's non-blocking advisory during
TASK-073's review. Low priority — hardening, not a functional bug.
