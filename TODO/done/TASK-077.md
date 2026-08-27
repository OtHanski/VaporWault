---
id:          TASK-077
title:       "Use secure_zero (not plain memset) for secrets in vw_admin.c"
status:      done
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

SRV.01 [2026-07-30]: Added the same `secure_zero`/`g_memset_fn` pattern
from `vw_auth.c` to `vw_admin.c` and converted every `memset(..., 0, ...)`
call that clears secret material: `pw_token`, `hash`/`salt` in
`handle_user_create` (all paths — error and success), `rec.password_hash`/
`rec.password_salt` after `vw_store_user_create`, the fetched
`vw_user_record_t urec`/`rec` in `handle_set_quota` and
`handle_set_admin_caps` (both the early-return and post-success paths),
`token`/`resp` (carries the cluster `auth_token`) in `handle_node_add` and
`handle_node_register_self`, and the request `payload` buffer zeroed
before `free()` in `handle_admin_connection` (may contain a raw password).
Left the one pre-existing `memset(&rec, 0, sizeof(rec))` in
`handle_user_create` untouched — that call zero-*initializes* a fresh,
not-yet-populated struct before filling it in, it isn't clearing a secret,
so it's out of this task's scope.

Validation: rebuilt clean on both platforms — GCC/WSL Ubuntu
(`VW_WERROR=ON`, full build + all 12 ctest suites pass) and MSVC
`/W4 /WX` (all 11 ctest suites pass). No behavior change — confirmed by
the unchanged admin-CLI integration tests passing unmodified.

CQR.08 [2026-07-30]: Reviewed the diff. Every `secure_zero` call sits on a
buffer/struct that genuinely carries secret material (password hash/salt,
a raw password token, or a cluster join `auth_token`); the one remaining
plain `memset` (struct init before first write) is correctly left alone.
No blocking or advisory findings. Sign-off given.

ARCH.00 [2026-07-30]: CQR.08 sign-off received. Both acceptance criteria
satisfied. Closing as done.
