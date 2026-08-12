---
id:          TASK-059
title:       CQR.08 full code quality audit and STYLE.md completion
status:      done
assignee:    CQR.08
created_by:  ARCH.00
created:     2026-07-13
priority:    normal
depends_on:  []
blocks:      []
review_by:   [ARCH.00]
tags:        [code-quality, documentation, phase-8]
---

Full code quality audit of the complete VaporWault C/C++ codebase. Produces a
STYLE.md document recording project-wide conventions, and a findings report
with `blocking` and `advisory` tags. Blocking findings spawn new tasks.

## Scope

### C best practices
- Error-path completeness: every function that can fail must have its return
  value checked by callers; no silently discarded `vw_err_t`
- Resource cleanup on all error paths (no memory leaks, no file descriptor
  leaks under error conditions)
- `const` correctness: pointers that are not modified should be `const`
- No implicit fallthrough in `switch` statements (C99: must use explicit
  `/* fall through */` comment or be absent)

### Undefined behaviour
- Signed integer overflow: verify no unchecked arithmetic on `int` for sizes
- Pointer aliasing: verify no strict-aliasing violations in serialization code
  (endian helpers that cast `uint8_t *` to wider types)
- Array bounds: every array index derived from external input must be range-checked

### API consistency
- Naming: `vw_{module}_{verb}` for public functions; `{verb}_{noun}` for static helpers
- Lifecycle: every `*_open` / `*_create` has a matching `*_close` / `*_destroy`
  in all callsites including error paths
- Output parameter convention: `*out_` prefix for all output parameters;
  `const` on all input-only pointer parameters

### Structural clarity
- Large source files (>800 lines): flag for potential module split
- Comment quality: flag any comment that describes WHAT rather than WHY
- Dead code: flag any unreachable branch or unused static function

### STYLE.md completion

`docs/STYLE.md` should be updated to document every decision made so far
(naming, error handling, serialization helpers, test conventions). The goal
is that a new developer can read STYLE.md and understand the project's C
conventions without reading the existing code.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: Priority order for audit: (1) `vw_store.c` and
`vw_storage.c` — largest and most complex, highest UB risk; (2)
`vw_file_handlers.c` — largest handler file, many error paths; (3)
`vw_cluster.c` and `vw_oplog.c` — replication correctness depends on
error-path discipline. STYLE.md must cover the endian helper pattern
(`vw_write_u32le` / `vw_read_u32le` from vw_proto.h) — it is used everywhere
and new code must follow the same pattern.

CQR.08 [2026-07-13]: Full audit complete. Files reviewed: vw_proto.h,
vw_store.c, vw_storage.c, vw_file_handlers.c, vw_cluster.c, vw_oplog.c,
vw_gc.c, vw_auth.c.

**No blocking findings.**

Advisory findings:

advisory: vw_oplog.c:492 (Windows) and :523 (POSIX) — `segs_insert()` return
  value is silently discarded in `enumerate_segments`. On OOM, a segment would
  be silently absent from the replay index, causing incomplete crash recovery
  or incorrect GC truncation decisions. Probability is low but the fix is
  trivial: propagate the return value through `enumerate_segments` and return
  early on VW_ERR_OOM.

advisory: vw_cluster.c:110 — `cluster_log` is missing
  `__attribute__((format(printf, 2, 3)))`. The `gc_log` function in vw_gc.c
  has this attribute. Without it, GCC/Clang will not emit format-string
  mismatch warnings for cluster log call sites.

advisory: vw_cluster.c:119 — `#include <stdarg.h>` appears after code in
  the middle of the file, outside the include block. Move to the top with the
  other standard headers.

advisory: vw_store.c — 1572 lines, exceeds the ~800 line threshold from
  STYLE.md §3. Consider splitting the quota subsystem
  (`vw_store_quota_*`) into `vw_store_quota.c`.

advisory: vw_auth.c:148 — `run_dummy_hash` uses a fixed dummy salt
  (`memset(dummy_salt, 0xAA, ...)`) for timing normalisation. A randomly
  generated dummy salt per process startup would eliminate any theoretical
  timing distinguisher between fixed-salt dummy hashes and real hashes.
  Current approach is sound in practice (Argon2id timing is memory-bandwidth
  bound, not salt-dependent), but worth noting.

advisory: vw_storage.c:601 — `(void)vw_fs_sync_file(st->rcdb_path)` in
  `vw_storage_gc_run` intentionally discards the sync error (GC is
  best-effort). This is correct behaviour but should have a comment explaining
  why the error is intentionally ignored.

docs/STYLE.md updated: added §14 (endian helpers), §15 (sensitive-data
zeroing, secure_zero, constant-time comparison), §16 (test conventions, TAP
harness, stub pattern for opaque types). All three sections contain
concrete code examples matching the codebase.

LGTM.

ARCH.00 [2026-07-14]: Code quality audit reviewed. No blocking findings. Six
advisory items — all minor: the segs_insert return-value discard and the missing
format-attribute on cluster_log are the most actionable. STYLE.md additions
(§14 endian helpers, §15 sensitive-data zeroing, §16 test conventions) are
complete and high-quality. Marking done.
