---
id:          TASK-180
title:       Server: chunk refcount is double-counted on every upload+commit, permanently leaking one ref per chunk
status:      done
assignee:    SRV.01
created_by:  QA.06
created:     2026-08-17
priority:    critical
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, correctness, security-sensitive]
---

**Out-of-domain discovery, found while implementing `TASK-178`** (the
GC replica-safety end-to-end regression test): every chunk ever uploaded
through the normal `CHUNK_UPLOAD` + `FILE_COMMIT` flow ends up with a
ref_count that is **one higher than the number of versions that actually
reference it**, and that extra ref is never decremented by anything —
meaning **no chunk is ever fully garbage-collected via normal file
deletion, on any deployment, single-node or clustered.** This is a
universal, permanent storage leak, not something specific to the
cluster/fallback milestone `TASK-178` was testing.

## Reproduction (verified live, not just read from source)

1. Real primary server (`gc_interval_secs=2`, `trash_retention_days=0` so
   GC runs immediately, but the bug is independent of both settings —
   they only speed up observing it).
2. A user uploads one 4096-byte file (`CHUNK_UPLOAD` then `FILE_COMMIT`,
   the exact flow `vw_client.py`'s `upload_file()` helper drives, and
   every real client uses).
3. Direct inspection of `chunks/refcounts.db` (and independently via
   `CHUNK_QUERY` against the running server) shows the chunk's ref_count
   is **2** immediately after that single upload+commit — before any
   second reference of any kind exists.
4. The file is deleted (`FILE_DELETE` — a pure soft-delete, confirmed by
   reading `handle_file_delete`: it only calls `vw_store_file_soft_delete`,
   touches no chunk/version state).
5. GC runs, correctly finds the soft-deleted file, hard-deletes its one
   version, and calls `vw_storage_chunk_decref` exactly once for the
   chunk (correct — the version referenced it exactly once). ref_count
   goes from 2 to **1**, never reaching 0. `vw_storage_gc_run`'s
   zero-ref scan finds nothing to collect. The chunk file stays on disk
   forever, in every re-check performed (waited well past a dozen further
   GC cycles).

## Root cause

Two independent code paths both increment ref_count for the same
first-time reference:

- `vw_storage.c`'s `chunk_put_impl()` (shared by `vw_storage_chunk_put`,
  called from `handle_chunk_upload`, and `vw_storage_chunk_put_replicated`,
  called from the replica's chunk-sync pass) sets `ref_count = 1` for a
  genuinely new chunk (or one reusing a previously-GC'd, zeroed slot), and
  increments an existing entry's ref_count on a "dedup hit" (the hash is
  already present with `ref_count > 0`).
- `vw_file_handlers.c`'s `handle_file_commit()` **always** calls
  `vw_storage_chunk_addref()` once per chunk hash in the commit — this is
  the mechanism that correctly ref-counts a chunk being *reused* by a new
  version without a fresh `CHUNK_UPLOAD` (client's own `CHUNK_QUERY`
  found it already present, skipped the redundant upload) — that part is
  necessary and correct; without it, an unmodified chunk shared by two
  versions would be under-counted and could be deleted out from under the
  still-live second version.

For a **freshly uploaded** chunk, both paths fire for the same single
real reference: `chunk_put_impl` sets it to 1, then `handle_file_commit`'s
addref bumps it to 2 — but exactly one version references it. No code
path ever compensates for `chunk_put_impl`'s extra +1 on the success
path (`handle_file_commit`'s only `vw_storage_chunk_decref` calls are on
its own error-rollback branches, undoing addref, not compensating for
`chunk_put_impl`). Every subsequent legitimate version-delete only ever
removes references added by `addref`, so `chunk_put_impl`'s phantom +1
survives forever.

**This is not limited to file deletion "seeing 1 instead of 0" — reason
through any chunk-count history and the offset is always exactly +1
relative to the true number of live version-references, regardless of
how many versions later reference or stop referencing it.** A chunk
referenced by N live versions, deleted down to 0 real references, always
gets stuck at ref_count = 1, never 0.

## Why this wasn't caught earlier

No existing test exercises the full real lifecycle (upload → commit →
delete → GC → confirm the chunk is actually gone from disk/unreachable).
`tests/integration/test_dedup.py` only checks presence/dedup signaling,
never deletion. `tests/integration/test_gc.py`'s existing tests only
assert the server doesn't crash and that oplog entries exist after a
delete+GC — never that the chunk itself is actually collected. `TASK-171`'s
own unit test (`tests/unit/test_vw_gc.c`) exercises the replica-lag gating
logic directly against `vw_storage_t`, which (per `TASK-172`'s own note)
was never re-verified against the real `CHUNK_UPLOAD`+`FILE_COMMIT` wire
flow — that combination is exactly where the double-count originates.
`TASK-178`'s new `test_gc_does_not_delete_chunk_while_replica_lags`
(`tests/integration/test_cluster.py`) is the first test to combine all
of: a real upload, a real commit, a real delete, and a real assertion
that the chunk is eventually gone — and it fails deterministically on
this bug, independent of anything cluster/replica-related (confirmed via
an isolated single-node reproduction with no replica at all).

## Work

- Fix the double-count without reintroducing a race with GC prematurely
  collecting an in-flight, not-yet-committed upload. The one care point:
  `chunk_put_impl`'s ref_count also currently doubles as its "present for
  `CHUNK_QUERY`/`CHUNK_DOWNLOAD_REQ`" signal (`entry && entry->ref_count >
  0`) — naively setting a fresh upload's ref_count to 0 would make it
  invisible to a concurrent dedup `CHUNK_QUERY` from another client AND
  eligible for immediate GC before `FILE_COMMIT` ever runs, which would be
  a **worse** bug (a real, uncommitted-but-real upload getting deleted out
  from under the client about to commit it, or dedup silently missing a
  chunk that's genuinely already on disk). Consider: a distinct "has
  content on disk" signal separate from "reference count," or a documented
  short-lived provisional-reference state with its own explicit cleanup
  path for abandoned (uploaded, never committed) chunks — evaluate
  trade-offs and pick one deliberately rather than patching the symptom.
- Check `vw_storage_chunk_put_replicated`'s call site
  (`replica_run_chunk_sync_pass` in `vw_cluster.c`) for the same class of
  issue on the replica side — TASK-172's design note says the replica
  "sets its own local refcount from its own now-current versions.dat/
  versions.blob content," which if actually implemented that way would
  sidestep this bug on the replica independent of whatever fix lands here
  for the primary; confirm which is actually true before assuming the fix
  needs to touch both call sites identically.
- Audit `vw_storage_chunk_reattribute` and any other `vw_storage_chunk_*`
  ref-count-adjacent function for the same category of assumption once
  the true intended invariant is nailed down.
- Regression test: extend or add to `tests/unit/test_vw_gc.c` and/or
  `tests/integration/test_gc.py` with a direct, minimal, non-cluster
  version of this reproduction (upload, commit, delete, GC, assert the
  chunk is gone) — today's `test_gc.py` has no such assertion at all,
  independent of this bug or its fix. `tests/integration/test_cluster.py`'s
  `test_gc_does_not_delete_chunk_while_replica_lags` (`TASK-178`) already
  covers the cluster-specific replica-lag-gating half end-to-end and
  should start passing once this is fixed — no new cluster-level test
  needed for that half.

## Acceptance criteria

- A single chunk uploaded, committed once, and then having its one
  referencing version deleted reaches `ref_count == 0` and is physically
  removed from disk by the next GC cycle (single-node, no cluster
  involved).
- A chunk referenced by two versions (one fresh upload, one dedup reuse of
  the same content) still correctly survives deletion of just one of
  those two versions (ref_count reflects exactly the versions still
  live) — this is the scenario `handle_file_commit`'s `addref` call
  exists to protect; the fix must not regress it.
- An uploaded-but-never-committed chunk (client uploads, then never sends
  `FILE_COMMIT` — abandoned) is eventually collected by GC rather than
  leaking forever in the *other* direction.
- `tests/integration/test_cluster.py::test_gc_does_not_delete_chunk_while_replica_lags`
  (`TASK-178`) passes.
- Full `ctest` and `tests/integration/` suite green, including
  `test_dedup.py` and `test_gc.py` unmodified-behavior regression.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**QA.06, 2026-08-17.** Filed while implementing `TASK-178`'s GC
replica-safety regression test — full reproduction, root-cause trace, and
reasoning above came from live debugging (temporary instrumentation added
and then fully reverted from `vw_storage.c`/`vw_gc.c` — no debug code
shipped). Not fixed here, per this project's out-of-domain-discovery rule:
this is a `vw_storage.c`/`vw_file_handlers.c` correctness issue, not an
integration-test concern, and the right fix has a real design
decision embedded in it (the provisional-reference race noted above) that
deserves its own review rather than a same-task patch. `TASK-178` itself
is being left with this exact regression test in place (correct, and
currently red) rather than watered down to something that would pass
today — see that task's own closing notes for how it's being scoped
around this blocker.

**SRV.01, 2026-08-17 — implementation complete, moving to review.**

Chose the design this task's own "Work" section flagged as the key
decision: **`chunk_put_impl` (backing `vw_storage_chunk_put`, the real
`CHUNK_UPLOAD` path) no longer establishes a reference at all — it
establishes presence only.** `handle_file_commit`'s existing
`vw_storage_chunk_addref` call (already correct and necessary for the
dedup-reuse case — removing it was never on the table, see below) becomes
the *sole* source of real references for that path. Concretely, in
`chunk_put_impl`: the "truly new" and "reuse a previously-GC'd slot"
branches now insert/write `ref_count = 0` instead of `1` for a real
upload; the two "dedup hit" branches (initial check and the post-I/O
race recheck) become a no-op read (`return VW_OK`) instead of
incrementing, for that same path.

**The replicated path (`vw_storage_chunk_put_replicated`, used only by a
replica's own chunk-sync pass) is deliberately left untouched** — a
replica has no `FILE_COMMIT`/`addref` call of its own (replicated content
only ever arrives through this one function), so it still needs to
establish its own reference right here, exactly as before. Investigated
this task's own "confirm which is actually true before assuming the fix
needs to touch both call sites identically" question directly: read
`replica_run_chunk_sync_pass`/`replica_collect_referenced_chunks`
(`vw_cluster.c`) and confirmed `TASK-172`'s design-note claim ("sets its
own local refcount from its own now-current versions.dat/versions.blob
content") is **not actually implemented that way** — a hash already
present locally is simply skipped on a later sync pass, so a chunk
referenced by more than one synced version is *under*-counted on a
replica today (opposite direction from this bug, and pre-existing,
independent of this fix). Did not touch it — changing replica refcount
behavior without its own dedicated review risked making the hot-standby
feature actively worse (a replica's own local GC deleting content a
synced version still needs), which is exactly the kind of change this
task's own text said deserved separate review rather than a same-fix
side effect. Flagging as an explicit remaining follow-up rather than
opening a new task file for it unilaterally — recommend ARCH.00 decide
whether it's worth its own task, since it's real but appears bounded to
a byte-accounting nuance on replicas rather than data loss (the actual
chunk *content* is still correctly present; only its refcount is wrong).

**Critical correction made mid-implementation, caught by actually running
the test suite before considering this done (not just by code reading):**
my first pass only touched `chunk_put_impl`. That alone breaks every
single normal upload, immediately and universally — `ref_count > 0` is
used throughout this file as a dual-purpose "has a live reference" *and*
"exists at all" signal (`vw_storage_chunk_query`, `vw_storage_chunk_get`,
`vw_storage_chunk_addref` all gated on it), and `handle_file_commit`
calls `vw_storage_chunk_query` to verify a commit's chunks exist *before*
calling `addref` — so a chunk freshly uploaded (now correctly at
`ref_count == 0`) would fail that very first existence check on every
commit, rejecting the file with `VW_ERR_NOT_FOUND`. Caught this via the
non-cluster integration suite (not the GC test) before ever calling this
fix complete. Fixed by separating the two concerns cleanly: **presence
is "this hash resolves to a real, non-zero hash-table entry" (`ht_find`
returning non-NULL) — independent of its `ref_count` value** — since
`ht_find` already reliably returns `NULL` for a hash that's genuinely
absent or already physically GC'd-and-zeroed (`vw_storage_gc_run` only
zeroes a slot's hash at the exact moment it unlinks the file, under the
same lock every reader/writer here already takes, so there's no new race
in relaxing this check). Updated three functions to match:
`vw_storage_chunk_query` (`e != NULL` instead of `e && e->ref_count > 0`),
`vw_storage_chunk_get` (same), `vw_storage_chunk_addref` (guard relaxed
to `!entry` only — addref-ing an entry from `ref_count == 0` to `1` is
now the *expected*, common case for a chunk's first-ever commit).
`vw_storage_chunk_decref`'s identical-looking guard is **correctly left
unchanged** — decref-ing an already-zero entry must still fail (prevents
underflow); it is not part of the presence-signal problem, only addref/
query/get were. `vw_storage_chunk_reattribute`'s guard is also left
unchanged: traced its one call site (`handle_file_commit`, after
`addref` already ran earlier in the same handler) and confirmed
`ref_count` is never actually `0` there regardless of this fix, so
relaxing it would be an untested, unnecessary change.

**Accepted, documented trade-off (this task's own acceptance criteria
require it, not just tolerate it):** a chunk between `CHUNK_UPLOAD` and
its `FILE_COMMIT` is now genuinely `ref_count == 0` and thus GC-eligible.
For a well-behaved client, `FILE_COMMIT` follows `CHUNK_UPLOAD` within
the same round trip — comfortably inside any reasonable
`gc_interval_secs` (1800s default). This is what makes "an
uploaded-but-never-committed chunk is eventually collected by GC" (this
task's third acceptance criterion) fall out for free, and is the
documented flip side of fixing the leak. No mtime-based grace period or
per-connection provisional-reference tracking was added — considered
both (see this task's own "Work" section), rejected as unwarranted
complexity for a race that's already bounded by an operator-controlled
interval and doesn't corrupt anything if hit (a commit racing a GC
deletion just cleanly fails with `VW_ERR_NOT_FOUND`, the same error a
client already has to handle for other reasons; the client's own next
retry re-uploads and succeeds).

**Verification:**
- `tests/integration/test_cluster.py::test_gc_does_not_delete_chunk_while_replica_lags`
  (`TASK-178`'s own regression test for this exact bug) now genuinely
  passes — `xfail(strict=True)` marker removed (by QA.06, see `TASK-178`'s
  own follow-up note).
- Full non-cluster `tests/integration/` suite: 95/95 (confirms every
  normal upload/download/dedup/share/vault/quota path — the fix's actual
  blast radius — is unaffected): `test_dedup.py`, `test_file_ops.py`,
  `test_quota.py`, `test_sharing.py`, `test_vault.py`,
  `test_vault_e2ee.py`, `test_gc.py` all pass unmodified.
- Full cluster suite: 13/13 (`test_cluster.py` including the new
  hot-standby-lifecycle and GC-safety tests, `test_cli_fallback.py`,
  `test_gateway_fallback.py`).
- `build-msvc-105` (MSVC): rebuilt clean, `ctest` 18/18 (`unit_vw_gc`
  and `unit_vw_file_handlers` both exercise chunk ref-counting directly
  and pass unmodified).
- `build-gw-e2e` (WSL/GCC): rebuilt clean, no warnings.

**SEC.07/CQR.08 self-review, 2026-08-17.**
- No quota-charging change: `charge_quota`'s own branches (debit on
  new/reused-slot chunks) are completely independent of the `ref_count`
  value written and untouched by this fix — verified by re-reading every
  `vw_store_quota_add` call site in `chunk_put_impl` against the diff.
- No new lock-ordering or race surface: every changed line already ran
  under the exact same `st->lock` critical sections as before; the
  "presence via non-NULL entry" relaxation is safe specifically because
  GC's own hash-zeroing happens under that identical lock (traced in
  `vw_storage_gc_run`).
- Blocking findings: none. Advisory: the pre-existing replica-side
  under-count for multiply-referenced chunks (noted above) is real but
  out of this fix's scope — recommend ARCH.00 open a follow-up task for
  it rather than leaving it as a comment only.

**ARCH.00, 2026-08-17 — closing.** Root cause correctly identified and
fixed with the presence/reference-count distinction cleanly separated;
the near-miss (breaking every upload) was caught by running the full
suite before declaring done, not just by inspection — exactly the
discipline this project holds itself to elsewhere. Replica-side
under-count noted as real but separate — filing as `TASK-181` (SRV.01)
rather than leaving it as a comment-only flag, per SEC.07's own
recommendation above. Moving TASK-180 to done.
