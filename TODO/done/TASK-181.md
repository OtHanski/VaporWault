---
id:          TASK-181
title:       "Server - replica-side chunk refcount under-counts a chunk referenced by more than one synced version"
status:      done
assignee:    SRV.01
created_by:  SEC.07
created:     2026-08-17
priority:    normal
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, correctness]
---

**Out-of-domain discovery, found while implementing `TASK-180`** (the
primary-side chunk refcount double-count fix): investigating whether that
fix needed to also touch `vw_storage_chunk_put_replicated` (used only by
a replica's own chunk-sync pass, `vw_cluster.c`'s
`replica_run_chunk_sync_pass`/`replica_collect_referenced_chunks`) turned
up a separate, pre-existing, unrelated bug on the replica side —
independent of `TASK-180`'s primary-side bug and not fixed by it.

`ARCHITECTURE.md`'s "Replica hot-standby data replication" decision row
(and `TASK-172`'s own implementation note) both describe the intended
design as: the replica "sets its own local refcount from its own
now-current versions.dat/versions.blob content — never from any value
the primary sends." **This is not actually what the code does.**
`replica_collect_referenced_chunks` correctly builds the full list of
every chunk hash referenced by every version currently in the replica's
own `versions.dat`/`versions.blob` — including duplicate entries when
more than one version references the same hash. But
`replica_run_chunk_sync_pass` only calls `vw_storage_chunk_put_replicated`
(the only thing that ever sets a ref_count on the replica's own store)
for hashes it does **not already have locally** — a hash already present
from an earlier fetch is silently skipped on every later pass, even
though it now appears in the referenced-chunks list again for the new
version. The replica's own refcounts.db therefore always reflects "how
many times this exact hash was ever *newly fetched*" (effectively capped
at a small number, often 1), not "how many live versions currently
reference it."

**Consequence:** if a replica's own local GC (every server, including a
replica, runs its own GC thread — confirmed in `vw_server_main.c`) ever
looks at replica-local refcounts to decide chunk eligibility, a chunk
genuinely still needed by a second, later-synced version could show a
refcount lower than its true reference count. Whether this is currently
a live data-loss risk or a latent one depends on how aggressively a
replica's own GC prunes relative to how many multiply-referenced chunks
typically exist — needs investigation, not assumed either way.

## Work

- Confirm exactly how badly this manifests: does a replica's local GC
  ever actually run zero-ref cleanup against these under-counted values
  today, or does something else (e.g., the replica never independently
  decides to delete content — only ever receiving primary-driven sync
  writes) make this currently inert? Read `vw_gc.c`'s interaction with a
  replica-role server's own `vw_storage_t` before assuming either way.
- Design the correct fix: most likely, on each `replica_run_chunk_sync_pass`,
  recompute (or reconcile) the replica's own refcounts.db to match the
  true occurrence count from `replica_collect_referenced_chunks`'s full
  (non-deduplicated) list — matching what `ARCHITECTURE.md`/`TASK-172`
  already claim happens. Consider whether this needs a new
  `vw_storage_chunk_set_refcount`-style primitive (an authoritative
  overwrite, distinct from `addref`/`decref`'s incremental semantics)
  rather than reusing `chunk_put_replicated`'s per-fetch increment for
  this purpose.
- Regression test: a real primary + replica, one file with two versions
  both referencing the identical chunk content (second version created
  via a client that skips re-uploading dedup'd content, matching how
  `vw_client.py`'s `upload_file` already behaves), synced to a replica,
  then confirm the replica's own refcount for that chunk actually
  reflects 2 real references — not 1.

## Acceptance criteria

- A chunk referenced by two live versions on the primary, once fully
  synced to a replica, shows the same true reference count on the
  replica as it would if computed from scratch by scanning the replica's
  own version records — not merely "at least 1."
- Deleting one of the two versions (on the primary, replicating through
  to the replica in the normal way) does not cause the replica to
  under-count and prematurely lose the chunk while the second version
  still needs it.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**SEC.07, 2026-08-17.** Filed during `TASK-180`'s review — see that
task's SRV.01 implementation note and self-review for the full
investigation trail. Not fixed as part of `TASK-180` since it's a
distinct bug on a distinct (replica) code path with its own design
question (how the replica should recompute vs. incrementally track
refcounts), deserving its own review rather than riding along with that
task's primary-side fix.

**SRV.01, 2026-08-17.** Investigated and fixed.

- **Manifestation confirmed live, not inert.** `vw_server_main.c` starts
  the GC thread unconditionally regardless of `cluster.is_replica`, and
  `vw_gc.c`'s `replica_lag_blocks_gc` gate (TASK-171) only trips when
  *this* server's own cluster has active replicas *of its own* — a plain
  replica leaf node always has `vw_cluster_has_active_replicas() == 0`,
  so its GC pass 3 (`vw_store_file_scan_deleted` → `chunk_decref` →
  `vw_storage_gc_run`) runs every cycle, unconditionally, against its own
  under-counted refcounts.db. `replica_run_file_sync_pass` re-fetches
  `files.db` wholesale on any change (not gated on the chunk-sync
  trigger), so a primary-side soft-delete's `deleted`/`deleted_at` fields
  reach the replica's own file_store correctly. This is a real
  premature-chunk-loss path, confirmed end-to-end by the new regression
  test below (fails reliably without the fix, passes with it).

- **Fix**: added `vw_storage_chunk_set_refcount` (`vw_storage.c`/`.h`) —
  an authoritative overwrite of a chunk's `ref_count`, distinct from
  `addref`/`decref`'s +1/-1 semantics, modeled directly on `decref`'s own
  locking/HT-update/rcdb-write pattern. `replica_run_chunk_sync_pass`
  (`vw_cluster.c`) now calls a new `replica_reconcile_chunk_refcounts`
  helper after its existing fetch loop: sorts a working copy of the full,
  non-deduplicated `hashes` list (from `replica_collect_referenced_chunks`)
  by hash, walks contiguous runs to get each unique hash's true occurrence
  count, and `set_refcount`s each one — safe to re-run every pass
  regardless of what any earlier pass left behind, matching
  ARCHITECTURE.md's/TASK-172's stated "recompute from scratch" design.
  Went with an authoritative overwrite (as the task's own Work section
  suggested) rather than reusing `chunk_put_replicated`'s per-fetch
  increment, since the bug is precisely that incremental tracking
  under-counts across passes — recomputation from the current
  ground-truth list is what actually matches the documented design.

- **Regression test**: `tests/integration/test_cluster.py::
  test_replica_reconciles_refcount_for_multiply_referenced_chunk`. Uses
  two separate files (not two versions of one file) each holding one live
  reference to identical (deduped) content, since there's no
  client-facing single-version-delete op to isolate "drop one of two
  references held by the same file" — see the test's own docstring for
  why that's the client-observable equivalent of the task's described
  scenario. Sequences the two uploads so the replica's first
  `chunk_put_replicated` (ref_count=1) happens in an earlier pass than the
  second file's dedup-only reference, reproducing the bug's actual
  cross-pass trigger rather than the harmless same-pass case. Verified
  both ways: fails with `AssertionError` (chunk_query flips to `False`
  after file_a's delete syncs through) when the reconciliation call is
  temporarily disabled, passes with it restored. Full
  `test_cluster.py` suite (9 tests) and `test_vw_gc`/`test_vw_store` unit
  tests all still pass.

- Verified via native MSVC build (`build-msvc-105`, clean compile + unit
  tests) and a fresh WSL/Ninja build (`build-wsl2`, scratch dir, removed
  after use) for the integration test above — noted for BLD.05 in case it
  matters: this session's original `build-wsl` CMake cache had a stale/
  corrupted `_deps/mbedtls-src` FetchContent checkout unrelated to this
  change (a fresh reconfigure into a new build dir resolved it cleanly);
  separately, running these cluster integration tests against a
  natively-built Windows `vapourwaultd.exe` hangs waiting for the admin
  socket to appear even on an unmodified test — reproduced with
  `test_pairing_registers_both_sides` — so these tests need WSL/Linux,
  not native Windows, to run at all in this environment.

**SEC.07, 2026-08-18.** Reviewed. No blocking findings.

- Trust boundary is unchanged from the existing replica-sync design:
  `hashes` is built from the replica's own `files.db`/`versions.dat`/
  `versions.blob`, which only ever get overwritten by
  `replica_fetch_and_write_file` after the mTLS-authenticated,
  pre-shared-token cluster handshake (`vw_cluster.c`'s own header comment)
  — no new untrusted input path is introduced.
- `vw_storage_chunk_set_refcount` takes the same write-lock as
  `addref`/`decref` and follows their exact read-modify-write-unlock
  shape; no new race window.
- `replica_reconcile_chunk_refcounts`'s `malloc((size_t)count *
  VW_HASH_BYTES)` mirrors the identical existing pattern in
  `replica_collect_referenced_chunks` — same theoretical-only overflow
  exposure as that pre-existing code (would need `count` to already
  exceed what a real deployment's live version set could produce), not
  worsened by this change.
- Noted, not filed as a new task (severity is effectively zero, not a
  security-relevant path): `replica_collect_referenced_chunks`'s
  `*out_count` accumulates into a `uint32_t` from a `uint64_t` running
  total (`total_hashes`) that the allocation itself is correctly sized
  against — a hypothetical wrap of the `uint32_t` count would need over
  4 billion referenced (version, chunk) pairs in one replica's live
  version set to ever manifest. Pre-existing since TASK-172; this task's
  reconciliation pass inherits whatever `count` that function returns but
  doesn't change its correctness.
- Confirmed the fix doesn't reintroduce TASK-171's replica-safety gate
  gap: reconciliation only ever calls `set_refcount` for hashes the fetch
  loop already confirmed present, and the NOT_FOUND defensive-skip path
  can only fire against a hash a concurrent local GC pass legitimately
  zeroed out from under it — logged, not silently swallowed.

**CQR.08, 2026-08-18.** Reviewed. One advisory finding fixed directly;
one left as-is (not worth the churn).

- **Fixed**: `vw_storage_chunk_set_refcount` did an unconditional
  `rcdb_write` (which always fsyncs) on every call, but
  `replica_reconcile_chunk_refcounts` now calls it once per unique
  referenced hash on *every* chunk-sync pass (every `replica_poll_interval_secs`,
  a few seconds by default) — most of those calls leave the count
  unchanged from the prior pass. Added an early return when
  `entry->ref_count == refcount` already holds, so a steady-state replica
  stops re-fsyncing every live chunk's refcount record on every single
  poll cycle. Verified: full `test_cluster.py` (9/9) and
  `test_vw_gc`/`test_vw_store` unit suites still pass after the change.
- **Left as-is (advisory, no action)**: `hash_to_hex_dbg` in `vw_cluster.c`
  duplicates `vw_storage.c`'s private `hash_to_hex` byte-for-byte. Both
  are `static`, single-purpose, debug-only formatting helpers with no
  shared state — introducing a shared header for one 6-line function used
  by exactly one warning log line each isn't worth the coupling.
- Naming/API shape is consistent with the existing `addref`/`decref`
  pair (same lock discipline, same `VW_ERR_NOT_FOUND`-on-absent
  contract); doc comment on the header correctly warns callers off using
  it for primary-side incremental tracking.
- Regression test's docstring correctly documents *why* it tests two
  files instead of two versions of one file (no client-facing
  single-version-delete op exists) — meets this project's "explain the
  why for non-obvious choices" convention.

**ARCH.00, 2026-08-18.** Both required reviewers (`SEC.07`, `CQR.08`)
signed off with no blocking findings; the one CQR.08 advisory finding was
fixed inline and re-verified. Acceptance criteria met per the regression
test (`test_replica_reconciles_refcount_for_multiply_referenced_chunk`),
confirmed to fail without the fix and pass with it. Closing.
