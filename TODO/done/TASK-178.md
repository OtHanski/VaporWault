---
id:          TASK-178
title:       "Integration tests - replica hot-standby, GC-safety, automatic fallback"
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-08-14
priority:    high
depends_on:  [TASK-170, TASK-171, TASK-172, TASK-173, TASK-174, TASK-175, TASK-176, TASK-177]
blocks:      []
review_by:   [CQR.08]
tags:        [test]
---

Full-feature integration coverage for `TASK-169`'s automatic-fallback
design, once every implementation task above has landed.

## Tests to add

- **Replica hot-standby correctness**: real primary + real replica, real
  test-server users; create a user, upload files (plaintext and
  vault-encrypted), grant a share, create a public link, all on the
  primary; wait for replica sync; confirm every one of those is correctly
  readable/downloadable/usable directly against the replica (same
  username+password works, file content byte-identical, share/link
  metadata matches).
- **GC replica-safety regression**: pair a replica, pause/slow its pull
  loop deliberately, delete a file on the primary (dropping a chunk's
  refcount to zero) and run GC — confirm the chunk is NOT removed from
  disk while the replica is still behind, and IS removed once the
  replica catches up and acks past the relevant watermark. This is the
  regression test for `TASK-171`'s finding, per `CLAUDE.md`'s standing
  rule that every resolved SEC.07/correctness finding gets one.
- **Daemon automatic fallback**: real primary + real synced replica +
  real daemon account configured with both. Kill the primary process;
  confirm `ls`/download still work (against the replica); confirm an
  upload/mkdir attempt gets queued, not sent to the replica; restart the
  primary; confirm the daemon reconnects to it and the queued write
  actually lands there (not on the replica).
- **Gateway automatic fallback**: same scenario via
  `tests/integration/test_gateway.py` — kill the primary, confirm
  `/api/files/list`/download still succeed through the gateway's
  fallback, confirm a write endpoint returns a clean error (not a crash),
  confirm normal read-write resumes once the primary is back.
- Regression test for every SEC.07 finding raised during `TASK-172`'s
  review (record-fetch handler unreachable from the normal client
  listener — the security note in that task) and `TASK-173`/`176`'s
  review (fallback CA-cert never optional), per `CLAUDE.md`'s standing
  rule.

## Acceptance criteria

- All scenarios above pass against real built binaries — no mocking the
  server/daemon/gateway, matching this project's established convention.
- Full `ctest` (both `build-msvc-105` and `build-gw-e2e`) and the full
  `tests/integration/` suite green with these tests included.
- Sign-off notes added to `TASK-171`/`172`/`173`/`176` cross-referencing
  which test here covers it, before `ARCH.00` closes this milestone —
  same pattern `TASK-168` already established for the multi-account
  milestone.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**QA.06, 2026-08-17 — implementation complete, moving to review.**

- **Replica hot-standby correctness**:
  `tests/integration/test_cluster.py::test_replica_hot_standby_full_lifecycle`.
  Real primary + replica, real pairing. Creates a plain file, a
  vault-encrypted file (folder + `vault_create` + a chunk committed with
  `vault_id`/`wrapped_dek`), a user-to-user share grant, and a public
  link — all on the primary via `vw_client.py`'s real wire client — then
  opens fresh connections directly to the replica and confirms: the plain
  file downloads byte-identical; the vault's wrapped key/salt/params and
  its chunk content round-trip exactly; the grantee can stat/download the
  shared file with the right permission; the public link redeems and
  downloads correctly. All four checks retry against a bounded deadline
  (`_wait_until`, new shared helper) rather than a fixed sleep, since
  different subsystems (users/shares/vaults/chunks) sync at slightly
  different points in the replica's pass.
- **GC replica-safety regression**:
  `test_cluster.py::test_gc_does_not_delete_chunk_while_replica_lags`.
  Real primary (`gc_interval_secs=2`, `trash_retention_days=0` — new
  optional `ClusterNode`/`_write_cluster_conf` kwargs, backward-compatible)
  + real replica. Confirms the chunk survives multiple real GC cycles
  while the replica is stopped (frozen watermark), matching this task's
  own "pause/slow its pull loop" framing (a stopped process is
  functionally identical to a frozen pull loop from the primary's own
  watermark-gating perspective — there's no finer-grained "pause but keep
  the connection open" hook to reach for instead). **Found a real,
  separate, pre-existing bug while writing the "and IS removed once
  caught up" half** — filed as `TASK-180` (SRV.01): chunk refcount is
  double-counted on every upload+commit (`chunk_put_impl`'s initial
  ref_count=1 plus `handle_file_commit`'s own `addref`), so a
  single-reference chunk never actually reaches 0, on any deployment,
  clustered or not — independent of and downstream of the replica-lag
  gating this test set out to verify (which IS confirmed correct: the
  chunk correctly does NOT disappear while the replica lags). Full
  root-cause trace is in `TASK-180`. This test is marked
  `@pytest.mark.xfail(strict=True)` referencing `TASK-180` rather than
  weakened or deleted — it's a correct, ready regression test that will
  start failing (forcing the marker's removal) the exact moment
  `TASK-180` is fixed.
- **Daemon automatic fallback**:
  `test_cli_fallback.py::test_cli_account_add_fallback_and_real_failover`
  already existed from `TASK-174`; extended with the two things this
  task's own text called out that weren't yet covered: a sync-engine
  upload made while on the fallback shows as a queued local change
  (`local_mod`, not `synced`) and is confirmed absent from a direct
  connection to the replica; after the primary returns, the same write is
  confirmed to land specifically on the primary (not the replica).
- **Gateway automatic fallback**: this task's own text named
  `test_gateway.py`, but the real fallback coverage from `TASK-176` lives
  in `test_gateway_fallback.py` (a separate file WEB.09 created for
  exactly this) — extended that one instead of creating a duplicate.
  Added the "confirm normal read-write resumes once the primary is back"
  half (fresh login after restart shows `read_only: false` again and a
  write actually succeeds), which wasn't in the original test.
- **SEC.07 regression tests**:
  `test_cluster.py::test_cluster_only_messages_rejected_on_normal_client_listener`
  (`TASK-172`'s handler-reachability finding — sends the raw
  `CLUSTER_FILE_SYNC_LIST` opcode over a real authenticated `vw/1`
  connection, confirms `VW_ERR_PROTO_INVALID`, confirms the connection
  survives and stays usable);
  `test_cli_fallback.py::test_cli_fallback_rejects_mismatched_ca_cert`
  and `test_gateway_fallback.py::test_gateway_refuses_to_start_without_fallback_ca_cert`
  (`TASK-173`/`176`'s "fallback CA-cert never optional" findings — the
  daemon must fail closed against a real cert mismatch, the gateway must
  refuse to start at all without one).
- Sign-off notes cross-referencing the above added to `TASK-171`, `172`,
  `173`, `176`.
- **Verification**: `build-msvc-105` (MSVC) rebuilt clean, `ctest` 18/18
  (one transient failure during verification — `unit_vw_ipc`'s hardcoded
  port 57123 collided with an unrelated ephemeral Windows Defender
  connection on this host at that moment; confirmed unrelated to any
  change in this task by re-running moments later, clean). `build-gw-e2e`
  (WSL/GCC) rebuilt clean. Full non-cluster `tests/integration/` suite:
  95/95. Cluster suite: 8/8 in `test_cluster.py` (7 passed, 1 correctly
  `xfailed`), plus the extended `test_cli_fallback.py`/
  `test_gateway_fallback.py` (5/5) — 13 cluster-marked tests total,
  all green or intentionally `xfail`.

**CQR.08 self-review, 2026-08-17.** New/modified test code reviewed for
the same discipline the rest of this suite holds itself to: every
`VwClient` opened is closed via `try/finally`; every new `ClusterNode`
pair is torn down in a `finally` block; no test invents a second way to
do something a helper already does (`_wait_until` added once, reused by
all four hot-standby-lifecycle checks rather than four bespoke polling
loops). The `xfail` marker's `reason` string is detailed enough that
whoever fixes `TASK-180` doesn't need to re-read this task to know what
to remove and why. No blocking findings.

**ARCH.00, 2026-08-17 — closing.** All four test categories this
milestone asked for exist and are correct; the one real bug they
surfaced (`TASK-180`) is properly filed rather than papered over, and the
test that found it is preserved (not deleted or weakened) so it enforces
the fix once it lands. Moving to done.

**QA.06, 2026-08-17 — follow-up.** `TASK-180` is fixed; removed the
`xfail(strict=True)` marker from
`test_gc_does_not_delete_chunk_while_replica_lags` now that it genuinely
passes (verified: it was `strict=True` specifically so an unexpected pass
would fail loudly rather than silently — confirmed that mechanism wasn't
needed since the fix was landed deliberately, not accidentally). Full
suite re-run green with the marker gone: 95/95 non-cluster, 13/13
cluster, 18/18 `ctest` (MSVC).
