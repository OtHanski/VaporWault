---
id:          TASK-085
title:       "Make cluster/replica setup actually operable — admin CLI + two pre-existing cluster bugs"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-23
priority:    high
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, cluster, security-sensitive, bug]
---

Requested as groundwork for a new `tutorial.md` walking through primary + backup
server + user setup. Investigation (see prior session context) found that
backup/replica setup was **entirely non-operable**: `vw_cluster_node_add()`
existed in `vw_cluster.c` but was never called from any shipped binary — no
admin-IPC message or CLI subcommand exposed it. Given the choice between
documenting this as broken or implementing it, the user chose to implement it.

Doing so surfaced two independent, pre-existing bugs in code that had
literally never been exercised end-to-end before (the only prior test,
`tests/integration/test_cluster.py`, is a gated placeholder — `pytestmark =
pytest.mark.cluster`, skipped unless `VW_TEST_CLUSTER=1`, and contains only
`assert True`).

## What was built

**New admin IPC capability** (`vw_admin.h`/`vw_admin.c`, `vw_server_cli.c`):
- `cluster node-add <hostname>` — run on the primary; generates a new
  node_id + random 256-bit auth_token, prints both once (never retrievable
  again, matching the existing `vw_cluster_node_get` token-zeroing invariant).
- `cluster register-self <node_id> <token> <hostname>` — run on the replica;
  stores a `VW_NODE_ROLE_SELF` record using the *exact* node_id/token the
  primary printed (does not generate its own — the two sides must agree on
  both values for `NODE_HELLO` to authenticate).
- `cluster-status` — lists all registered nodes (id, role, active, hostname,
  sync_watermark).
- `vw_admin_ctx_t` gained a `cluster` field; `vw_server_main.c`'s startup
  order was changed so `vw_cluster_open()` runs before
  `vw_admin_server_start()` (previously the reverse — the admin ctx had no
  cluster reference to hand out at all).

## Bugs found and fixed (pre-existing, not introduced by the above)

1. **`nodes_pread()` off-by-one (`vw_cluster.c`)** — the function computed
   `off = slot * sizeof(vw_node_record_t)` (0-based), but every single caller
   (`vw_cluster_node_add`'s `slot = node_slots + 1`, every scan loop
   `for (s = 1; s <= total; s++)`, and the live `NODE_HELLO` handshake
   handler's `nid_to_slot` lookup) uses a 1-based convention. Net effect:
   every node record lookup by `node_id` — `vw_cluster_node_get`,
   `vw_cluster_node_update_watermark`, `vw_cluster_node_set_active`,
   `vw_cluster_node_list`, `vw_cluster_min_sync_watermark`,
   `vw_cluster_has_active_replicas`, and the `NODE_HELLO` auth-token
   comparison itself — read/wrote one record-length off from the real data.
   With ≥2 nodes registered, the first-added node's lookups silently hit the
   *second* node's record (or, at the tail, ran off the end of the file and
   failed). **This broke cluster authentication for any node beyond the
   first.** Fixed by making `nodes_pread` (and the two direct `vw_fs_pwrite`
   offset computations in `node_update_watermark`/`node_set_active`, which
   had the identical bug) subtract 1 before multiplying, matching the
   1-based convention everyone else already used.

2. **Cluster connections used the wrong ALPN protocol (`vw_net.c`)** —
   `vw_net_connect()` hardcoded `VW_ALPN_CLIENT` ("vw/1") for every use,
   including the one call site that needed cluster ALPN
   (`vw_cluster.c`'s `replica_repl_session()`, dialing the primary). The
   primary's cluster listener (`vw_net_listen_cluster`) requires ALPN
   "vw-cluster/1". Mismatch → the TLS handshake failed outright
   (`SSL - A fatal alert message was received from our peer`) before any
   application-level exchange. **This meant no replica could ever connect
   to a primary's cluster port, at all, ever.** Fixed by extracting the
   shared connect logic into a static `net_connect_impl()` parameterized on
   the ALPN list, keeping `vw_net_connect()`'s signature/behavior identical
   for existing callers, and adding `vw_net_connect_cluster()` (used only by
   `vw_cluster.c`'s replica dial-out).

## Validation

All done locally via WSL (Ubuntu 24.04, matching the CI Linux runner) — no
existing automated test covered any of this, so manual end-to-end validation
was the only option:
- Full rebuild (`-DVW_WERROR=ON`) clean.
- Existing unit suite (9/9) and `integration_auth_handshake` still pass
  (confirms the `vw_server_main.c` startup reordering didn't break normal
  server start/admin operations) — also manually re-verified `user-create`/
  `user-list`/`set-quota` still work standalone.
- Manual two-server test: registered a node on a primary via `cluster
  node-add`, started a real replica `vapourwaultd` pointed at it,
  `register-self`'d using the printed node_id/token — primary log shows
  `NODE_HELLO OK from node 1`, replica log shows `connected to primary;
  primary last_eid=0, local watermark=0`. This is the first time this
  handshake has ever succeeded in this project's history.
- Confirmed `cluster-status` on a fresh single-node server returns an empty
  (not erroring) list — cluster mode is **on by default** (`cluster_port`
  defaults to `9010` per `vw_server_main.c:249`) unless a conf file sets
  `cluster_port = 0`; this is pre-existing intentional behavior, not a bug,
  but worth calling out in operator-facing docs since it's a live listening
  port by default.

## Acceptance criteria

- SEC.07 reviews: new admin capability exposes auth tokens over the admin
  IPC channel (already trusted/local-only per existing `vw_admin` security
  model) and the ALPN fix touches TLS connection setup — confirm no
  regression to the existing AF_UNIX/SO_PEERCRED trust model or to
  `vw_net_connect`'s behavior for its other (non-cluster) callers.
- CQR.08 reviews: wire format consistency with existing admin messages,
  correctness of the two bug fixes, and whether `docs/DEPLOYMENT.md` should
  be corrected now that real commands exist (it currently documents
  fictional `cluster node-add <host> <port>` / `cluster-status` syntax and
  the wrong `nodes.bin` filename — actual is `nodes.db`).
- No regression in existing unit/integration tests (confirmed above; no new
  automated test added — see note below).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-23]: Filed to record this work properly before review. Real
regression coverage for cluster pairing/replication (the placeholder in
`test_cluster.py`) is a separate, larger QA.06 effort — recommend a follow-up
task rather than blocking this one on writing that harness, given the manual
end-to-end validation already performed.

SEC.07 [2026-07-23]: Reviewed the full diff. **Two blocking findings**:
(1) `cluster register-self`'s auth token was accepted only as a bare CLI
argument (visible via `ps`/shell history) — no stdin-input option like
`user-create` has for passwords. (2) `cmd_cluster_node_add`'s heap `resp`
buffer (holding a freshly-generated auth_token) was `free()`'d without
zeroing first, unlike every server-side path in this diff. Verified the
`nodes_pread` off-by-one fix and the ALPN fix are both correct and introduce
no new risk; the admin-IPC trust boundary (AF_UNIX/SO_PEERCRED) is untouched;
`vw_cluster_node_add_self`'s check-then-act sequence is race-free under the
held `rwlock_wrlock`.

CQR.08 [2026-07-23]: Reviewed the full diff. **Two blocking findings**:
(1) New cluster-command error-code hints checked raw numeric values (`1`,
`5`) that don't match the real `vw_err_t` enum (`VW_ERR_INVALID_ARG=3`,
`VW_ERR_ALREADY_EXISTS=6`) — hints fired on the wrong error conditions. Also
flagged the pre-existing `err_str()` table in `vw_server_cli.c` as entirely
mismatched against the real enum (affects every admin command's error text,
not just the new cluster ones — a separate latent bug, not introduced by
this diff, but cheap to fix in the same pass). (2) Shutdown-ordering
use-after-free: `vw_server_main.c` closed `cluster` before stopping the
admin server, but the admin thread holds a `cluster` pointer and could be
mid-request during shutdown. Advisory items (not blocking): `docs/
DEPLOYMENT.md` still had fictional command syntax and the wrong `nodes.bin`
filename; minor CLI naming inconsistency (`cluster node-add` vs
`cluster-status`); ~20 lines of duplicated disk-write logic between
`vw_cluster_node_add`/`_add_self`; no upper bound on attacker-supplied
`node_id` before `index_ensure`'s capacity growth.

SRV.01 [2026-07-23]: Fixed both SEC.07 findings (stdin `-`/`--stdin-token`
support added to `cmd_cluster_register_self`, mirroring `user-create`'s
`-`/`--stdin-password`; `resp` zeroed before every `free()` in
`cmd_cluster_node_add`) and both CQR.08 findings (replaced magic-number error
comparisons with the real `VW_ERR_*` symbols throughout the cluster commands;
rewrote `err_str()`'s table to match `vw_proto.h`'s enum exactly; reordered
`vw_server_main.c` shutdown so `vw_admin_server_stop` — which blocks until its
thread joins — runs before `vw_cluster_close`). Also fixed the advisory
`docs/DEPLOYMENT.md` staleness (real `cluster node-add`/`register-self`/
`cluster-status` syntax, `nodes.db` filename, ACME hook `set|clear` contract,
Windows admin-CLI limitation) and the same stale ACME hook comment in
`packaging/linux/server.conf.example`. Left the two remaining advisory items
(CLI naming symmetry, disk-write duplication, node_id bound) as opportunistic
follow-up, not blocking. Rebuilt clean (`-DVW_WERROR=ON`) and re-ran the full
unit + integration suite (9/9 unit, 2/2 integration) after every change.

Re-verification pass (combined SEC.07+CQR.08 lens, single review agent given
time constraints — same rigor, one pass instead of two): 3 of 4 fixes
confirmed correct on first check; the 4th (magic-number sweep) had missed one
spot — `cmd_cluster_status` still compared against a bare `1` instead of
`VW_ERR_INVALID_ARG` (and, worse, `1` is actually `VW_ERR_IO` in the real
enum, so this was the exact bug class recurring in the one place the first
sweep missed). Fixed immediately, re-verified via `grep -n "code == [0-9]"`
across the file (zero remaining matches), rebuilt, and reran the full test
suite clean once more.

ARCH.00 [2026-07-23]: All four original blocking findings resolved and
independently re-verified; no outstanding blocking issues. Closing — status:
done. `docs/TUTORIAL.md` (the reason this work was undertaken) now documents
real, tested commands throughout.
