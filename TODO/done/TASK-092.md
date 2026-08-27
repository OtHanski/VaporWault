---
id:          TASK-092
title:       "Granular admin roles (beyond boolean is_admin)"
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-24
priority:    low
depends_on:  []
blocks:      []
review_by:   [SEC.07, CQR.08]
tags:        [server, admin, security-sensitive]
---

Admin privilege is currently a single boolean (`vw_user_record_t.is_admin`)
— an account either can do everything an admin can (create/list users, set
quotas, view the oplog, reload certs, and now — per `TASK-085` — manage
cluster nodes) or nothing. There's no way to delegate a narrower role (e.g.
a helpdesk admin who can reset passwords/quotas but shouldn't be able to
register cluster nodes or read the audit oplog). This is a common ask once
a deployment has more than one administrator.

## Acceptance criteria

- Design a role model (ARCH.00 input welcome given it affects the admin IPC
  contract) — e.g. a small fixed set of capability bits (user management,
  quota management, oplog/audit read, cluster management, cert reload)
  rather than free-form RBAC, to keep this proportionate to the product's
  actual admin-team size.
- `vw_admin.c`'s per-message handlers check the connecting admin's specific
  capability, not just a blanket `is_admin` flag — each admin message type
  (`USER_CREATE`, `SET_QUOTA`, `OPLOG_TAIL`, `NODE_ADD`, `RELOAD_CERT`, etc.)
  maps to a capability.
- `vapourwault-server-cli` gains a way to grant/revoke specific capabilities
  per admin user.
- SEC.07 reviews the capability-check placement carefully — a missed check
  on any one admin message type reintroduces the all-or-nothing problem for
  that specific operation.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-24]: Filed after a feature-gap discussion; assigned to
SRV.01 (user/permission storage is their domain) with SEC.07+CQR.08 review
required (permission-model change, tagged `security-sensitive` per routing
rule 1). Low priority — most deployments likely have very few admins, so
this matters less than the other gaps filed alongside it; revisit priority
if a specific deployment need for delegated admin roles comes up.

SRV.01 [2026-07-29]: Implemented as a small fixed set of capability bits per
the acceptance criteria's own recommendation, rather than free-form RBAC.

**Role model**: `vw_admin_cap_t` (`vw_proto.h`) — five bits:
`VW_CAP_USER_MGMT`, `VW_CAP_QUOTA_MGMT`, `VW_CAP_AUDIT_READ`,
`VW_CAP_CLUSTER_MGMT`, `VW_CAP_CERT_RELOAD`. `vw_user_record_t` gained an
`admin_caps` (uint32_t) field, reusing 4 of the former `_pad[5]` reserved
bytes (`_pad1` keeps 1 byte for future use) — same "reuse reserved bytes"
pattern as `TASK-090`'s `deleted_at`, confirmed layout-compatible (offset
252 is still 4-byte aligned after the split, verified no compiler padding
introduced, `_Static_assert(sizeof(vw_user_record_t) == 256)` still holds
on both MSVC and GCC).

**Backward-compatibility convention (the key design decision here)**:
`admin_caps == 0` on an `is_admin == 1` record is treated as
`VW_CAP_ALL` (full admin), not "no capabilities" — every admin account
that existed before this feature shipped reads back `admin_caps == 0`
(since those bytes were always-zero padding), so this is what preserves
their exact existing access without a migration step (this codebase has no
migration tooling for its flat-file stores). Consequence: there is no way
to express "admin with zero capabilities" — that's a deliberate, accepted
gap (a meaningless state; unset `is_admin` instead). New helper
`vw_admin_has_cap(rec, cap)` (`vw_store.h`) centralizes this convention so
every call site gets it right rather than each re-implementing the
"0 means full" special case.

**Scope decision (important, flagging explicitly for SEC.07/CQR.08
review)**: this only capability-gates the six *network-facing wire
protocol* admin messages in `vw_file_handlers.c`'s 0x06xx range
(`QUOTA_ADJUST`→`VW_CAP_QUOTA_MGMT`, `USER_LIST`→`VW_CAP_USER_MGMT`,
`USER_SUSPEND`→`VW_CAP_USER_MGMT`, `AUDIT_QUERY`→`VW_CAP_AUDIT_READ`,
`CLUSTER_STATUS`→`VW_CAP_CLUSTER_MGMT`, `INVITE_CREATE`→`VW_CAP_USER_MGMT`)
— these already carry a specific authenticated admin *account's* identity
via `session.user_id`, which is exactly where "delegate a narrower role to
a specific human, e.g. a helpdesk admin logging in remotely" applies.

The **local** `admin.sock` channel (`vw_admin.c`, used by
`vapourwault-server-cli`) is deliberately **not** capability-gated per
message type, and I don't believe it should be: that channel's trust model
is already OS-level (`SO_PEERCRED`, same UID as the server operator) —
whoever can reach it already has an access level no account-level
capability bitmask could meaningfully restrict (they could just as well
edit `users.dat` directly with that same OS access). Bolting a weaker,
account-based check onto an already-fully-trusted local channel doesn't
add real security and isn't what "helpdesk admin who shouldn't register
cluster nodes" was describing (a true helpdesk person wouldn't have shell
access to the server box). If the product later wants remote-delegatable
`NODE_ADD`/`RELOAD_CERT`, that needs those operations exposed over the
*wire* protocol with real admin-account authentication — a bigger, separate
change — not a check bolted onto the local socket. Flagging this
explicitly since the original filing's acceptance criteria examples
(`NODE_ADD`, `RELOAD_CERT`) are both local-socket-only operations.

**What `vapourwault-server-cli` (local, fully-trusted) *does* gain**: a new
`VW_ADMIN_SET_CAPS_REQ/RESP` (0x9017/0x9018) message and `set-admin-caps
<username> <all|cap1,cap2,...>` command — this is how the trusted operator
delegates a narrower role to a different, less-trusted admin *account* that
will authenticate remotely. Also extended the local `USER_LIST_RESP` wire
entry (append-only, 92→96 bytes) to show each admin's `ADMIN_CAPS` column
in `user-list` output, so an operator can confirm delegation actually took
effect — this local-only protocol isn't part of `docs/PROTOCOL.md` (that
document only covers the `vw/1`/`vw-cluster/1` ALPN channels), so no
protocol-doc version bump was needed. The GUI's own `USER_LIST_RESP`
parsing (`vw_view_users.cpp`) uses the *wire* protocol's separate
`ULIST_ENTRY_WIRE=220` format (confirmed via source read), not this local
one, so it is unaffected.

**Error code choice**: an authenticated admin who lacks the specific
capability for an operation now gets `VW_ERR_PERMISSION`, distinct from
`VW_ERR_AUTH_REQUIRED` (still returned for "not an admin at all") — lets a
client distinguish "you're not an admin" from "you're an admin but not
authorized for this specific action."

**Validation**: full project (49 targets) builds clean under both MSVC
`/W4 /WX` (Windows) and GCC (WSL Ubuntu 24.04, matching this project's
established dual-platform validation practice) with zero warnings from
this change. Full existing unit suite passes with no regressions
(`test_vw_store`, `test_vw_auth`, and others). Added 5 new
`VW_TEST_CASE`s to `tests/unit/test_vw_store.c` directly exercising
`vw_admin_has_cap()`: non-admin always denied regardless of `admin_caps`,
`admin_caps==0` grants everything, a restricted subset denies everything
outside it, explicit `VW_CAP_ALL` grants everything, and a simulated
legacy (pre-feature) on-disk record is still treated as fully capable.
One MSVC-only finding caught during this: `/W4` flagged
`VW_ASSERT_EQ(256, (int)sizeof(vw_user_record_t))` as C4127 ("conditional
expression is constant", since `sizeof()` is compile-time-constant) —
removed as genuinely redundant (already enforced by the header's own
`_Static_assert`), not worked around.

Live end-to-end validation against a real server instance (WSL, real TLS
cert, real admin socket — not mocked): created an admin account via
`user-create --admin` (showed `ADMIN_CAPS=full` by default, confirming the
0-as-legacy-default convention), restricted it via `set-admin-caps
helpdesk quota_mgmt,audit_read` (confirmed via `user-list`), reset to
`all` explicitly (round-trips back to displaying `full`), confirmed an
unknown capability name is rejected client-side with a clear message,
confirmed an unknown username is rejected server-side (`not_found`), and
confirmed setting capabilities on a non-admin target is accepted (the bits
are stored) but displays `-` and has no effect per `vw_admin_has_cap`'s
`is_admin` gate.

Did not attempt a live wire-protocol-level test (would require standing up
the client daemon + a real admin login session over TLS) given the six
wire handlers use the exact same "fetch user record → check field →
early-return" idiom already proven correct elsewhere in this file, now
with one additional, unit-tested `vw_admin_has_cap()` call — the marginal
risk left to test there is very low relative to the setup cost. Flagging
this gap explicitly for SEC.07 rather than silently claiming full coverage.

SEC.07 [2026-07-29]: Adversarial review complete. No blocking findings —
capability-check placement is correct in all six handlers (verified
against every admin message in `docs/PROTOCOL.md` §7.6; `USER_CREATE`/
`USER_MODIFY`/`DRIVE_CONFIG` are simply unimplemented, nothing to gate),
the "admin_caps==0 means full" convention has no bypasses anywhere in the
tree, the local-socket scope decision is correctly backed by a real
`SO_PEERCRED` check (verified in `vw_admin.c`), `handle_set_admin_caps` is
correctly bounds-checked, and `vw_store_user_create`'s two call sites both
zero the record before populating it (no uninitialized `admin_caps`).
Two advisory items, both **pre-existing, not introduced by this diff**:
(1) five of the six handlers never `secure_zero` the fetched
`vw_user_record_t` (which carries `password_hash`/`password_salt`) before
it goes out of scope — only `handle_cluster_status` does; (2)
`handle_cluster_status`'s "not admin at all" branch already returned
`VW_ERR_PERMISSION` before this task (not `VW_ERR_AUTH_REQUIRED` like the
other five), so that one endpoint can't distinguish "not admin" from
"admin, wrong capability" — inconsistent with the new convention but not
this task's regression. Recommending a small follow-up hygiene task for
both; not blocking this one.

CQR.08 [2026-07-29]: Review complete. One blocking finding, now fixed:

- **`docs/PROTOCOL.md` §7.6 was stale** — still said all `0x06xx` messages
  need only blanket `is_admin`, with no mention that six of them now also
  require a specific capability and can return `VW_ERR_PERMISSION` to an
  authenticated admin. Fixed: added a capability-requirement table to §7.6
  covering all six messages (including `CLUSTER_STATUS`, cross-referenced
  to §7.7 where its opcode is actually defined), explicitly scoped to the
  network wire protocol only (not the local `admin.sock` channel, which
  isn't part of this document). Protocol version bumped 8→9 with a
  changelog entry — no payload shapes changed, this documents new
  server-side authorization behavior on existing messages.

Two advisory items:
- **Duplicate `{bit, name}` capability table** in `vw_server_cli.c`
  (`caps_str` and `parse_caps` each had their own copy) — fixed by hoisting
  to one file-scope `VW_CAP_NAMES[]` array both functions now share.
- **`VW_CAP_*` vs. this codebase's `VW_ADMIN_CAP_*`-shaped-enum naming
  precedent** (e.g. `vw_perm_t`/`VW_PERM_*`) — left as-is; CQR.08 itself
  flagged this as "no collision risk, reads fine in context," and renaming
  now would touch every call site across `vw_proto.h`, `vw_store.h`,
  `vw_file_handlers.c` (×6), `vw_admin.c`, and `vw_server_cli.c` (×2) for a
  purely cosmetic gain. Not worth the churn.
- Six-site duplication of the two-step admin/capability check in
  `vw_file_handlers.c`: CQR.08 explicitly assessed this as acceptable given
  the six sites already differ in cleanup style predating this change, and
  a shared helper would cost more indirection than it saves. No action.

Re-verified after the fixes: full project rebuilds clean on both MSVC
`/W4 /WX` and GCC (WSL) with zero warnings; existing test suite still
passes with no regressions.

ARCH.00 [2026-07-29]: Both SEC.07 and CQR.08 sign-off requirements
satisfied — the one blocking finding is fixed and re-verified, and the two
pre-existing advisory items (password-field zeroing gap, one inconsistent
error code in `handle_cluster_status`) are accepted as follow-up hygiene
work rather than blockers, since neither was introduced or made worse by
this task. Filing a low-priority follow-up task for those two items.
Moving status to `done`.
