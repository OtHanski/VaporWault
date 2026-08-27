---
id:          TASK-205
title:       "ARCH.00 design - opt-in email alerts for admins and users"
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-08-25
priority:    normal
depends_on:  []
blocks:      [TASK-206, TASK-207, TASK-208, TASK-209, TASK-210, TASK-211, TASK-212, TASK-213]
review_by:   [CQR.08]
tags:        [design]
---

Grew out of a discussion of `TASK-169`'s client-side fallback: that
feature has no alerting layer, so a primary outage (or a lagging
replica, or a failing ACME renewal, etc.) can go unnoticed by an admin,
and a user has no way to learn "someone shared something with you" or
"you're near your quota" except by opening a client and looking. The
outbound SMTP relay (`vw_smtp.c`) already exists (2FA OTP, recovery,
invites) — this reuses it rather than building new send infrastructure.

## Decisions

1. **Two separate preference surfaces, not one.** Server-admin alerts and
   end-user alerts are configured through entirely different channels,
   because "admin" in this codebase (`vw_user_record_t.is_admin`) is a
   capability flag on an ordinary user record, not a separate operator
   identity with its own config surface — and the two audiences want
   different things (operational health vs. personal account activity):
   - **User categories**: per-user, opt-in, settable live by the user
     themselves through their own authenticated session — same shape as
     the existing "2FA is optional per-user" precedent
     (`ARCHITECTURE.md`). Requires a small, additive wire-protocol change
     (`TASK-206`).
   - **Admin categories**: server-operator configuration in
     `vapourwaultd.conf` (alert recipient address + one boolean per
     category), read at startup exactly like the existing SMTP relay
     settings. No protocol change, no live admin-socket toggle in v1 —
     these are operational knobs an operator sets once when provisioning
     the server, not per-session user state. (A live `vapourwault-server-
     cli`/server-GUI toggle is a reasonable future addition; explicitly
     deferred here, not forgotten — see Notes.)
2. **Default OFF, everywhere.** No email is ever sent unless the
   recipient (user or admin) explicitly opted in to that specific
   category. This is worth stating as a hard requirement, not just a
   default, given the standing risk of silently spamming a configured
   SMTP relay or leaking activity to an address nobody asked to notify.
3. **v1 category list** (mechanism is designed to make adding a category
   later cheap — same "extensible provider interface" spirit as the 2FA
   design — so this list is a deliberately bounded starting set, not a
   ceiling):
   - User: `share_received` (a grant or link naming you was created —
     redemption of an anonymous public link doesn't count, there's no
     "you" to notify), `quota_warning` (your usage crossed a threshold,
     e.g. 90%, of your quota), `new_login` (a **fresh** `AUTH_REQUEST`
     succeeded on your account — deliberately excludes `SESSION_RESUME`,
     which is the daemon's normal reconnect path and would otherwise
     spam this on every flaky network blip), `account_security_change`
     (password changed, or 2FA enabled/disabled).
   - Admin: `replica_lag` (a paired replica hasn't acknowledged the
     primary's oplog watermark within a configurable threshold —
     see the caveat below), `acme_renewal_failure`, `disk_capacity`
     (server-wide storage nearing capacity), `lockout_spike` (an unusual
     rate of auth lockouts in a rolling window — possible brute force),
     `crash_recovery` (the oplog crash-recovery replay ran at this
     startup, meaning the server didn't shut down cleanly last time).
4. **Debounce is part of the design, not an afterthought.** Threshold-
   style categories (`quota_warning`, `replica_lag`, `disk_capacity`,
   `lockout_spike`) fire once on crossing into the bad state and re-arm
   only after the condition clears — no repeat reminders while it stays
   bad, so a stuck problem doesn't become a mail flood. One-shot event
   categories (`share_received`, `new_login`, `account_security_change`,
   `crash_recovery`) need no debounce; each is tied to a single discrete
   action.
5. **Caveat, recorded honestly rather than glossed over**: `replica_lag`
   is the closest server-observable proxy for "clients may be running on
   fallback," but it is not the same signal — the primary has no direct
   visibility into a client connecting straight to a replica
   (`TASK-169`'s fallback path never touches the primary). A true
   "N accounts are currently on fallback" admin alert would need the
   client or gateway to report that state back to the primary somehow,
   which doesn't exist today and is out of scope here. `replica_lag`
   still closes most of the practical gap (a replica that's actually
   behind is the scenario worth knowing about either way) but should not
   be presented to the admin as "clients are on fallback."

## Decisions recorded (`ARCHITECTURE.md`, Decision Log table)

- New row: `Opt-in email alerts (admin + user)` — see `ARCHITECTURE.md`.

## Task breakdown

| Task | Assignee | Depends on | review_by | tags |
|------|----------|------------|-----------|------|
| `TASK-206` — Protocol: `NOTIFY_PREFS_GET`/`_SET` wire spec (user categories only) | PRT.04 | 205 | CQR.08 | protocol |
| `TASK-207` — Server: user-category preference storage + triggers (`share_received`, `quota_warning`, `new_login`, `account_security_change`) | SRV.01 | 206 | SEC.07, CQR.08 | security-sensitive, server |
| `TASK-208` — Server: admin-category config + triggers (`replica_lag`, `acme_renewal_failure`, `disk_capacity`, `lockout_spike`, `crash_recovery`) | SRV.01 | 207 | SEC.07, CQR.08 | security-sensitive, server |
| `TASK-209` — Client: daemon IPC + `vapourwault-cli notify` for user categories | CLI.02 | 207 | CQR.08 | client |
| `TASK-210` — GUI: notification-preferences panel | GUI.03 | 209 | CQR.08 | gui |
| `TASK-211` — Web gateway/frontend: notification-preferences UI | WEB.09 | 207 | SEC.07, CQR.08 | security-sensitive, gateway |
| `TASK-212` — Docs: admin config keys + user-facing toggle documentation | BLD.05 | 207-211 | CQR.08 | docs |
| `TASK-213` — Integration tests: every trigger, debounce behavior, default-off regression | QA.06 | 206-212 | CQR.08 | test |

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-25]: Design complete, `ARCHITECTURE.md` updated, task
breakdown created directly in `TODO/todo/`. Deferred, not forgotten: a
live admin-socket/server-GUI toggle for admin categories (instead of
editing `vapourwaultd.conf` and restarting) would be a reasonable
follow-up once this v1 ships — file it as a new task against SRV.01/
GUI.03 if requested rather than scoping it in here.

ARCH.00 [2026-08-27]: **Milestone closed.** `TASK-206`–`213` all `done`,
each with its required reviewer sign-off (`SEC.07`+`CQR.08` on the three
`security-sensitive`-tagged tasks — `207`, `208`, `211`; `CQR.08` alone
on the rest). `ARCHITECTURE.md`'s Implementation Phases table (Phase 20, added by
`TASK-204`'s audit) updated from "design complete, implementation in
progress" to "complete" as part of this same closure — per `TASK-204`'s
own finding that leaving a shipped phase's status stale is this table's
real recurring failure mode, closing it in the same breath as the
milestone itself rather than deferring the edit.

Two real gaps surfaced during implementation, filed rather than silently
absorbed into this milestone's own scope: `TASK-219` (no self-service
2FA enable/disable exists, so `account_security_change` only fires for
password changes today) and `TASK-222` (no wire path sets a user's email
at all, discovered by `TASK-213` — `priority: high`, since it also
silently breaks the already-shipped `TASK-046` password-recovery
feature, not just this one). Both are follow-ups to plan, not blockers
this milestone was waiting on — the design's own four user categories
and five admin categories all ship and work exactly as specified for
any account that does have an email on file.
