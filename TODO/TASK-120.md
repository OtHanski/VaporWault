---
id:          TASK-120
title:       Verify docs/TUTORIAL.md is current; write a non-technical end-user client setup tutorial
status:      todo
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-08-04
priority:    normal
depends_on:  [TASK-114, TASK-115, TASK-116, TASK-117, TASK-118, TASK-119]
blocks:      []
review_by:   [CQR.08]
tags:        [docs, gui]
---

Requested by the user as a final, deliberately-last task — to be picked up
only after TASK-114 through TASK-119 close, since several of them (the
Windows threading fix, the documentation-drift cleanup, the mbedTLS
resolution) could change details a tutorial would otherwise need to
describe accurately, and it makes sense to write user-facing docs against
settled ground rather than re-editing them mid-flight.

`docs/TUTORIAL.md` exists today, but it is **entirely server-admin-
oriented**: standing up a primary + backup server pair, TLS/ACME, user
creation via `vapourwault-server-cli`, and cluster pairing. Its own
"Platform note" says it's Linux-only for the admin CLI. Client setup gets
exactly one terse paragraph at the very end (§6 "What's next"), written for
someone already comfortable with a shell and `daemon.conf` — not remotely
aimed at a non-technical end user.

The user specifically wants a **separate** tutorial for the audience who
will actually use a deployed VaporWault day to day but never touch the
server: e.g. a family member using a family-hosted drive, who received
login credentials from whoever set up the server and just wants to install
the client and start using it. This is a distinct document with a distinct
voice from `docs/TUTORIAL.md`, not a section added to it.

## Acceptance criteria

- **Part 1 — audit the existing `docs/TUTORIAL.md`** for accuracy against
  current code/config: confirm the `server.conf` keys it shows still exist
  and mean what it says, the `vapourwault-server-cli` command syntax shown
  is current, the ACME/DNS-01 walkthrough matches current behavior, and the
  ports/systemd/packaging steps match `packaging/linux/install.sh`'s actual
  behavior today. Fix anything found stale. (This should be cheap if
  TASK-117/118/119 didn't change server-admin-facing behavior — this is a
  verification pass, not an expected rewrite.)
- **Part 2 — write a new tutorial** (suggest `docs/CLIENT_GETTING_STARTED.md`
  or similar — pick a name that reads as clearly distinct from
  `docs/TUTORIAL.md` at a glance) aimed at a non-technical end user:
  - Assumes someone else already set up the server and gave them: a server
    address, a username, and a password (and, if 2FA is enabled, how to get
    their OTP). Does not assume they know or care what `daemon.conf`,
    `vapourwault-cli`, or a systemd unit are.
  - Walks through installing the **client GUI** (not the CLI) — download/
    install, first-run login screen, adding a folder to sync, seeing sync
    status, and what a conflict-resolution `.conflict.*` file looks like
    and means in plain language if they ever see one.
  - Uses plain language throughout — no jargon like "daemon", "IPC",
    "chunk", "oplog" without a one-line lay explanation the first time each
    concept that matters to them comes up (e.g. "your files are checked
    against the server every few seconds" rather than "the sync interval").
  - Include basic troubleshooting for the failure modes a non-technical
    user would actually hit: wrong password, server unreachable/offline,
    "why hasn't my file shown up yet", what a paused/errored status icon
    means and what to do about it (point them to asking their admin rather
    than trying to self-diagnose IPC/network issues).
  - Should be reviewable by someone unfamiliar with the codebase for
    whether it actually reads as accessible — CQR.08's review should
    specifically judge it against that bar, not just technical accuracy.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-04]: Filed from a project-state review the user requested,
as an explicitly-last task gated on TASK-114 through TASK-119 closing
first, per the user's own sequencing instruction.
