---
id:          TASK-120
title:       Verify docs/TUTORIAL.md is current; write a non-technical end-user client setup tutorial
status:      done
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

GUI.03 [2026-08-05]: Resolved.

**Part 1 — `docs/TUTORIAL.md` audit.** Checked every concrete technical
claim against current source, not just skimmed for obvious staleness:
`server.conf` keys against `packaging/linux/server.conf.example` (exact
match, all 7 keys shown), `vapourwault-server-cli` command syntax against
`src/server/vw_server_cli.c` (`user-create`, `set-quota`, `user-list`,
`cluster node-add`/`register-self`/`status` — all argument orders and the
`-`/stdin-password/stdin-token handling match exactly), the ACME DNS-01
hook contract (`<script> set <domain> <token>` / `<script> clear <domain>`)
against `src/server/vw_ddns.c`'s actual `run_hook()` (exact match), the
admin-socket-is-POSIX-only claim against `src/server/vw_admin.c` (confirmed
— Windows build compiles to a no-op stub, `vw_admin_server_start` never
actually listens), and `packaging/linux/install.sh`'s actual behavior
against the tutorial's description of it (exact match: user/dirs created,
config only installed if absent, no firewall changes). `docs/DEPLOYMENT.md`
section numbers the tutorial points to (§1, §7, §8, §10) still exist and
match.

Found one real drift: `user-list`'s output gained an `ADMIN_CAPS` column
(`TASK-092`) that the tutorial's sample output didn't show. Fixed, with a
one-line explanation of what `full`/`-`/a capability list means. Everything
else checked out — confirms this task's own prediction that TASK-117/118/119
didn't touch server-admin-facing behavior.

**Part 2 — `docs/CLIENT_GETTING_STARTED.md` (new).** Before writing,
traced the actual current end-user flow end to end rather than assuming a
polished onboarding exists: `src/gui/client/ClientApp.cpp`'s view-switching
logic, `vw_view_login.cpp` (password + optional 2FA — confirmed the
password field is zeroed after *every* login attempt including a
2FA-required one, so the UI genuinely shows an empty password box the
second time around — documented that explicitly so it doesn't read as a
bug to a first-time user), `vw_view_settings.cpp` (add/remove sync folder
UI), `vw_view_browser.cpp` (sync-state colour/label mapping,
Pause/Resume), `vw_view_queue.cpp` (pending uploads/downloads/errors), and
`vw_sync.c`'s `make_conflict_path` (exact `.conflict.<UTC timestamp>`
naming) plus its caller (confirms conflicts are resolved automatically —
local kept, server version saved alongside — not something the user needs
to act on).

**Real gap found and handled honestly rather than glossed over:** there is
no first-run GUI wizard for entering server address/username, and no
packaged installer (no NSIS/MSI/etc. — `packaging/windows/` and
`packaging/linux/` are both script-based). A user's `daemon.conf` must be
manually edited once (`notepad`/text editor) and the daemon started via one
`Start-ScheduledTask`/`systemctl --user enable --now` command before the
GUI is useful at all — confirmed via both installer scripts'
(`client_install.sh`, `Install-VaporWaultClient.ps1`) actual "next steps"
output. Structured the new doc as **Part 1 (one-time setup, clearly marked
skippable if the admin already did it)** and **Part 2 (everyday use)**
rather than pretending a wizard exists — the task's own framing ("assumes
someone else already set up... and gave them a server address, username,
password") stretches naturally to cover this, and Part 2 (the genuinely
non-technical bulk of the document) is accurate to what's actually a
simple, jargon-light experience once the daemon is running.

Verified every command/path/binary name in the new doc against source:
`daemon.conf` locations (`%APPDATA%\VaporWault\`,
`~/.local/share/vapourwault/`) match both installer scripts exactly;
`vapourwault-gui`/`vapourwault-gui.exe` binary name matches
`src/gui/client/CMakeLists.txt`; the Windows release `.zip` bundles
`SDL2.dll` alongside the `.exe`s (checked `.github/workflows/release.yml`'s
staging step) so no separate SDL2 download is needed there; login error
codes 300/301/304 (`VW_ERR_AUTH_BAD_CREDS`/`_2FA_REQUIRED`/`_LOCKED`) match
`src/core/vw_proto.h` exactly.

**Found and filed separately (not fixed here, out of scope for a docs
task):** `TASK-126` — the GUI's "Conflict" popup modal is dead code
(nothing ever calls `OpenPopup` for it) and, had it ever fired, would have
told users to run `vapourwault-cli resolve <path>`, a command that doesn't
exist. Didn't propagate that wrong command into the new tutorial — described
the real (automatic) conflict behavior instead.

CQR.08 [2026-08-05]: Reviewed against the accessibility bar this task
specifically asked for, not just technical accuracy (which checks out —
spot-verified several claims independently: `daemon.conf` paths, the
`ADMIN_CAPS` fix, the conflict-file naming pattern, and the login-error
code mappings all match source).

On accessibility: every term flagged as jargon in the acceptance criteria
("daemon", "IPC", "chunk", "oplog") either doesn't appear in
`CLIENT_GETTING_STARTED.md` at all, or is introduced with a plain-language
gloss on first use ("daemon" → "a small helper program that runs quietly
in the background"). Sentences are short, instructions are numbered where
sequence matters, and the two "offline" states (daemon-unreachable vs.
server-unreachable) — which are genuinely easy to conflate — get distinct,
separately-labeled troubleshooting entries instead of one generic "can't
connect" bucket. The troubleshooting section consistently defers
network/account-lockout issues to "ask your admin" rather than inventing
self-diagnosis steps the target reader couldn't safely follow, matching
the acceptance criteria's explicit instruction.

One judgment call worth recording: Part 1 (one-time setup) is unavoidably
more technical than the rest — editing a config file and running one
shell/PowerShell command — because that reflects the real product today
(no onboarding wizard exists). Rather than smoothing this over, the doc
says so plainly and front-loads an escape hatch ("skip to Part 2" / "ask
your admin to do this once"). That's the right call for a doc's honesty
over a doc's polish — a wizard would be a product feature to build, not
something a tutorial should pretend into existence. No blocking findings.
Sign off.

ARCH.00 [2026-08-05]: All review_by sign-offs recorded, no unresolved
blocking findings. Marking `done`.
