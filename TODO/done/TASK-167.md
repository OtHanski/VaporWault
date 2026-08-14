---
id:          TASK-167
title:       Packaging/deployment docs: gateway state-dir permissions, multi-account daemon layout
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-13
priority:    normal
depends_on:  [TASK-161, TASK-165]
blocks:      [TASK-168]
review_by:   [CQR.08]
tags:        [build, docs]
---

Depends on `TASK-161`'s daemon `accounts/<id>/` state layout and
`TASK-165`'s new gateway `--state-dir`. `docs/DEPLOYMENT.md` and the
packaging scripts under `packaging/` currently document/assume a single
daemon `state_dir` per install and no gateway state directory at all.

## Work

- `docs/DEPLOYMENT.md`: document the new `accounts/<account_id>/` subtree
  under the daemon's `state_dir` (what's in it, that it's created/removed
  automatically by `account add`/`account remove`, not something an admin
  edits by hand).
- Document the new gateway `--state-dir` flag: where it should live per
  platform (matching this doc's existing per-platform state-dir
  conventions for the daemon/server), and its required file permissions
  (owned by the gateway service user, `0600`-equivalent) — cross-reference
  `TASK-165`'s security note rather than re-deriving it.
- `packaging/linux/scripts/` (systemd unit files, postinst/prerm/postrm
  scriptlets) and the Windows service/scheduled-task registration
  (`Install-VaporWault*.ps1` / WiX fragments, per `TASK-145`'s existing
  installer work): ensure the gateway's new state directory is created
  with correct ownership/permissions at install time, the same way the
  daemon's existing state directory already is — reuse that existing logic
  rather than writing a second, parallel permission-setup path.

## Acceptance criteria

- A fresh install (per platform) ends up with the gateway's state
  directory present, owned by the correct service account, and permission
  bits matching `TASK-165`'s requirement — verified, not just documented.
- `docs/DEPLOYMENT.md` accurately describes the multi-account daemon layout
  well enough that an admin could recognize/clean up an
  `accounts/<id>/` subtree if needed without guessing at its structure.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

**BLD.05 [2026-08-13]:** Implemented, with one scope correction found while
doing it: the task's own "Work" section asked for Windows service/scheduled-
task registration for the gateway's state directory, but the gateway has
**no Windows deployment path at all** today (`docs/DEPLOYMENT.md`'s Section
11 — the only place the gateway is documented — is Linux/systemd-only
throughout; no WiX fragment, no `Install-VaporWault*.ps1` reference,
anywhere). Noted explicitly in the doc's new §11.7 rather than fabricating
Windows gateway packaging that doesn't correspond to anything real. The
client daemon's Windows side needed no changes: `Install-VaporWaultClient.ps1`
already sets a restrictive ACL on its whole `StateDir` (predates this task),
and `accounts/<id>/` subdirs created inside it at runtime inherit that
protection — nothing TASK-161-specific to add there.

- `packaging/linux/install.sh`: extended with a `GATEWAY_BIN`/
  `GATEWAY_DATA_DIR` conditional block, mirroring the exact pattern already
  used for the optional `GUI_BIN` (same "only install what this build
  actually produced" convention) — not a second, parallel permission-setup
  path, reusing this same script and its existing `SERVICE_USER` variable.
  Creates `/var/lib/vapourwault-gateway` at mode `0700` (narrower than the
  server's own `0750` — no legitimate reason for group-read access to a
  bearer-credential store) only when `vapourwault-web-gateway` was actually
  built, and installs `vapourwault-web-gateway.service` alongside it.
- `packaging/linux/vapourwault-web-gateway.service`: added `--state-dir
  /var/lib/vapourwault-gateway` to `ExecStart` and a matching
  `ReadWritePaths=` entry — required, not optional cleanup: `ProtectSystem=
  strict` makes the whole filesystem read-only except explicitly listed
  paths, so without this the gateway would still start but every attempt to
  persist a remembered login would fail with `EROFS`. Also fixed the unit's
  own comment, which pre-`TASK-165` correctly said the gateway "has no
  persistent state of its own" — no longer true.
- `docs/DEPLOYMENT.md`: new §11.7 documenting both the daemon's
  `accounts/<account_id>/` subtree (what's in it, that `account add`/
  `account remove` manage it automatically, what's safe to clean up by
  hand and when) and the gateway's `remember.db` (what it holds, that the
  gateway self-hardens the *file's* permissions on creation, and that the
  install script now handles the *directory's* permissions) — cross-
  referencing `TASK-165`'s security rationale rather than re-deriving it,
  per the task's own instruction. Updated §11.3's flag table (`--state-dir`
  row) and rewrote §11.5's now-stale "no install-script integration for the
  gateway" paragraph to describe the real, now-existing path. Added a
  checklist line to §10 (Security hardening checklist) for the new state
  directory's permissions.
- **Verified, not just documented** (this task's own acceptance criterion):
  ran the real `install.sh` (built Linux binaries from `build-gw-e2e`)
  inside a disposable Ubuntu 24.04 Docker container. Confirmed
  `/var/lib/vapourwault-gateway` is created with `owner=vapourwault
  group=vapourwault mode=700` on a fresh install; confirmed the installed
  unit file's `ExecStart`/`ReadWritePaths` match what's documented;
  confirmed re-running the script is a no-op on the already-correct
  directory (idempotent, matching the script's own header comment);
  confirmed a server-only build (no gateway binary present) creates
  neither the gateway state directory nor its unit file, i.e. no clutter
  for installs that don't want the feature. (The script's own final
  `systemctl daemon-reload`/`enable` steps fail inside the container, as
  expected — no systemd running as PID 1 there — but that happens *after*
  every directory/file-creation step already under test, and is not
  something this task needed to work around: a real target host always has
  systemd running, which is the actual, intended runtime for this script.)
  Container removed after verification, no lasting changes to this
  session's environment.
- No C/CMake changes in this task; both build trees and the full test suite
  were already green from `TASK-166` and untouched here.
