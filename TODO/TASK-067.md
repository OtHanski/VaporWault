---
id:          TASK-067
title:       Client daemon Linux packaging — systemd user service and install script
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-14
priority:    normal
depends_on:  [TASK-062]
blocks:      []
review_by:   [CQR.08]
tags:        [packaging, linux, client, deployment, phase-10]
---

Provide everything needed to install the VaporWault client daemon as a systemd
user service on Linux (so it starts automatically when the user logs in, without
requiring root).

## Acceptance criteria

### systemd user service (`packaging/linux/vapourwault-daemon.service`)

```ini
[Unit]
Description=VaporWault client sync daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/vapourwault-daemon --state-dir %h/.local/share/vapourwault
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=default.target
```

Runs as the user (`systemctl --user enable/start vapourwault-daemon`).
`%h` expands to the user's home directory.
`state_dir` is where `daemon.conf`, `session.tok`, and `cache.db` live.

### Sample client config (`packaging/linux/client.conf.example`)

Commented template for `~/.local/share/vapourwault/daemon.conf`:

```ini
server_host      = vault.example.com
server_port      = 4430
ca_cert_pem_path =
username         = yourname
ipc_port         = 47832
sync_interval_ms = 30000
```

### Client install script (`packaging/linux/client_install.sh`)

Bash install script (no root required — installs to `$HOME/.local`):

1. Copies `vapourwault-daemon` and `vapourwault-cli` to `$HOME/.local/bin/`.
2. Installs the systemd user service to
   `$HOME/.config/systemd/user/vapourwault-daemon.service`.
3. Runs `systemctl --user daemon-reload`.
4. Creates `$HOME/.local/share/vapourwault/` and installs the default config
   template (without overwriting an existing `daemon.conf`).
5. Prints next-step instructions (configure daemon.conf, then
   `systemctl --user enable --now vapourwault-daemon`).

### CMake install targets

Add `install()` directives for client binaries to the top-level `CMakeLists.txt`
(if not already present from TASK-062). The client install prefix is typically
`~/.local` for per-user installs, which `cmake --install` handles via `--prefix`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: The systemd user service is the right approach — the
client daemon is a per-user process that should start on login and stop on
logout.  A system-level service for the client daemon would require root and
is the wrong design.  The state_dir path (`~/.local/share/vapourwault`) follows
XDG Base Directory conventions.

BLD.05 [2026-07-14]: All items delivered:
- `packaging/linux/vapourwault-daemon.service` — `Type=simple`, `%h`-based
  paths, `Restart=on-failure`, `TimeoutStopSec=30` (lets in-progress sync finish).
- `packaging/linux/client.conf.example` — fully commented config template for
  `~/.local/share/vapourwault/daemon.conf`.
- `packaging/linux/client_install.sh` — no-root bash installer: copies binaries
  to `$HOME/.local/bin`, installs user service, runs `systemctl --user daemon-reload`,
  writes config template (no overwrite), prints next-step instructions.
- `CMakeLists.txt` updated: client user service now installs to
  `lib/systemd/user` on Linux. Client binaries were already present from
  TASK-062.

CQR.08 [2026-07-14]: ADVISORY — No blocking findings.
- `client_install.sh`: uses `set -euo pipefail`, `install -m 0755`/`0644`/`0600`
  for correct permissions, `--no-overwrite` semantics for daemon.conf are
  correctly implemented with `[ ! -f ... ]`.
- Service unit uses `%h` (not hardcoded `$HOME`) — correct for systemd user units.
- CMake path: `lib/systemd/user` is the correct XDG prefix for user units.
Sign-off: APPROVED.

ARCH.00 [2026-07-14]: CQR.08 sign-off received. No blocking findings. Closing.
