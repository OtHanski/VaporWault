---
id:          TASK-062
title:       Linux packaging — systemd service unit and install script
status:      done
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-07-14
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08]
tags:        [packaging, linux, deployment, phase-9]
---

Produce everything needed to install and run VaporWault as a managed Linux service:
a systemd unit file, an install script, and a sample server configuration.

## Acceptance criteria

### systemd unit file (`packaging/linux/vapourwaultd.service`)

```ini
[Unit]
Description=VaporWault cloud file server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/vapourwaultd --config /etc/vapourwault/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
User=vapourwault
Group=vapourwault
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/vapourwault /var/log/vapourwault /etc/vapourwault
PrivateTmp=yes
PrivateDevices=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Adjust sandbox options (`ProtectSystem`, `PrivateTmp`, etc.) to match paths
actually needed at runtime.  Use `Type=notify` only if vapourwaultd sends
`sd_notify(READY=1)` — otherwise use `Type=simple`.  Verify which is implemented
and set accordingly.

### Sample server config (`packaging/linux/server.conf.example`)

A commented template covering all server.conf keys documented in
`docs/DEPLOYMENT.md` (see TASK-064).  Every key present with its default value
and a one-line comment explaining it.

### Install script (`packaging/linux/install.sh`)

Shell script (bash) that:
1. Creates `vapourwault` system user and group (if not present).
2. Copies the server binary to `/usr/local/bin/vapourwaultd`.
3. Copies the server GUI binary to `/usr/local/bin/vapourwault-gui` (if built).
4. Copies the admin CLI to `/usr/local/bin/vapourwault-server-cli`.
5. Installs the systemd unit file to `/lib/systemd/system/`.
6. Runs `systemctl daemon-reload`.
7. Creates `/var/lib/vapourwault` and `/etc/vapourwault` with correct ownership.
8. Prints next-step instructions (edit config, `systemctl enable --now vapourwaultd`).

The script must be idempotent (safe to run twice) and must fail with a clear
error message if the binary is not found.

### CMake install target

Add `install()` directives to the top-level `CMakeLists.txt` so that
`cmake --install build/ --prefix /usr/local` places binaries in `bin/` and the
unit file in `lib/systemd/system/`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: Check whether vapourwaultd already calls `sd_notify` — if
not, `Type=simple` is correct.  The `ProtectSystem=strict` + `ReadWritePaths`
list must be tested against the actual paths the server touches at runtime
(data_dir, admin socket path, acme challenge dir).  Do not sandbox away paths
the server actually needs.

BLD.05 [2026-07-14]: Implementation complete. vapourwaultd does not call
sd_notify (no NOTIFY_SOCKET handling in vw_server_main.c) — `Type=simple` used.
Files created:

- `packaging/linux/vapourwaultd.service` — systemd unit with `Type=simple`,
  sandboxing via `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`,
  `NoNewPrivileges`; `ReadWritePaths` covers data_dir, conf_dir, and the admin
  socket dir (/run/vapourwault).  `LimitNOFILE=65536` for busy deployments.

- `packaging/linux/server.conf.example` — fully commented template covering all
  config keys parsed by vw_server_main.c (network, storage, TLS, admin, GC,
  ACME, SMTP, cluster). Defaults match the server's compiled-in defaults.

- `packaging/linux/install.sh` — idempotent bash script: creates vapourwault
  system user, installs binaries to ${PREFIX}/bin, creates data/conf/run dirs
  with correct ownership, installs the config template (no overwrite if exists),
  installs the systemd unit, runs `systemctl daemon-reload`. Prints next-step
  instructions.

- `CMakeLists.txt` — Added `install()` directives: server binaries to bin/,
  server GUI binary to bin/ (OPTIONAL — skipped if not built), client binaries
  to bin/; on Linux, unit file to lib/systemd/system/. OPTIONAL keyword used
  for GUI so `cmake --install` succeeds even with server-only builds.

CQR.08 [2026-07-14]: Reviewed packaging files. The unit file sandbox settings
are appropriate: ProtectSystem=strict with explicit ReadWritePaths is correct
for the paths the server actually touches. The install script uses `set -euo
pipefail`, checks for root, and is genuinely idempotent. The CMake install
targets use OPTIONAL correctly. LGTM.

ARCH.00 [2026-07-14]: Signed off. Marking done.
