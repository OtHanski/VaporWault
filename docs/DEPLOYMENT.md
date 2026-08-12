# VaporWault — Deployment Guide

**Audience**: System administrators installing and operating VaporWault.

---

## 1. Requirements

### Operating systems

| Platform | Minimum version |
|----------|----------------|
| Linux    | Any distribution with glibc ≥ 2.17 (RHEL 7, Debian 8, Ubuntu 16.04+) |
| Windows  | Windows Server 2019 / Windows 10 (1809) or newer |

macOS is not yet supported.

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU      | 1 core  | 2+ cores |
| RAM      | 256 MiB | 1 GiB+ |
| Disk     | 2 GiB (OS + binaries) + your file storage | SSD for the data directory |

### Network

- TCP port **4430** (or `listen_port`) must be reachable by clients.
- TCP port **9010** (or `cluster_port`) must be reachable by replica nodes in cluster mode.
- Port **443** outbound required for ACME certificate renewal.

### Prerequisites

| Component | Linux | Windows |
|-----------|-------|---------|
| mbedTLS runtime | Install `libmbedtls-dev` / `mbedtls` package, or link statically | Statically linked in the binary |
| TLS certificate | Required (manual PEM or automatic ACME) | Required |

---

## 2. Installation

**Recommended path**: install from the OS-native packages (`.deb`/`.rpm`/`.msi`)
described in §12 — they handle the system user, directories, config template,
and service registration for you. The manual/from-source path below remains
fully supported for scripted, air-gapped, or otherwise advanced deployments.

### Linux (manual, from source)

Build from source first:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Then run the install script as root:

```bash
sudo packaging/linux/install.sh
```

Optional flags:

```bash
sudo packaging/linux/install.sh --prefix /usr/local --build-dir build
```

The script creates the `vapourwault` system user, installs binaries to
`/usr/local/bin`, creates `/var/lib/vapourwault` and `/etc/vapourwault`, and
installs the systemd unit.

### Windows (manual, from source)

Build from source (MSVC or MinGW) then run as Administrator in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass `
    -File packaging\windows\Install-VaporWault.ps1 `
    -BuildDir build\bin
```

The script copies binaries to `C:\Program Files\VaporWault`, creates
`C:\ProgramData\VaporWault`, registers the Windows Service, and opens a
firewall rule for port 4430.

---

## 3. server.conf reference

The server reads its configuration from a plain-text INI file (`key = value`).
Lines beginning with `#` are comments. The default location is:

- **Linux**: `/etc/vapourwault/server.conf`
- **Windows**: `C:\ProgramData\VaporWault\server.conf`

### Network

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_host` | string | `0.0.0.0` | IP address to bind. Use `127.0.0.1` to restrict to localhost. |
| `listen_port` | integer | `4430` | TCP port for TLS client connections. |
| `max_connections` | integer | `256` | Maximum simultaneous client connections. |
| `max_workers` | integer | `4` | Worker thread pool size (1–64). |

### Storage

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `data_dir` | path | `/var/lib/vapourwault` | Root directory for all server data (users, files, oplog). Must be writable by the server process. |

### TLS

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cert_pem_path` | path | `/etc/vapourwault/server.crt` | TLS certificate chain in PEM format. |
| `key_pem_path` | path | `/etc/vapourwault/server.key` | TLS private key in PEM format. |

### Administration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `admin_socket` | path | `/run/vapourwault/admin.sock` | AF_UNIX socket for `vapourwault-server-cli`. **POSIX only** — `vapourwault-server-cli` cannot connect to a Windows server at all yet (no admin IPC transport is implemented on Windows). Leave empty on Windows. |
| `log_level` | string | `INFO` | Logging verbosity: `ERROR`, `WARN`, `INFO`, or `DEBUG`. |

### Garbage collection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `gc_interval_secs` | integer | `1800` | How often (seconds) to run the GC thread. Set to `0` to disable. GC removes expired sessions, orphaned chunks, old oplog segments, and files whose trash retention window (below) has elapsed. |
| `trash_retention_days` | integer | `7` | How long a deleted file stays recoverable (`restore-file`) before GC purges it for good. Set to `0` to purge immediately (no recycle-bin grace period). A trashed file still counts against its owner's quota until purged. |

### ACME (automatic TLS via Let's Encrypt)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `acme_enabled` | 0/1 | `0` | Set to `1` to enable automatic certificate renewal. |
| `acme_directory` | URL | Let's Encrypt production | ACME directory URL. Use the Let's Encrypt staging URL for testing. |
| `acme_contact` | string | _(empty)_ | Contact email for expiry notifications (`mailto:` prefix required). |
| `acme_domain` | string | _(empty)_ | Domain name for the certificate. Must match what clients connect to. |
| `acme_account_key` | path | `/etc/vapourwault/acme-account.key` | ACME account private key. Created automatically on first run. |
| `acme_dns_hook` | path | _(empty)_ | Script called to add/remove DNS TXT records for DNS-01 challenges. Called as: `hook set <domain> <token>` to create the record, `hook clear <domain>` (no token argument) to remove it. |
| `acme_http_root` | path | _(empty)_ | Directory served at `http://<domain>/.well-known/acme-challenge/` for HTTP-01 challenges. |
| `acme_renew_days` | integer | `30` | Renew the certificate this many days before expiry. |

### SMTP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `smtp_host` | string | _(empty)_ | SMTP relay hostname. Leave empty to disable email features (2FA OTP, password recovery). |
| `smtp_port` | integer | `587` | SMTP port. |
| `smtp_tls_mode` | string | `starttls` | TLS mode: `none`, `starttls`, or `tls`. |
| `smtp_username` | string | _(empty)_ | SMTP username. |
| `smtp_password` | string | _(empty)_ | SMTP password. |
| `smtp_from_addr` | string | _(empty)_ | Sender address for outgoing email. |
| `smtp_from_name` | string | `VaporWault` | Sender display name. |
| `smtp_verify_cert` | 0/1 | `1` | Verify the SMTP server's TLS certificate. Set to `0` only for testing. |
| `smtp_ca_cert_path` | path | _(empty)_ | Custom CA certificate for SMTP TLS verification. |

### Cluster (replication)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cluster_port` | integer | `9010` | TCP port for cluster replication. Set to `0` to disable cluster mode. |
| `cluster_is_replica` | 0/1 | `0` | Set to `1` for replica nodes. |
| `cluster_primary_host` | string | _(empty)_ | Primary node hostname/IP (replica only). |
| `cluster_primary_port` | integer | `9010` | Primary node cluster port (replica only). |
| `cluster_poll_interval_secs` | integer | `5` | How often a replica pulls new oplog entries from the primary (seconds). |

---

## 4. TLS certificates

### Automatic (ACME / Let's Encrypt)

Enable ACME renewal in `server.conf`:

```ini
acme_enabled  = 1
acme_contact  = mailto:admin@example.com
acme_domain   = vault.example.com
```

Choose a challenge method:

**DNS-01** (recommended — works behind firewalls):

```ini
acme_dns_hook = /usr/local/bin/my-dns-hook.sh
```

The hook script must accept `set <domain> <token>` (create the `_acme-challenge` TXT record) and `clear <domain>` (remove it — no token argument) and update your DNS provider accordingly.

**HTTP-01** (requires port 80 to be publicly reachable):

```ini
acme_http_root = /var/www/acme
```

Point your web server to serve `/.well-known/acme-challenge/` from that directory, or let `vapourwaultd` handle it if port 80 is not in use by another process.

### Manual PEM

Generate a self-signed certificate for internal/testing use:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
    -nodes -keyout /etc/vapourwault/server.key \
    -out /etc/vapourwault/server.crt \
    -subj "/CN=vault.example.com" \
    -addext "subjectAltName=DNS:vault.example.com,IP:192.168.1.10"
chmod 600 /etc/vapourwault/server.key
```

For production, obtain a certificate from a public CA (Let's Encrypt, ZeroSSL, your organisation's PKI) and replace the PEM files. No server restart is required — send `SIGHUP` to reload:

```bash
systemctl reload vapourwaultd
```

---

## 5. First-run setup

After installation and editing `server.conf`:

### Linux

```bash
# Start the service
systemctl enable --now vapourwaultd

# Verify it started
systemctl status vapourwaultd

# Create the first admin user (Argon2id hashing takes ~2 seconds)
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    user-create admin 'YourStrongPassword!' --admin
```

### Windows

```powershell
Start-Service VaporWault

& "C:\Program Files\VaporWault\vapourwault-server-cli.exe" `
    user-create admin 'YourStrongPassword!' --admin
```

### Verify the server is healthy

```bash
# Linux: check the admin socket is present
ls -l /run/vapourwault/admin.sock

# Tail recent log output
journalctl -u vapourwaultd -n 50

# List users
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock user-list
```

---

## 6. Cluster setup

Cluster mode is **on by default** (`cluster_port` defaults to `9010`) — set
`cluster_port = 0` explicitly in `server.conf` if you don't intend to use it,
to avoid leaving an unused TLS listener open.

### Primary node

`server.conf` on the primary (this is the default — no change needed unless
you'd previously disabled it):

```ini
cluster_port       = 9010
cluster_is_replica = 0
```

Register the replica (run once per replica, on the primary):

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster node-add replica1.example.com
```

This prints a `node_id` and a 256-bit authentication token — record both now,
the token is never shown again. Pairing needs one more step on the replica
itself (see below): the primary only mints the token, it doesn't push it
anywhere.

### Replica node

```ini
cluster_port               = 0
cluster_is_replica         = 1
cluster_primary_host       = primary.example.com
cluster_primary_port       = 9010
cluster_poll_interval_secs = 5
```

Complete pairing by giving the replica the same `node_id`/token the primary
printed:

```bash
echo '<token-from-primary>' | vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster register-self <node_id> - replica1.example.com
```

(`-` reads the token from stdin instead of argv, keeping it out of shell
history and `ps` output — the token is a bearer credential, treat it like a
password. You can also pass it directly as the third argument if you accept
that tradeoff.) This writes the replica's own record to
`data_dir/cluster/nodes.db`. The replica daemon retries the connection with
exponential backoff (2s–60s) until this record exists.

### Verify replication

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster status
```

The output shows each node's `NODE_ID`, `ROLE` (`replica` on the primary's own
list, `self` on a replica's own list), `ACTV`, `HOSTNAME`, and
`SYNC_WATERMARK` (the last oplog entry_id confirmed applied — 0 until the
replica has pulled anything).

---

## 7. Backup and restore

### What to back up

Back up in this order (to maintain consistency):

1. **`data_dir/oplog/`** — the append-only operation log. Take a filesystem snapshot or copy while the server is running.
2. **`data_dir/store/`** — user and session records.
3. **`data_dir/chunks/`** — chunk content-addressed storage.

All three directories must be consistent with each other. A snapshot of the entire `data_dir` is the safest approach.

### Restore

1. Stop the server.
2. Replace `data_dir` contents with the backup.
3. Restart the server. On start-up it will recover any partially-written oplog tail automatically.

### Recovering an accidentally deleted file (trash)

A deleted file stays recoverable for `trash_retention_days` (default 7) before
GC purges it for good — this is separate from the full-`data_dir` backup above
and doesn't require restoring anything:

```bash
# See what's recoverable for a user (file_id, deletion time, name)
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock \
    list-deleted alice

# Restore one by file_id
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock \
    restore-file 42
```

---

## 8. Upgrading

**If you installed via a package** (§12): `apt install ./<new>.deb`,
`rpm -U <new>.rpm`/`dnf upgrade <new>.rpm`, or re-running the `.msi` all
upgrade in place — config and data are preserved by every package format's
upgrade path (only *removal*, not upgrade, has the DEB/RPM asymmetry
described in §12.3). Restart the service afterward (package upgrades do not
restart a running service automatically, matching the "don't act on a
config you haven't reviewed" philosophy used throughout this project).

**If you installed manually from source**:

1. Download and build the new version.
2. Stop the service (`systemctl stop vapourwaultd` / `Stop-Service VaporWault`).
3. Replace the binaries (`install.sh` or `Install-VaporWault.ps1` re-run).
4. Start the service.

The oplog format is forward-compatible within a major version. All confirmed entries written by an older binary are valid input to a newer binary.

**Rolling upgrade** (primary + replica): upgrade the replica first, then the primary. If the new replica binary encounters an oplog entry type it does not recognise, it logs a warning and skips that entry — no data loss.

---

## 9. Troubleshooting

### Server won't start

```bash
# Check logs
journalctl -u vapourwaultd -n 100

# Validate config without starting
vapourwaultd --config /etc/vapourwault/server.conf --check-config
```

Common causes:
- `cert_pem_path` or `key_pem_path` file not found or unreadable.
- `listen_port` already in use (`ss -tlnp | grep 4430`).
- `data_dir` not writable by the `vapourwault` user.

### Admin CLI can't connect

On Windows, this is expected — `vapourwault-server-cli` has no admin IPC
transport there yet and always fails to connect. On Linux:

```bash
ls -l /run/vapourwault/admin.sock    # must exist and be owned by vapourwault
id                                   # must be running as the correct user
```

### High memory usage

Increase `max_workers` conservatively. Each worker holds a TLS context and an I/O buffer. `max_connections` governs how many TLS sessions are open simultaneously.

### Oplog recovery

If the server crashed mid-write, it recovers automatically on next start: the oplog scanner (`seg_scan`) truncates any unconfirmed tail entry. No manual intervention is needed.

---

## 10. Security hardening checklist

- [ ] TLS 1.3 is enforced (the server refuses TLS 1.2 and below — no configuration needed).
- [ ] Cipher suites restricted to `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`.
- [ ] `key_pem_path` is readable only by the `vapourwault` user (`chmod 600`).
- [ ] `admin_socket` is mode `0600` (set automatically by the server).
- [ ] Firewall: restrict port 4430 to intended client IP ranges; restrict port 9010 to replica node IPs only.
- [ ] Enable 2FA (email OTP) for all admin accounts: configure `smtp_*` keys and have users enable 2FA in their client settings.
- [ ] Use ACME or a CA-signed certificate — not a self-signed cert — in production.
- [ ] Enable GC (`gc_interval_secs = 1800`, the default) so expired sessions are cleaned up.
- [ ] On Linux: verify the systemd sandbox is active (`systemctl status vapourwaultd` should show `ProtectSystem=strict`).
- [ ] **Client daemon hosts**: `vapourwault-daemon`'s IPC port (loopback TCP,
      default 47832) binds to `127.0.0.1` only. **On Linux**, connections are
      also verified against `/proc/net/tcp` to confirm the connecting
      process shares the daemon's UID (TASK-093) — a different local user's
      connection is rejected. **On Windows** (TASK-103), connections are
      verified against `GetExtendedTcpTable` plus a PID-to-SID lookup;
      deliberately more permissive than the Linux check on any failure to
      positively resolve a *mismatched* SID (API unavailable, insufficient
      privilege, a race between `accept()` and the table snapshot falls back
      to trusting loopback binding alone, rather than rejecting the
      connection). **On macOS**, no such check exists (support is deferred
      project-wide) — the daemon trusts loopback binding alone there. On a
      single-user machine this is no different from any other local IPC
      channel regardless of platform. **Do not run the client daemon on a
      shared multi-user macOS host**: any local user could issue
      `vapourwault-cli login <guess>` against the configured account,
      effectively a local password-guessing oracle, or otherwise control the
      daemon (pause sync, add/remove folders, etc.) without their own
      credentials. Shared multi-user Linux and Windows hosts are no longer
      subject to this specific risk (Windows' check is best-effort — see
      above — but strictly better than trusting loopback binding alone), but
      running a personal sync daemon on a shared host is still not a
      configuration this project targets or tests.

---

## 11. Web gateway + nginx + frontend deployment

This section covers `vapourwault-web-gateway` (`src/gateway/`) and the static
TypeScript frontend (`web/`) — the browser-accessible alternative to the CLI
and ImGui GUI clients, added in `TASK-127`–`TASK-141`. Everything in Sections
1–10 above still applies to the VaporWault **server** itself; this section is
additive, covering the two new pieces that sit in front of it.

### 11.1 How the pieces fit together

```
Browser
  │  HTTPS (nginx-terminated TLS)
  ▼
nginx  ── serves web/dist/ (+ index.html, style.css) as static files
  │        for every path except /api/*
  │
  │  plain HTTP, loopback only, reverse-proxied
  ▼
vapourwault-web-gateway  ── listens on 127.0.0.1:8080 by default
  │
  │  vw/1 (TLS, mbedTLS, same wire protocol every other client speaks)
  ▼
VaporWault server (vapourwaultd), port 4430
```

The gateway is **its own `vw/1` client** — a sibling of `vapourwault-daemon`,
not a bridge over its IPC (`ARCHITECTURE.md`'s Web gateway module map,
`TASK-127`). It authenticates against the VaporWault server directly, one
live session per logged-in browser tab. It does not need to run on the same
host as the server — `--server-host`/`--server-port` below can point at any
reachable VaporWault server.

**Critically: the gateway's own HTTP listener is not designed to be
internet-facing.** Its hand-rolled HTTP/1.1 parser (`src/gateway/vw_http.c`,
`TASK-129`) is deliberately scoped down on the assumption that nginx is its
*only* upstream — it does not robustly handle malformed or non-HTTP/1.1
traffic the way a general-purpose HTTP server would, because nginx (which
does handle that) is standing in front of it. This is an intentional design
tradeoff (`TASK-127`/`TASK-129`), not a bug or an oversight to be fixed
later. Concretely:

> **Never bind `--listen-host` to a public or otherwise internet-reachable
> address.** Leave it at the default `127.0.0.1` (loopback), or at most an
> internal/private network address reachable *only* by the nginx instance
> proxying it — never a public IP, never `0.0.0.0` on a host with any public
> interface. All internet-facing TLS termination, and all hardening against
> malformed/hostile traffic, is nginx's job in this deployment model, not
> the gateway's. A misconfiguration that exposes the gateway's listener
> directly hands its reduced-hardening parser to arbitrary internet traffic.

### 11.2 Building the gateway and frontend

The gateway is a normal CMake target, gated behind its own option flag
(default `OFF`, since not every deployment wants the web surface at all):

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DVW_BUILD_WEB_GATEWAY=ON
cmake --build build -j$(nproc) --target vapourwault-web-gateway
```

(Combine `-DVW_BUILD_WEB_GATEWAY=ON` with whatever other flags you already
use for the server build in Section 2 — it's an independent, additive
option, not a replacement build.) This produces `build/bin/vapourwault-web-gateway`.

The frontend is a separate, dev-time-only Node/TypeScript build — nothing
from `node_modules` ships to the browser, only its compiled output
(`web/package.json`'s own description). It is **not** orchestrated by CMake;
build it directly with npm (requires Node.js — any reasonably current LTS
release; this was last verified against Node 18+):

```bash
cd web
npm install
npm run build
```

This runs `tsc -p tsconfig.json` (see `web/package.json`'s `build` script)
and produces `web/dist/*.js` alongside the already-present `web/index.html`
and `web/style.css` — together, `web/index.html`, `web/style.css`, and
`web/dist/` are the complete static asset set nginx needs to serve.

### 11.3 Gateway configuration

Unlike the server (`server.conf`) or the client daemon (`daemon.conf`), the
gateway has **no config file** — its only configuration surface is CLI
flags (`vapourwault-web-gateway --help`, `src/gateway/main.c`):

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--server-host HOST` | Yes | — | VaporWault server to connect to. |
| `--server-port PORT` | Yes | — | VaporWault server's TLS port (`listen_port` in that server's `server.conf`, default `4430`). |
| `--ca-cert PATH` | Yes | — | CA certificate (PEM) to verify the server's TLS certificate against. See below — this is **mandatory**, there is no "trust the system store" fallback like the client daemon's `ca_cert_pem_path` has. |
| `--listen-host HOST` | No | `127.0.0.1` | Address the gateway's own HTTP listener binds to. See the loopback-only warning in §11.1 before changing this. |
| `--listen-port PORT` | No | `8080` | Port the gateway's own HTTP listener binds to. |

**On `--ca-cert`**: the gateway is itself a `vw/1` client of the VaporWault
server, and — per `ARCHITECTURE.md`'s Gateway↔server TLS verification
decision — it always verifies the server's certificate
(`VW_CERT_VERIFY_REQUIRED`, hardcoded in `src/gateway/vw_gateway_api.c`); it
never runs with certificate verification disabled, unlike `vw_net_connect`'s
test-only escape hatch. `main.c` refuses to start at all without
`--ca-cert` set. What to point it at depends on how the server's certificate
was issued:

- **Self-signed** (Section 4's manual-PEM example): point `--ca-cert` at
  that same `server.crt` — a self-signed certificate is its own trust
  anchor.
- **CA-signed** (ACME/Let's Encrypt or an organizational CA, Section 4):
  point `--ca-cert` at that CA's root certificate PEM (for Let's Encrypt,
  the ISRG Root X1 certificate; for an internal PKI, your organization's
  root CA cert) — not the server's own leaf certificate.

The gateway has no daemonization of its own (no `fork`/`setsid`) — it runs
in the foreground and logs to stdout/stderr, matching systemd's expectations
for `Type=simple` (§11.5 below); it is not meant to be run detached by hand
in production.

### 11.4 nginx site configuration

An example nginx site config already exists at `web/nginx.conf.example`
(`TASK-136`) — this section explains how it fits together rather than
duplicating it. Copy it into place and adjust the domain/cert paths:

```bash
sudo cp web/nginx.conf.example /etc/nginx/sites-available/vapourwault
sudo ln -s /etc/nginx/sites-available/vapourwault /etc/nginx/sites-enabled/
```

What it does:

- Terminates browser-facing TLS itself (`listen 443 ssl` — its own
  `ssl_certificate`/`ssl_certificate_key`, unrelated to the VaporWault
  server's own TLS cert or the gateway's `--ca-cert`; get one the same way
  as any other public web server, e.g. via `certbot`, or reuse this
  project's own ACME support if you'd rather not run a second ACME client).
- Serves `web/index.html`/`web/style.css`/`web/dist/` as static files
  (`root` + `try_files`) for every path that isn't `/api/*`.
- Reverse-proxies `/api/*` to the gateway's loopback listener
  (`proxy_pass http://127.0.0.1:8080`, matching the gateway's own
  `--listen-host`/`--listen-port` defaults from §11.3 — update this if you
  changed either flag) with `proxy_http_version 1.1` and an emptied
  `Connection` header, since `vw_http.c` always closes the connection after
  one response (no keep-alive) and expects a clean HTTP/1.1 request per
  call.
- Redirects plain HTTP (port 80) to HTTPS.

Reload nginx after installing or changing the site config:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 11.5 systemd unit for the gateway

A systemd unit, `packaging/linux/vapourwault-web-gateway.service`, follows
the same conventions as `vapourwaultd.service` (`Type=simple`,
`Restart=on-failure`, a dedicated non-privileged user, the same sandboxing
directives — `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`,
`ProtectSystem=strict`). Unlike the server, the gateway has no config file
to point at — its ExecStart line *is* its configuration (§11.3's flags),
so **edit that line directly** for your deployment before installing it.

There is currently no install-script integration for the gateway
(`packaging/linux/install.sh` only handles the server; the gateway has no
CPack installer component yet either — see `CMakeLists.txt`'s comment above
its `install()` rules). Install it directly, either via CMake's own install
step or by hand:

```bash
# Build with the gateway enabled (§11.2), then either:

# Option A: let CMake install the binary + unit file together
sudo cmake --install build --prefix /usr/local

# Option B: copy them by hand
sudo install -m 755 build/bin/vapourwault-web-gateway /usr/local/bin/
sudo install -m 644 packaging/linux/vapourwault-web-gateway.service \
    /lib/systemd/system/vapourwault-web-gateway.service
```

Either way, the `vapourwault` system user must already exist (created by
`packaging/linux/install.sh` when you installed the server, §2 — if the
gateway runs on a host without the server installed, create the user
yourself: `useradd --system --no-create-home --shell /usr/sbin/nologin
vapourwault`), and the CA cert path in the unit's `ExecStart` (§11.3) must be
readable by that user.

Edit the `ExecStart` line in `/lib/systemd/system/vapourwault-web-gateway.service`
for your `--server-host`/`--server-port`/`--ca-cert`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vapourwault-web-gateway

# Verify
sudo systemctl status vapourwault-web-gateway
sudo journalctl -u vapourwault-web-gateway -n 50
```

### 11.6 Fresh host walkthrough

A concrete, ordered path from a fresh Linux host to a working
server + gateway + nginx + frontend deployment, all on one host (split
across hosts by adjusting `--server-host`/`--ca-cert` and the nginx
`proxy_pass` target accordingly):

1. **Install build prerequisites**: a C compiler, CMake, and (new for this
   section) Node.js + npm for the frontend build. See `VENDOR_SETUP.md` for
   the C/CMake toolchain list — it does not yet cover Node.js/npm, so make
   sure both are installed via your distribution's package manager or
   [nodejs.org](https://nodejs.org) before continuing.
2. **Build everything**, gateway included:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release -DVW_BUILD_WEB_GATEWAY=ON
   cmake --build build -j$(nproc)
   ```
3. **Install and start the VaporWault server** — follow Sections 2 (Linux
   install), 3 (`server.conf`), 4 (TLS certificate — a self-signed cert is
   fine to start with), and 5 (first-run setup, including creating an admin
   user) above in full before continuing. Confirm it's up:
   `systemctl status vapourwaultd`.
4. **Install and start the gateway** — §11.5 above. Point `--server-host`/
   `--server-port` at the server from step 3 (`127.0.0.1`/`4430` if it's the
   same host) and `--ca-cert` at the `server.crt` from step 3's TLS setup
   (self-signed case — see §11.3 for the CA-signed case). Confirm it's up:
   `curl -i http://127.0.0.1:8080/api/login` (no real request body — a bare
   `GET` against a `POST`-only route) should get *some* HTTP error response
   back rather than "connection refused," which is enough to confirm the
   listener itself is alive; the full `/api/*` route surface is defined by
   `TASK-132`–`TASK-135`'s endpoint handlers
   (`src/gateway/vw_gateway_api.c`).
5. **Build the frontend** — §11.2's `npm install && npm run build` in
   `web/`.
6. **Install and configure nginx** — install nginx via your distribution's
   package manager, then §11.4 above: copy `web/nginx.conf.example` into
   `/etc/nginx/sites-available/`, point its `root` at wherever you've put
   `web/index.html`/`web/style.css`/`web/dist/` (copy the whole `web/`
   output tree to e.g. `/usr/share/vapourwault/web/` if you don't want to
   serve directly out of the checkout), set `server_name` and the
   `ssl_certificate`/`ssl_certificate_key` paths for nginx's own
   browser-facing TLS (a separate cert from the server's — see §11.4),
   enable the site, and reload nginx.
7. **Verify end-to-end**: open `https://<your-domain>/` in a browser, log
   in with the admin user created in step 3, and confirm the file browser
   loads. If it doesn't, check (in this order) `journalctl -u
   vapourwault-web-gateway`, then nginx's error log
   (`/var/log/nginx/error.log`), then `journalctl -u vapourwaultd`.
8. **Firewall**: confirm only port 443 (and 80, for the HTTP→HTTPS
   redirect) need to be open to the internet on this host. Port 8080 (the
   gateway) and port 4430 (the server, if colocated) should **not** be
   reachable from outside this host at all — re-read §11.1's warning if
   you're tempted to open either for convenience.

---

## 12. Installing via OS packages (.deb / .rpm / .msi)

Since `TASK-145`–`TASK-151`, every tagged release publishes OS-native
installer packages alongside the plain tarball/zip (see `docs/RELEASE.md`'s
"Installer packages" section for what the release workflow produces). This
is the **recommended** install path — §2's manual/from-source scripts remain
supported for scripted or air-gapped deployments, but the packages handle
user/directory/service setup for you and are the easier default.

Server and client are **independently installable** — install only the
component you need on a given host (e.g. a headless server on one machine,
the client daemon on your desktop).

### 12.1 Debian / Ubuntu (`.deb`)

```bash
# Server (requires root)
sudo apt install ./vapourwault-server_<version>_amd64.deb

# Client (no root required for daemon operation; apt itself still needs root to install the package)
sudo apt install ./vapourwault-client_<version>_amd64.deb
```

The server package creates the `vapourwault` system user and
`/etc/vapourwault`, `/var/lib/vapourwault`, `/run/vapourwault`, installs a
`server.conf` template only if one doesn't already exist, and registers
(but does not enable/start) the `vapourwaultd` systemd unit — configure
`server.conf` first (§3), then:

```bash
sudo systemctl enable --now vapourwaultd
```

The client package installs a systemd **user** unit. Since it's per-user,
`apt install` cannot start it for a specific user — after installing, each
user who wants sync runs:

```bash
systemctl --user enable --now vapourwault-daemon
```

**Removing**: `sudo apt remove vapourwault-server` keeps `/etc/vapourwault`
and `/var/lib/vapourwault` (config and data survive); `sudo apt purge
vapourwault-server` deletes both, plus the `vapourwault` system user. An
in-place upgrade (`apt install` over an existing version) never deletes
config or data, and never overwrites an admin-edited `server.conf`.

### 12.2 Fedora / RHEL (`.rpm`)

```bash
sudo dnf install ./vapourwault-server-<version>-1.x86_64.rpm
sudo dnf install ./vapourwault-client-<version>-1.x86_64.rpm
```

Install/enable steps are identical to §12.1's DEB instructions (same
maintainer-script logic underneath, just packaged for `rpm`/`dnf`).

**Removing — important difference from DEB**: RPM has no separate "purge"
concept. `sudo dnf remove vapourwault-server` behaves like DEB's `apt
purge`, **not** `apt remove` — it deletes `/etc/vapourwault`,
`/var/lib/vapourwault`, and the `vapourwault` system user immediately. If
you're coming from Debian/Ubuntu habits, there is no gentler removal option
on Fedora/RHEL; back up `/etc/vapourwault` and `/var/lib/vapourwault`
first if you might want them back. As with DEB, an in-place upgrade
(`rpm -U`/`dnf upgrade`) never deletes config or data.

### 12.3 Windows (`.msi`)

Double-click the `.msi`, or from PowerShell:

```powershell
msiexec /i vapourwault-server-<version>-win64.msi
msiexec /i vapourwault-client-<version>-win64.msi
```

**Server MSI** requires Administrator elevation (UAC prompt) — it installs
to `Program Files`, registers a real Windows Service (`ServiceInstall`) with
a firewall rule for the TLS listen port, and installs a `server.conf`
template to `%ProgramData%\VaporWault\server.conf` only if one doesn't
already exist. It does not start the service automatically — configure
`server.conf` first, then start the `VaporWault` service from `services.msc`
or `Start-Service VaporWault`.

**Client MSI** installs **per-user, with no elevation** (no UAC prompt) —
it installs to `%LOCALAPPDATA%`/`%APPDATA%` and registers a per-user
Scheduled Task (logon trigger) that starts `vapourwault-daemon`
automatically at your next logon.

**Removing/upgrading**: uninstall from "Apps & Features" (or `msiexec /x
<path-to-msi>`), or simply run a newer version's `.msi` — CPack's WiX
upgrade handling (`CPACK_WIX_UPGRADE_GUID`, fixed per product) replaces the
old version in place without a separate uninstall step, preserving
`server.conf`/`daemon.conf`.

### 12.4 All packages are unsigned

No code-signing certificate or GPG key currently exists for this project.
Expect the normal OS warnings for unsigned software: `apt`/`dnf` will warn
about an unsigned package (still installable — these aren't served from a
signed repository at all, so there's no signature to check against), and
Windows will show its usual SmartScreen/unknown-publisher prompt for the
`.msi`. This is an accepted, documented gap, not an oversight — revisit if
this project ever sets up code-signing infrastructure.
