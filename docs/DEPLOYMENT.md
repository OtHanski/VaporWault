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

### Linux

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

### Windows

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
