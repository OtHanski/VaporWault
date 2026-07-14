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
| `admin_socket` | path | `/run/vapourwault/admin.sock` | AF_UNIX socket for `vapourwault-server-cli`. Leave empty to disable (Windows only; Windows uses an alternative IPC channel). |
| `log_level` | string | `INFO` | Logging verbosity: `ERROR`, `WARN`, `INFO`, or `DEBUG`. |

### Garbage collection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `gc_interval_secs` | integer | `300` | How often (seconds) to run the GC thread. Set to `0` to disable. GC removes expired sessions, orphaned chunks, and old oplog segments. |

### ACME (automatic TLS via Let's Encrypt)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `acme_enabled` | 0/1 | `0` | Set to `1` to enable automatic certificate renewal. |
| `acme_directory` | URL | Let's Encrypt production | ACME directory URL. Use the Let's Encrypt staging URL for testing. |
| `acme_contact` | string | _(empty)_ | Contact email for expiry notifications (`mailto:` prefix required). |
| `acme_domain` | string | _(empty)_ | Domain name for the certificate. Must match what clients connect to. |
| `acme_account_key` | path | `/etc/vapourwault/acme-account.key` | ACME account private key. Created automatically on first run. |
| `acme_dns_hook` | path | _(empty)_ | Script called to add/remove DNS TXT records for DNS-01 challenges. Called as: `hook add|remove <domain> <token>`. |
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

The hook script must accept `add <domain> <token>` and `remove <domain> <token>` arguments and update your DNS provider's `_acme-challenge` TXT record accordingly.

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

### Primary node

Enable clustering in `server.conf` on the primary:

```ini
cluster_port      = 9010
cluster_is_replica = 0
```

Register each replica node:

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster node-add replica1.example.com 9010
```

The command outputs a pre-shared authentication token. Record it — you will need it to configure the replica.

### Replica node

```ini
cluster_port               = 9010
cluster_is_replica         = 1
cluster_primary_host       = primary.example.com
cluster_primary_port       = 9010
cluster_poll_interval_secs = 5
```

Place the authentication token issued by the primary in the replica's `data_dir/cluster/nodes.bin` (created automatically when the replica first connects).

### Verify replication

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster-status
```

The output shows each replica's `node_id`, `last_sync_watermark`, and connection state.

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
- [ ] Enable GC (`gc_interval_secs = 300`) so expired sessions are cleaned up.
- [ ] On Linux: verify the systemd sandbox is active (`systemctl status vapourwaultd` should show `ProtectSystem=strict`).
