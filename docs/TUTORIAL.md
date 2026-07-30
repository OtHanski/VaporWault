# VaporWault — Getting Started: Primary Server, Backup Server, and Users

This is a from-scratch, copy-paste walkthrough for standing up a new VaporWault
deployment: one primary server reachable at a real domain, a second server
that replicates it as a hot backup, and a couple of user accounts. It assumes
Linux (see the callout below for why).

**Platform note**: this tutorial is Linux-only. The admin CLI
(`vapourwault-server-cli`) — which is how you create users and pair a backup
server — has no working transport on Windows yet (`admin_socket` is a
POSIX-only AF_UNIX socket; there's no Windows equivalent implemented). A
Windows server can still run and serve files, but you can't administer it
from that binary. Track that gap before relying on Windows in production.

For reference documentation beyond this walkthrough (full config key list,
backup/restore, upgrading, security hardening checklist), see
`docs/DEPLOYMENT.md`. For building from source, see `VENDOR_SETUP.md`.

---

## What you'll end up with

- **`vault1`** — the primary server, reachable at a real domain over TLS,
  with two user accounts.
- **`vault2`** — a second server, paired as a replica, continuously pulling
  a copy of the primary's data (users, files, oplog) over its own encrypted
  channel.

Both are independent `vapourwaultd` processes — they can be two machines on
the same network, or two VMs, or two containers; anywhere both can reach each
other over TCP works. You need root (or a user with `sudo`) on both.

---

## 1. Build (or download) the binaries

**Download a release** (fastest — see `docs/RELEASE.md` for how releases are
cut): grab `vaporwault-<version>-linux-x86_64.tar.gz` from the project's
GitHub Releases page and extract it. You'll get `vapourwaultd` and
`vapourwault-server-cli` among the binaries — that's all this tutorial needs.

**Or build from source**:

```bash
git clone --recurse-submodules <this-repo-url> VaporWault
cd VaporWault
cmake -B build -DCMAKE_BUILD_TYPE=Release -DVW_BUILD_CLIENT=OFF -DVW_BUILD_GUI=OFF
cmake --build build -j$(nproc)
```

(`-DVW_BUILD_CLIENT=OFF -DVW_BUILD_GUI=OFF` skips everything this tutorial
doesn't need — server + admin CLI only. Drop those flags if you want the
client/GUI too.) See `VENDOR_SETUP.md` if this is your first build — mbedTLS
and Argon2 fetch automatically, but you'll want the whole repo cloned with
submodules first.

Do this on **both** machines (`vault1` and `vault2`).

---

## 2. Install the primary server (`vault1`)

```bash
sudo packaging/linux/install.sh
```

This creates a dedicated `vapourwault` system user, installs the binaries to
`/usr/local/bin`, creates `/var/lib/vapourwault` (data), `/etc/vapourwault`
(config), `/run/vapourwault` (admin socket), copies
`server.conf.example` → `/etc/vapourwault/server.conf` (only if that file
doesn't already exist — safe to re-run), and installs the systemd unit. It
does **not** open any firewall port or start the service — both are next.

Edit `/etc/vapourwault/server.conf`:

```ini
listen_host      = 0.0.0.0
listen_port      = 4430
data_dir         = /var/lib/vapourwault
cert_pem_path    = /etc/vapourwault/server.crt
key_pem_path     = /etc/vapourwault/server.key
admin_socket     = /run/vapourwault/admin.sock
log_level        = INFO
```

Leave the rest at their defaults for now — TLS and cluster settings come
next. Open the firewall for the client port:

```bash
sudo ufw allow 4430/tcp   # or the equivalent for your firewall
```

(`install.sh` doesn't do this for you — see `docs/DEPLOYMENT.md` §1 for the
full port list, including the cluster port you'll open in step 5.)

---

## 3. Connect it to a real address (TLS)

You need a real certificate before start-up — `vapourwaultd` won't serve TLS
without one. Two options:

### Option A — ACME (recommended for a real domain)

Point a DNS `A`/`AAAA` record at `vault1`'s IP first (e.g. `vault.example.com`
→ `vault1`'s address), then enable ACME in `server.conf`:

```ini
acme_enabled  = 1
acme_contact  = mailto:admin@example.com
acme_domain   = vault.example.com
```

Pick a challenge method:

- **DNS-01** (works even if `vault1` isn't yet reachable on port 80 —
  preferred): set `acme_dns_hook` to a script you write for your DNS
  provider's API. VaporWault calls it as:
  - `<script> set <domain> <token>` — create the `_acme-challenge` TXT record
  - `<script> clear <domain>` — remove it (no token argument)

  ```ini
  acme_dns_hook = /usr/local/bin/my-dns-hook.sh
  ```

- **HTTP-01** (simpler, but port 80 must be publicly reachable and pointed at
  `vault1`):

  ```ini
  acme_http_root = /var/www/acme
  ```

The certificate renews automatically (`acme_renew_days = 30` by default — no
further action needed once this is configured).

### Option B — manual certificate (fine for internal/testing use)

```bash
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
    -nodes -keyout /etc/vapourwault/server.key \
    -out    /etc/vapourwault/server.crt \
    -subj "/CN=vault.example.com" \
    -addext "subjectAltName=DNS:vault.example.com,IP:<vault1's IP>"
sudo chmod 600 /etc/vapourwault/server.key
sudo chown vapourwault:vapourwault /etc/vapourwault/server.key /etc/vapourwault/server.crt
```

For anything beyond a lab/internal setup, use Option A instead — clients will
reject a self-signed cert unless you also distribute it as a trusted CA,
which is more operational overhead than ACME.

### Start it

```bash
sudo systemctl enable --now vapourwaultd
sudo systemctl status vapourwaultd
```

Check the log if it doesn't come up clean:

```bash
sudo journalctl -u vapourwaultd -n 50
```

Common first-run failures: `cert_pem_path`/`key_pem_path` unreadable by the
`vapourwault` user, or `listen_port` already in use.

---

## 4. Create user accounts

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    user-create admin 'YourStrongAdminPassword!' --admin
```

`--admin` marks the account as an administrator; omit it for an ordinary
user. Passing the password directly on the command line is visible in shell
history and `ps` — for anything beyond a quick lab setup, pipe it via stdin
instead:

```bash
echo 'YourStrongAdminPassword!' | vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    user-create admin - --admin
```

Create a second, ordinary user the same way:

```bash
echo 'AlicesPassword!' | vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    user-create alice -
```

Optionally cap how much storage Alice can use (bytes; `0` = unlimited):

```bash
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock \
    set-quota alice 10737418240   # 10 GiB
```

Verify:

```bash
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock user-list
```

```
USER_ID   ADMIN  ACTV   USERNAME                                                          QUOTA             USED
1         yes    yes    admin                                                             0                 0
2         no     yes    alice                                                             10737418240       0
```

---

## 5. Set up the backup server (`vault2`)

Cluster mode is **on by default** — `cluster_port` defaults to `9010` — so
`vault1` is already listening for a replica even though you haven't paired
one yet. (If you don't want that, set `cluster_port = 0` on any server you
never intend to pair.)

### Install and configure `vault2`

On `vault2` (same install step as `vault1`):

```bash
sudo packaging/linux/install.sh
```

Edit `/etc/vapourwault/server.conf` on `vault2`:

```ini
listen_host      = 0.0.0.0
listen_port      = 4430
data_dir         = /var/lib/vapourwault
cert_pem_path    = /etc/vapourwault/server.crt
key_pem_path     = /etc/vapourwault/server.key
admin_socket     = /run/vapourwault/admin.sock

cluster_port               = 0
cluster_is_replica         = 1
cluster_primary_host       = vault.example.com
cluster_primary_port       = 9010
cluster_poll_interval_secs = 5
```

`vault2` needs a certificate too — repeat step 3 for it (ACME with its own
domain, or a manual cert; it doesn't need to be the same certificate as
`vault1`'s, since replication only requires each side to trust the other's
cert as its own CA — see the note at the end of this section).

Open the cluster port between the two machines (on `vault1`, since that's
the side listening):

```bash
# on vault1
sudo ufw allow from <vault2's IP> to any port 9010 proto tcp
```

### Register the replica (run on `vault1`)

```bash
vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster node-add vault2.example.com
```

```
registered node_id=1 hostname=vault2.example.com role=replica
auth_token (record this now, it cannot be retrieved again):
<64 hex characters>

On the replica's own server, run:
  vapourwault-server-cli cluster register-self 1 <token-above> <this-server's-hostname>
```

**Copy the printed `node_id` and token now** — the token is never shown
again after this. It's a bearer credential (equivalent to a password for this
one purpose); treat it accordingly.

### Complete pairing (run on `vault2`)

Start `vault2`'s service first if you haven't (`systemctl enable --now
vapourwaultd`) — it will retry the connection to `vault1` with backoff until
the next step completes.

```bash
echo '<token-from-vault1>' | vapourwault-server-cli \
    --admin-socket /run/vapourwault/admin.sock \
    cluster register-self 1 - vault2.example.com
```

(`-` reads the token from stdin, keeping it off the command line/shell
history — same reasoning as the password handling in step 4. `1` is the
`node_id` `vault1` printed; use whatever value you actually got.)

### Verify replication

On `vault1`:

```bash
vapourwault-server-cli --admin-socket /run/vapourwault/admin.sock cluster status
```

```
NODE_ID   ROLE     ACTV   HOSTNAME                                  SYNC_WATERMARK
1         replica  yes    vault2.example.com                        0
```

Check `vault2`'s logs for confirmation the handshake succeeded:

```bash
sudo journalctl -u vapourwaultd -n 20 | grep -i cluster
```

You should see a line like `replica: connected to primary`. On `vault1`,
`journalctl -u vapourwaultd | grep NODE_HELLO` should show `NODE_HELLO OK from
node 1`. `SYNC_WATERMARK` in `cluster status` advances above `0` once there's
oplog activity for the replica to pull (e.g. after you create the users in
step 4, if you do that step after pairing, or after any subsequent
file/user/permission change).

**Certificate note**: replication connects with certificate verification
required, using each side's own configured certificate as the trust anchor
for the peer. The simplest setup — sharing one certificate/key pair across
both `vault1` and `vault2` — always works. If you'd rather each server keep
its own distinct certificate, that also works as long as each one's
`cert_pem_path` is set up to be able to verify the *other's* certificate;
for a first setup, sharing one pair is the least fiddly option.

---

## 6. What's next

- **Backups of `vault1`/`vault2` themselves** (independent of replication):
  see `docs/DEPLOYMENT.md` §7 for what to snapshot (`data_dir/oplog`,
  `data_dir/store`, `data_dir/chunks`, in that order) and §8 for upgrades.
- **Security hardening**: `docs/DEPLOYMENT.md` §10 has a checklist (cipher
  suites, socket permissions, 2FA via SMTP, firewall scoping).
- **Client access**: install `vapourwault-daemon`/`vapourwault-cli`, point
  `daemon.conf` at the server (`server_host`, `server_port`,
  `ca_cert_pem_path`, `username`), start the daemon, then run
  `vapourwault-cli login <password|-|--stdin-password>` (use `-`/
  `--stdin-password` to keep the password out of shell history). Once
  logged in, `vapourwault-cli status` reflects the connected state and
  `add-folder`/`ls`/etc. become useful. **Do not run the client daemon on a
  shared multi-user host** — its IPC port has no per-user authentication;
  see `docs/DEPLOYMENT.md` §10 for the full caveat.
