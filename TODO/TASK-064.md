---
id:          TASK-064
title:       Admin deployment guide (docs/DEPLOYMENT.md)
status:      done
assignee:    ARCH.00
created_by:  ARCH.00
created:     2026-07-14
priority:    normal
depends_on:  [TASK-062, TASK-063]
blocks:      []
review_by:   [CQR.08]
tags:        [documentation, deployment, phase-9]
---

Write `docs/DEPLOYMENT.md` — the authoritative operator guide covering everything
needed to get VaporWault running in a production environment on Linux and Windows.

This is the document a system administrator reads when setting up VaporWault for
the first time. It should be self-contained: no prior knowledge of the codebase
required.

## Acceptance criteria

### Sections

1. **Requirements** — OS versions tested; CPU/RAM/disk minimums; open ports.

2. **Installation**
   - Linux: apt/yum prerequisites (mbedTLS runtime if shared), run `install.sh`.
   - Windows: prerequisites, run `Install-VaporWault.ps1`.

3. **server.conf reference** — every configuration key, its type, default, and
   a one-paragraph description.  Grouped by subsystem (network, storage, TLS,
   cluster, GC, ACME, SMTP).

4. **TLS certificates**
   - ACME automatic (Let's Encrypt, DNS-01 and HTTP-01 modes): required DNS/HTTP
     setup, how to configure.
   - Manual PEM: how to generate a self-signed cert for internal use; how to
     install CA-signed certs.

5. **First-run setup** — create first admin user via `vapourwault-server-cli
   user-create`, configure quota, verify server is healthy.

6. **Cluster setup** — primary configuration; replica configuration; registering
   a replica with `vapourwault-server-cli cluster node-add`; verifying replication
   via `cluster-status`.

7. **Backup and restore** — which directories to back up, in what order
   (data_dir, oplog, rcdb); how to restore.

8. **Upgrading** — binary replacement procedure; oplog forward-compatibility
   guarantee; when a rolling upgrade is safe vs. when to stop-all-then-upgrade.

9. **Troubleshooting** — how to read server logs; common errors and their fixes;
   how to use `vapourwault-server-cli` for diagnostics.

10. **Security hardening checklist** — TLS 1.3 enforced (document where); admin
    socket permissions; firewall recommendations; 2FA setup.

### Style

- Written for a technical operator, not a developer.
- Commands in fenced code blocks with the correct shell prompt (`$` for bash,
  `>` for PowerShell).
- No references to internal code structure or variable names.
- Accurate: every config key matches what `vw_server_main.c` actually parses.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-14]: This document depends on TASK-062 and TASK-063 because it
references the install scripts and config templates those tasks produce.  It also
depends on having a complete picture of all server.conf keys — SRV.01 should
confirm the final key list before this task starts.  The cluster setup section
is the most complex; reference docs/PROTOCOL.md §9 (cluster) for the wire-level
details where useful.

ARCH.00 [2026-07-14]: Written. `docs/DEPLOYMENT.md` covers all 10 required
sections: requirements, installation (Linux + Windows), server.conf reference
(all parsed keys), TLS (ACME + manual), first-run setup, cluster setup, backup
and restore, upgrading, troubleshooting, and security hardening checklist.
Config key reference derived directly from vw_server_main.c parse tables —
all keys verified against the parser.

CQR.08 [2026-07-14]: Reviewed for accuracy and completeness. The server.conf
reference table covers all keys parsed in vw_server_main.c (verified by cross-
referencing the config parser switch block). Upgrade notes correctly describe
forward-compatibility of the oplog format and the rolling-upgrade order.
Security hardening checklist items are accurate. LGTM.

ARCH.00 [2026-07-14]: Signed off. Marking done.
