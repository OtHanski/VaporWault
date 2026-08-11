---
id:          TASK-142
title:       Packaging + deployment docs for the web gateway and nginx frontend
status:      todo
assignee:    BLD.05
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-128]
blocks:      []
review_by:   [CQR.08]
tags:        [build, deployment]
---

Today's packaging story (`docs/RELEASE.md`, `docs/DEPLOYMENT.md`,
`packaging/linux/`, `packaging/windows/`) only covers native binary
artifacts (server, client daemon, CLIs, ImGui GUIs) — no static-asset +
reverse-proxy deployment exists. Add one for the web gateway + frontend.

Scope:

1. Linux systemd unit for `vapourwault-web-gateway`, matching the existing
   service-packaging pattern for `vapourwaultd`/`vapourwault-daemon`
   (`packaging/linux/`).
2. `docs/DEPLOYMENT.md` section: nginx site config (coordinate with
   `TASK-136`'s example config rather than duplicating it — this task owns
   the deployment-doc integration, `TASK-136` owns getting a working config
   scaffolded), gateway config file (listen address/port, path to the
   `web/dist` build output for nginx to serve, server connection settings),
   and the recommended process supervision (systemd) for the gateway.
2. `docs/RELEASE.md` update: add the gateway executable and the `web/`
   static-asset build output to the release artifact list.
3. Note explicitly in the deployment doc that the gateway's own HTTP
   listener is expected to be reachable *only* from nginx (loopback or an
   internal network), never exposed directly to the internet — nginx is
   the TLS-terminating, hardened front door; the gateway's hand-rolled
   HTTP layer (`TASK-129`) was scoped down assuming exactly this.

## Acceptance criteria

- A fresh Linux host can go from source checkout to a working nginx +
  gateway + server deployment by following `docs/DEPLOYMENT.md` alone.
- systemd unit starts/stops/restarts the gateway cleanly, matching the
  existing daemon's service packaging conventions.
- Deployment doc explicitly states the "gateway is not internet-facing
  directly" assumption, so a future deployer doesn't accidentally expose it
  without nginx in front.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave.
