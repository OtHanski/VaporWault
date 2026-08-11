---
id:          TASK-134
title:       Implement gateway sharing endpoints (grants, public links)
status:      todo
assignee:    WEB.09
created_by:  ARCH.00
created:     2026-08-10
priority:    normal
depends_on:  [TASK-127, TASK-131, TASK-132]
blocks:      [TASK-140]
review_by:   [SEC.07, CQR.08]
tags:        [gateway, web, security-sensitive]
---

Map `vw_client_core.h`'s sharing surface (grant/revoke/list user-to-user
shares, create/revoke/list/access public links) onto gateway HTTP/JSON
endpoints, per the existing sharing model in `ARCHITECTURE.md`
("Sharing model", `TASK-088`) and `docs/PROTOCOL.md` §7.5/§7.10.

Public-link access (`LINK_ACCESS`) is a pre-auth, unauthenticated flow
server-side (establishes a scoped session bound to one `share_id`) — the
gateway needs a route that doesn't require an existing gateway session
cookie for redeeming a link, mirroring that. Treat a redeemed link's scoped
session the same way `TASK-131`'s session manager treats a normal login:
same session-pool slot type, same timeout/eviction behavior, just
originated differently.

## Acceptance criteria

- Grant/revoke/list a share, and create/revoke/list a public link, all work
  end-to-end through the gateway.
- A public link can be redeemed by a browser with **no** prior gateway
  session/cookie, establishing a scoped gateway session bound to that
  `share_id` exactly like the wire protocol's own `LINK_ACCESS` scoping.
- A revoked share/link is rejected on the scoped session's *next* request,
  not just at future redemption time — matching the server's own live-check
  behavior (`ARCHITECTURE.md`'s sharing-model note) rather than caching
  permission at gateway-session-creation time.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-08-10]: Filed as part of the `TASK-127` web gateway design's
initial implementation wave. Tagged `security-sensitive` since public link
tokens are effectively bearer credentials and this endpoint set has its own
unauthenticated entry point.
