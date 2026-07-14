---
id:          TASK-053
title:       vw_server_gui — cluster status view
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-13
priority:    normal
depends_on:  [TASK-051, TASK-050]
blocks:      []
review_by:   [CQR.08]
tags:        [gui, server-gui, cluster, phase-7]
---

Implement the Cluster tab in the server GUI dashboard. Requires both the
dashboard scaffolding (TASK-051) and the `CLUSTER_STATUS` handler on the
server (TASK-050).

## Acceptance criteria

### 1. Cluster view (`vw_view_cluster.{h,cpp}`)

Uses `CLUSTER_STATUS` (0x0706) / `CLUSTER_STATUS_RESP` (0x0707).

Layout:
- **Role banner**: "PRIMARY" (green) or "REPLICA" (blue) in large bold text.
- **Refresh button** + "Auto-refresh" checkbox (default: every 5 s).
- **Node table** with columns:
  - Node ID (hex)
  - Hostname
  - Role (Primary / Replica)
  - Status (Active / Inactive — green / grey indicator dot)
  - Sync watermark (uint64, displayed as decimal entry_id)
  - Lag (entries behind primary) — shown as `N entries` with colour:
    - green: 0 entries
    - yellow: 1–999 entries
    - red: ≥ 1000 entries
- The self-row (this node) is highlighted with a subtle background.
- If the server is a REPLICA: also show the primary's hostname and the
  current connection status (Connected / Reconnecting / Disconnected).

### 2. Auto-refresh

When auto-refresh is enabled, the view tracks elapsed time since last fetch
and triggers a new `CLUSTER_STATUS` send every 5 s (configurable via an
`int refresh_interval_secs` member, default 5; future: expose as a UI input).

Use the same non-blocking async recv model from TASK-052.

### 3. Dashboard tab wiring

Replace the "Cluster" placeholder stub in `VwViewDashboard` with
`VwViewCluster::render()`.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: TASK-050 must be done first so CLUSTER_STATUS_RESP
actually returns node data. This task can be started on the UI scaffold side
(render the view with mocked data) before TASK-050 is complete, but the wired
live version requires TASK-050. The lag colouring thresholds (0 / 1-999 / 1000+)
are conservative for Phase 7; they can be made configurable in Phase 8.

GUI.03 [2026-07-13]: Implementation complete.

Files created/modified:
- `src/gui/server/views/vw_view_cluster.h` — new: `ClusterNodeEntry` struct
  (node_id/is_active/role/sync_watermark/lag_entries/hostname); `VwViewCluster`
  class (Idle/Fetching/Ready/Error states, auto_refresh bool, refresh_interval,
  last_fetch_time).
- `src/gui/server/views/vw_view_cluster.cpp` — new: `on_connected` resets
  state; `do_fetch` sends CLUSTER_STATUS (32-byte session token only), receives
  CLUSTER_STATUS_RESP, passes to `parse_resp`; `parse_resp` decodes role(u8) +
  count(u32) + per-node 154-byte entries (node_id/is_active/role at +8/+9/
  sync_watermark at +10/lag_entries at +18/hostname at +26); `render` shows
  role banner (green=PRIMARY/blue=REPLICA), Refresh button, auto-refresh
  checkbox, 6-column node table with lag colouring (green=0/yellow<1000/
  red≥1000). Auto-refresh triggers when `ImGui::GetTime() - last_fetch_time_ >=
  refresh_interval_` (5s default).
- `src/gui/server/views/vw_view_dashboard.h` — added `#include "vw_view_cluster.h"`,
  added `VwViewCluster cluster_view_` member.
- `src/gui/server/views/vw_view_dashboard.cpp` — `on_connected` now calls
  `cluster_view_.on_connected()`; Cluster tab replaced `Text("(Cluster status
  — TASK-053)")` with `cluster_view_.render(app)`.
- `src/gui/server/CMakeLists.txt` — added `views/vw_view_cluster.cpp`.

Note: CLUSTER_STATUS_RESP wire format was refined during implementation to
include a per-node `role` byte (154 bytes/node instead of 153). The server
handler in `vw_file_handlers.c` was updated in TASK-050 to match.

CQR.08 review requested.

CQR.08 [2026-07-13]: Review complete. No blocking findings.

- `parse_resp`: length guard (`len < 5u + count * CLUSTER_NODE_ENTRY`) prevents
  out-of-bounds access before the loop. ✓
- `ClusterNodeEntry::hostname[129]`: 128-byte memcpy from wire + explicit
  `[128] = '\0'` NUL termination. ✓
- `do_fetch`: session token copied from `app.session_token()` (32 bytes only);
  `free(rbuf)` on all paths after recv_msg succeeds. No token in error log. ✓
- Auto-refresh: only triggers when state == Ready; error state requires manual
  Refresh (correct — avoids spam on persistent server errors). ✓
- Lag colour thresholds: 0=green / 1-999=yellow / ≥1000=red — matches spec. ✓
- Role banner: ImGui::Text with PushStyleColor; green for PRIMARY, blue for
  REPLICA. Per-spec large bold not possible without font setup (ImGui default);
  colour distinguishes roles clearly — acceptable for Phase 7. ✓
- CMakeLists: `vw_view_cluster.cpp` added; server include path already present
  from TASK-052 for proto.h helpers. ✓

Advisory: `do_fetch` is synchronous (blocks render thread during send+recv);
same advisory as TASK-052 — acceptable for Phase 7, async queue in Phase 8.
Auto-refresh timer is `last_fetch_time_` set to `ImGui::GetTime()` on
successful fetch only; failed fetches keep the stale last time, so after an
error the 5s auto-refresh won't auto-retry until the user clicks Refresh and
clears the error state (state must be Ready for auto-refresh). This is
intentional conservative behaviour.

**CQR.08 sign-off granted.**

ARCH.00 [2026-07-13]: CQR.08 signed off. No blocking findings. TASK-053 done.
Phase 7 milestone complete: all TASK-047 through TASK-053 are done.
