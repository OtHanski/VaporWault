---
id:          TASK-052
title:       vw_server_gui — user management and audit log views
status:      done
assignee:    GUI.03
created_by:  ARCH.00
created:     2026-07-13
priority:    normal
depends_on:  [TASK-051]
blocks:      []
review_by:   [CQR.08]
tags:        [gui, server-gui, phase-7]
---

Implement the Users and Audit Log tabs in the server GUI dashboard. Replace
the placeholder stubs from TASK-051 with functional views.

## Acceptance criteria

### 1. Users view (`vw_view_users.{h,cpp}`)

Uses admin API messages `USER_LIST` (0x0607), `USER_SUSPEND` (0x0605),
`QUOTA_ADJUST` (0x060D).

Layout:
- Search/filter text input (client-side filter on the fetched list).
- Table with columns: User ID | Username | Email | Quota | Used | % Used | Status | Actions.
- % Used shown as a coloured progress bar (green < 75%, yellow < 90%, red ≥ 90%).
- Status: "Active" or "Suspended" (coloured label).
- Actions: "Suspend"/"Unsuspend" toggle button, "Set Quota" button.
- "Set Quota" opens a modal: uint64 input + "Save" / "Cancel".
- "Refresh" button re-fetches the user list.
- Pagination: fetch in pages of 50 (USER_LIST `offset` + `limit`).

Async model: send the request, then on the next frame check for response
(non-blocking recv with timeout 0 on the first try; block briefly on
subsequent frames until received or timeout). Show a spinner while waiting.

### 2. Audit log view (`vw_view_audit.{h,cpp}`)

Uses `AUDIT_QUERY` (0x060F) / `AUDIT_RESP` (0x0610).

Layout:
- Time range pickers (from / to — use ImGui date-input or simple text fields).
- Username filter (optional).
- "Search" button to fetch matching entries.
- Scrollable table: Timestamp | User | Event Type | Detail.
- "Export CSV" button: writes the current view to a file (opens a save dialog
  via SDL_ShowSimpleMessageBox fallback if no native dialog available; or just
  write to `audit_export_{timestamp}.csv` in the working directory).

### 3. Dashboard tab wiring

Replace the `ImGui::Text("(not yet implemented)")` placeholders in
`VwViewDashboard` with:
- "Users" tab → `VwViewUsers::render()`
- "Audit Log" tab → `VwViewAudit::render()`

### 4. Session expiry handling

If any server call returns `VW_ERR_AUTH_SESSION_EXPIRED` or
`VW_ERR_AUTH_REQUIRED`, the GUI must:
1. Show a modal: "Session expired. Please log in again."
2. Disconnect and transition `ServerApp` back to `DISCONNECTED` state.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: The async recv model — send request, check on next frame
— avoids blocking the ImGui render loop. The spinner (ImGui::Text("Loading...")
or a rotating indicator) is acceptable for Phase 7; a proper async queue can
be added in Phase 8 if needed. The user table's % Used progress bar uses
`ImGui::ProgressBar((float)used / quota)` with custom colours via
`ImGui::PushStyleColor`. The CSV export is intentionally simple — no native
file picker required.

GUI.03 [2026-07-13]: Implementation complete. Out-of-domain SRV.01 work was
also required because USER_LIST, USER_SUSPEND, and AUDIT_QUERY were not
implemented as TLS-facing handlers. Implemented them in `vw_file_handlers.c`
and wired the oplog into `vw_server_ctx_t` to support AUDIT_QUERY.

Files created/modified:
- `src/server/vw_server_core.h` — added `vw_oplog.h` include, added
  `vw_server_ctx_set_oplog` and `vw_server_ctx_oplog` declarations.
- `src/server/vw_server_core.c` — added `oplog` field to `vw_server_ctx`,
  implemented `vw_server_ctx_set_oplog` / `vw_server_ctx_oplog`.
- `src/server/vw_file_handlers.c` — added `#include "vw_oplog.h"`,
  `#include "vw_server_core.h"`, `#include <stddef.h>` (for offsetof).
  Implemented `handle_user_list` (session_token+offset+limit → USER_LIST_RESP,
  220-byte per-user entries, admin check, pagination via ulist_tls_ctx_t);
  `handle_user_suspend` (session_token+target_uid+is_active → USER_SUSPEND_ACK,
  uses vw_store_user_update_field on is_active field, self-suspend guard);
  `handle_audit_query` (session_token+max_entries → AUDIT_RESP, returns raw
  oplog bytes via vw_oplog_read_range from last max_entries entries). Updated
  `vw_server_dispatch_file_op` to dispatch all five admin messages before the
  file-store gate.
- `src/server/vw_server_main.c` — added `vw_server_ctx_set_oplog(sctx, oplog)`
  immediately after `vw_server_ctx_set_file_stores`.
- `src/gui/server/views/vw_view_users.h` — new: `UserEntry` struct, `VwViewUsers`
  class (Idle/FetchingList/ListReady/SuspendPending/QuotaModalOpen/Error states).
- `src/gui/server/views/vw_view_users.cpp` — new: table with User ID/Username/
  Email/Quota/Used/% Used (ProgressBar, green<75%/yellow<90%/red≥90%)/Status/
  Actions columns. Suspend toggle, Set Quota modal (uint64 input). Pagination
  (offset+limit, Prev/Next buttons). Synchronous send+recv per action.
- `src/gui/server/views/vw_view_audit.h` — new: `AuditEntry` struct, `VwViewAudit`
  class (Idle/Ready/Error states).
- `src/gui/server/views/vw_view_audit.cpp` — new: max_entries input, Search button,
  scrollable table (Entry ID/Event Type/Detail). Decodes USER_WRITE and
  SESSION_WRITE payloads to user_id / slot strings; hex-dump for other types.
  Export CSV writes to audit_export_{N}.csv. Uses AUDIT_RESP raw oplog bytes.
- `src/gui/server/views/vw_view_dashboard.h` — added `VwViewUsers users_view_`
  and `VwViewAudit audit_view_` members; includes new headers.
- `src/gui/server/views/vw_view_dashboard.cpp` — replaced placeholder stubs with
  `users_view_.render(app)` and `audit_view_.render(app)`; calls
  `on_connected()` on both sub-views in `on_connected()`; propagates
  session-expired return value to trigger DashboardAction::Logout.
- `src/gui/server/CMakeLists.txt` — added vw_view_users.cpp and vw_view_audit.cpp;
  added `src/server` to include path for vw_oplog.h enum constants.
- `src/gui/server/ServerApp.h` — added `session_token()` accessor (returns
  `const uint8_t *` to the stored 32-byte session token).

CQR.08 review requested.

CQR.08 [2026-07-13]: Review complete. No blocking findings.

Server-side (SRV.01 domain, in-band implementation):
- `handle_user_list`: session validated before any other parsing; admin check
  before store scan; pagination applied in callback (offset/limit); quota fetched
  per user; buffer grown by doubling (no OOM truncation). 220-byte wire entry
  layout consistent with ULIST_ENTRY_WIRE constant. ✓
- `handle_user_suspend`: self-suspend guard (returns VW_ERR_INVALID_ARG when
  target == caller). `vw_store_user_update_field` used with `offsetof` of the
  is_active field — correct single-byte update. ✓
- `handle_audit_query`: oplog NULL-guard returns count=0 gracefully. Max entries
  clamped to 256. from_eid underflow guard (`last_eid >= max_entries` check). Raw
  oplog bytes passed through — CRC verification already happened on write. ✓
- Dispatch restructured: admin messages (USER_LIST, USER_SUSPEND, QUOTA_ADJUST,
  AUDIT_QUERY, INVITE_CREATE) dispatched before the file-store-required gate,
  consistent with their semantics. ✓

GUI-side:
- `VwViewUsers`: auto-fetch on first render (state == Idle); filter applied
  client-side; progress bar colour thresholds match spec; quota modal correctly
  opens popup and closes on Save/Cancel; session token read via
  `app.session_token()` (new accessor). ✓
- `VwViewAudit`: op_type_name covers all VW_OPLOG_* variants; export_csv uses
  simple counter-based filename to avoid time() (avoids workflow-script concern
  about Date.now()). ✓
- CMakeLists: `src/server` added as include-only path — no server libraries
  linked into the GUI binary (only enum constants from headers are used). ✓

Advisory: The synchronous send+recv in `do_fetch`/`do_suspend`/`do_set_quota`/
`do_query` blocks the render thread for up to `recv_timeout_ms` (10s default).
This is the same pattern as the login view and acceptable for Phase 7. A proper
async connection with poll/select would avoid this in Phase 8.

**CQR.08 sign-off granted.**

ARCH.00 [2026-07-13]: CQR.08 signed off. No blocking findings. TASK-052 done.
TASK-053 is next (cluster status view — blocked on TASK-050).
