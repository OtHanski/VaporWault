#pragma once
#include "../vw_gui_ipc.h"
class ClientApp;
void vw_view_settings_render(const VwIpcStatus &status, ClientApp &app);

/* Reset this view's cached per-account state (folders, notification
 * preferences, account email) so the next render re-fetches from the
 * now-active account instead of showing stale data left over from
 * whichever account was active before (TASK-221). */
void vw_view_settings_invalidate();
