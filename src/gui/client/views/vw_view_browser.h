#pragma once
#include "../vw_gui_ipc.h"
class ClientApp;
void vw_view_browser_render(const VwIpcStatus &status, ClientApp &app);

/* Multi-account (TASK-163): force a refetch on the next render, for the
 * newly-active account. Render-thread only — call only from code paths
 * that run on the render thread (e.g. the account switcher), never from
 * ClientApp's background poll thread, which does not hold this file's
 * (unguarded, render-thread-only-by-convention) static view state. */
void vw_view_browser_invalidate();
