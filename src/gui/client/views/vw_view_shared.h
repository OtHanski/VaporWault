#pragma once
#include "../vw_gui_ipc.h"
class ClientApp;
void vw_view_shared_render(const VwIpcStatus &status, ClientApp &app);

/* Multi-account (TASK-163): see vw_view_browser.h's invalidate doc comment
 * — same render-thread-only caveat applies here. */
void vw_view_shared_invalidate();
