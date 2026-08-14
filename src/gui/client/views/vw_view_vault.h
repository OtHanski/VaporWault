#pragma once
#include "../vw_gui_ipc.h"
class ClientApp;
void vw_view_vault_render(const VwIpcStatus &status, ClientApp &app);

/*
 * Whether vault_id has been created/unlocked from THIS GUI process since
 * it started. This is a client-side hint only, not authoritative — the
 * daemon may already hold vault_id unlocked from an earlier GUI session
 * or CLI use that this process doesn't know about (there is no IPC query
 * for "is this vault currently unlocked in the daemon"). A false negative
 * here just means an extra, harmless re-unlock prompt; it is never wrong
 * in the unsafe direction (it never claims a vault is unlocked when it
 * isn't). Used by vw_view_browser.cpp's "Decrypt & Download..." action to
 * decide whether to attempt a download directly or point the user at the
 * Vault tab first.
 */
bool vw_view_vault_is_unlocked(uint64_t vault_id);

/* Multi-account (TASK-163): see vw_view_browser.h's invalidate doc comment
 * — same render-thread-only caveat applies here. Also clears the
 * unlocked-vault hint set above, since vault_id numbering is server-
 * assigned per-server and a different account may be on a different
 * server entirely — a stale hint here could wrongly claim a same-numbered
 * vault on the new account's server is already unlocked. */
void vw_view_vault_invalidate();
