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
