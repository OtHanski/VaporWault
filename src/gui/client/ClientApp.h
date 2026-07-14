#pragma once

/*
 * ClientApp — top-level application state for the VaporWault client GUI.
 *
 * Owns the IPC connection and view dispatch. A background thread polls the
 * daemon status every 2 seconds. All shared state is guarded by status_mutex_.
 * The render thread may read cached_status_ without a lock only for display;
 * it must hold the lock to call any VwGuiIpc method.
 */

#include "vw_gui_ipc.h"
#include <SDL.h>
#include <mutex>
#include <atomic>
#include <cstdint>

enum class AppView { Login, Browser, Queue, Settings };

class ClientApp {
public:
    ClientApp();
    ~ClientApp();

    ClientApp(const ClientApp &) = delete;
    ClientApp &operator=(const ClientApp &) = delete;

    /* Call once after SDL/ImGui are initialised. Starts the background thread. */
    void start();

    /* Call once per frame — renders the active view. */
    void render_frame();

    /* Call before ImGui/SDL shutdown. Stops the background thread. */
    void stop();

    AppView active_view() const { return active_view_; }

    /* Snapshot of the last status received from the daemon (background-thread updated). */
    VwIpcStatus status_snapshot() {
        std::lock_guard<std::mutex> lk(status_mutex_);
        return cached_status_;
    }

    /* Called by views to request an IPC operation on the render thread.
     * The caller must NOT hold status_mutex_. */
    bool ipc_sync_now();
    bool ipc_pause(const char *folder_root = nullptr);
    bool ipc_resume(const char *folder_root = nullptr);
    bool ipc_shutdown();
    int  ipc_folder_add(const char *local, const char *virt);
    int  ipc_folder_remove(const char *local);

    uint16_t ipc_port = VW_IPC_DEFAULT_PORT;

private:
    VwGuiIpc    ipc_;
    AppView     active_view_ = AppView::Login;

    std::mutex      status_mutex_;
    VwIpcStatus     cached_status_;
    std::atomic_bool poll_running_{false};
    SDL_Thread     *poll_thread_ = nullptr;

    /* Seconds until the next reconnect attempt. */
    float reconnect_timer_ = 0.0f;

    static int poll_thread_func(void *self);
    void poll_loop();
    void try_connect();
    void render_offline_banner();
};
