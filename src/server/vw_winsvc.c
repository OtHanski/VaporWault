/*
 * vw_winsvc.c — Windows Service Control Manager integration for vapourwaultd.
 *
 * Compiled only on Windows.  Adds a WinMain / service entry point that:
 *   1. Attempts StartServiceCtrlDispatcher.
 *   2. If that fails with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, the binary
 *      is running as a regular console process — falls through to the normal
 *      vw_server_main_run() path.
 *
 * Service control:
 *   SERVICE_CONTROL_STOP / SERVICE_CONTROL_SHUTDOWN  → vw_server_main_request_stop()
 *   SERVICE_CONTROL_PARAMCHANGE (i.e. config reload)  → reload request flag
 *     (not yet implemented; handled gracefully by returning NO_ERROR)
 *
 * Registration / removal (as Administrator):
 *   sc create VaporWault binPath= "C:\...\vapourwaultd.exe --config C:\...\server.conf" start= auto
 *   sc delete VaporWault
 * Or use the PowerShell installer: Install-VaporWault.ps1
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#include "vw_server_main.h"

/* ── Globals ─────────────────────────────────────────────────────────────── */

static SERVICE_STATUS_HANDLE g_svc_handle    = NULL;
static SERVICE_STATUS        g_svc_status;

/* Saved argv from main() for passing to vw_server_main_run() in ServiceMain. */
static int    g_argc = 0;
static char **g_argv = NULL;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void report_status(DWORD current_state, DWORD win32_exit_code,
                           DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    g_svc_status.dwCurrentState  = current_state;
    g_svc_status.dwWin32ExitCode = win32_exit_code;
    g_svc_status.dwWaitHint      = wait_hint;

    if (current_state == SERVICE_START_PENDING)
        g_svc_status.dwControlsAccepted = 0;
    else
        g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP
                                         | SERVICE_ACCEPT_SHUTDOWN;

    if (current_state == SERVICE_RUNNING ||
        current_state == SERVICE_STOPPED)
        g_svc_status.dwCheckPoint = 0;
    else
        g_svc_status.dwCheckPoint = checkpoint++;

    SetServiceStatus(g_svc_handle, &g_svc_status);
}

/* ── Service control handler ─────────────────────────────────────────────── */

static DWORD WINAPI svc_handler(DWORD control, DWORD event_type,
                                 LPVOID event_data, LPVOID context)
{
    (void)event_type; (void)event_data; (void)context;

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        vw_server_main_request_stop();
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* ── ServiceMain ─────────────────────────────────────────────────────────── */

static VOID WINAPI svc_main(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv; /* SCM passes its own argc/argv; use g_argc/g_argv */

    g_svc_handle = RegisterServiceCtrlHandlerExA(
        "VaporWault", svc_handler, NULL);
    if (!g_svc_handle) return;

    g_svc_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwServiceSpecificExitCode = 0;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* Run the server.  Blocks until shutdown or fatal error. */
    int rc = vw_server_main_run(g_argc, g_argv);

    report_status(SERVICE_STOPPED,
                  rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
                  0);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

/*
 * vw_winsvc_main() replaces main() on Windows.  It is called from main.c via
 * the conditional below.  Keeping it non-static makes it easy to test.
 *
 * Behaviour:
 *   - Running as Windows Service: StartServiceCtrlDispatcher succeeds; svc_main
 *     is invoked by the SCM and calls vw_server_main_run().
 *   - Running as console app: StartServiceCtrlDispatcher fails with
 *     ERROR_FAILED_SERVICE_CONTROLLER_CONNECT; we fall through to a direct call
 *     of vw_server_main_run().
 */
int vw_winsvc_main(int argc, char *argv[])
{
    g_argc = argc;
    g_argv = argv;

    static SERVICE_TABLE_ENTRYA dispatch_table[] = {
        { (LPSTR)"VaporWault", svc_main },
        { NULL,                 NULL     }
    };

    if (!StartServiceCtrlDispatcherA(dispatch_table)) {
        DWORD err = GetLastError();
        if (err != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Unexpected SCM error — report and exit. */
            fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n",
                    (unsigned long)err);
            return 1;
        }
        /* Not running as a service — run as a normal console process. */
        return vw_server_main_run(argc, argv);
    }

    /* Returned from StartServiceCtrlDispatcherA — all cleanup done. */
    return 0;
}

#endif /* _WIN32 */
