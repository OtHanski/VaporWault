#ifndef VW_CLIENT_CLI_H
#define VW_CLIENT_CLI_H

/*
 * vw_client_cli — thin CLI frontend for the VaporWault daemon.
 *
 * Connects to the running daemon via IPC and dispatches subcommands.
 * No direct server connection; all operations go through the daemon.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse argv and dispatch the subcommand to the daemon via IPC.
 *
 * ipc_port_default: port to use unless overridden by --ipc-port.
 * Returns 0 on success, 1 on error (error already printed to stderr).
 */
int vw_client_cli_main(int argc, char *argv[], uint16_t ipc_port_default);

#ifdef __cplusplus
}
#endif

#endif /* VW_CLIENT_CLI_H */
