#ifndef VW_SERVER_CLI_H
#define VW_SERVER_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Entry point for the vapourwault-server-cli binary.
 * Returns 0 on success, 1 on error.
 */
int vw_server_cli_main(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* VW_SERVER_CLI_H */
