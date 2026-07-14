#include "vw_client_cli.h"
#include "vw_ipc.h"

int main(int argc, char *argv[]) {
    return vw_client_cli_main(argc, argv, VW_IPC_DEFAULT_PORT);
}
