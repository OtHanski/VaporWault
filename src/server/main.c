/*
 * main.c — VaporWault server entry point.
 *
 * On Windows: delegates to vw_winsvc_main(), which tries to register as a
 * Windows Service and falls back to a direct vw_server_main_run() call when
 * launched as a console process.
 *
 * On other platforms: delegates directly to vw_server_main_run().
 */

#include "vw_server_main.h"

#ifdef _WIN32
int vw_winsvc_main(int argc, char *argv[]);
#endif

int main(int argc, char *argv[]) {
#ifdef _WIN32
    return vw_winsvc_main(argc, argv);
#else
    return vw_server_main_run(argc, argv);
#endif
}
