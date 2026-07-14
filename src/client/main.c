#include "vw_daemon.h"
#include "../core/vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <shlobj.h>   /* SHGetFolderPathA */
#else
#  include <unistd.h>
#  include <pwd.h>
#endif

/*
 * Resolve the default state directory:
 *   Linux/macOS : $XDG_STATE_HOME/vapourwault   (fallback: ~/.local/state/vapourwault)
 *   Windows     : %LOCALAPPDATA%\VaporWault
 */
static void default_state_dir(char *out, size_t outsz) {
#ifdef _WIN32
    char base[512] = "";
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base);
    snprintf(out, outsz, "%s\\VaporWault", base);
#else
    const char *xdg = getenv("XDG_STATE_HOME");
    if (xdg && xdg[0]) {
        snprintf(out, outsz, "%s/vapourwault", xdg);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : "/tmp";
        }
        snprintf(out, outsz, "%s/.local/state/vapourwault", home);
    }
#endif
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--daemon] [--state-dir <dir>]\n"
            "\n"
            "  --daemon          Daemonize (Linux only; Windows: foreground)\n"
            "  --state-dir <dir> Override default state directory\n"
            "\n"
            "Default state dir:\n"
#ifdef _WIN32
            "  %%LOCALAPPDATA%%\\VaporWault\n"
#else
            "  $XDG_STATE_HOME/vapourwault  (or ~/.local/state/vapourwault)\n"
#endif
            , prog);
}

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    char state_dir[512] = "";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            snprintf(state_dir, sizeof(state_dir), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!state_dir[0]) default_state_dir(state_dir, sizeof(state_dir));

    vw_daemon_cfg_t cfg;
    vw_err_t err = vw_daemon_cfg_load(state_dir, &cfg);
    if (err != VW_OK) {
        fprintf(stderr, "Failed to load config: %d\n", (int)err);
        return 1;
    }

    /* Write defaults if no config file exists yet */
    (void)vw_daemon_cfg_write_defaults(state_dir, &cfg);

    err = vw_daemon_run(&cfg, daemon_mode);
    return err == VW_OK ? 0 : 1;
}
