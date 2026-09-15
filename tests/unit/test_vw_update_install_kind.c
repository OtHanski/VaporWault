/*
 * test_vw_update_install_kind.c — unit tests for TASK-00295's
 * vw_update_detect_install_kind().
 *
 * The function under test resolves the CURRENTLY RUNNING binary's own
 * directory (GetModuleFileNameA / /proc/self/exe) — there is no injection
 * point for "pretend this is a different directory." So this test uses
 * the one thing that's always true: whatever directory this test binary
 * itself is running from IS the directory vw_update_detect_install_kind()
 * will look in when called from this same process. It resolves that
 * directory independently (its own small self-path lookup, not sharing
 * code with the function under test — an independent check, not a
 * tautology) and creates/removes the real ".vw-portable" marker file
 * there across each test case.
 *
 * TC-1: no marker (the normal state right after a build) -> PACKAGE_OR_UNKNOWN
 * TC-2: marker created -> PORTABLE
 * TC-3: marker removed again -> PACKAGE_OR_UNKNOWN (not stuck PORTABLE)
 */

#include "vw_test.h"
#include "vw_client_core.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

static void self_exe_dir_for_test(char *out, size_t out_sz) {
#ifdef _WIN32
    char exe_path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
    VW_ASSERT(n > 0 && n < sizeof(exe_path));
    char *slash = strrchr(exe_path, '\\');
    VW_ASSERT(slash != NULL);
    *slash = '\0';
    snprintf(out, out_sz, "%s", exe_path);
#else
    char exe_path[4096];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    VW_ASSERT(n > 0 && (size_t)n < sizeof(exe_path));
    exe_path[n] = '\0';
    char *slash = strrchr(exe_path, '/');
    VW_ASSERT(slash != NULL);
    *slash = '\0';
    snprintf(out, out_sz, "%s", exe_path);
#endif
}

static void marker_path_for_test(char *out, size_t out_sz) {
    char dir[4096];
    self_exe_dir_for_test(dir, sizeof(dir));
#ifdef _WIN32
    snprintf(out, out_sz, "%s\\.vw-portable", dir);
#else
    snprintf(out, out_sz, "%s/.vw-portable", dir);
#endif
}

VW_TEST_SUITE("vw_update_install_kind") {

    char marker[4096];
    marker_path_for_test(marker, sizeof(marker));

    /* Ensure a clean slate regardless of what a prior failed run left
     * behind — remove() on a nonexistent file is a harmless no-op here. */
    remove(marker);

    VW_TEST_CASE("no marker present -> PACKAGE_OR_UNKNOWN") {
        VW_ASSERT_EQ((int)vw_update_detect_install_kind(),
                      (int)VW_UPDATE_KIND_PACKAGE_OR_UNKNOWN);
    }

    VW_TEST_CASE("marker present -> PORTABLE") {
        FILE *f = fopen(marker, "wb");
        VW_ASSERT(f != NULL);
        fclose(f);

        VW_ASSERT_EQ((int)vw_update_detect_install_kind(),
                      (int)VW_UPDATE_KIND_PORTABLE);

        remove(marker);
    }

    VW_TEST_CASE("marker removed again -> back to PACKAGE_OR_UNKNOWN") {
        /* Belt-and-braces: the previous case already removed it, but this
         * proves the function isn't caching/sticky across calls. */
        VW_ASSERT_EQ((int)vw_update_detect_install_kind(),
                      (int)VW_UPDATE_KIND_PACKAGE_OR_UNKNOWN);
    }
}
VW_TEST_SUITE_END()
