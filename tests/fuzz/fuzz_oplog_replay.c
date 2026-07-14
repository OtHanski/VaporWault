/*
 * fuzz_oplog_replay.c — libFuzzer target for the oplog segment file parser.
 *
 * Strategy:
 *   1. Create a temp directory <tmpdir>/oplog/.
 *   2. Write the fuzzer's bytes as segment file 0000000000000001.log.
 *   3. Call vw_oplog_open(tmpdir, &ctx) — exercises seg_scan (crash recovery,
 *      CRC validation, truncation of unconfirmed tail entries).
 *   4. Call vw_oplog_replay_from(ctx, 1, cb, NULL) — exercises sequential
 *      read of every confirmed entry.
 *   5. Call vw_oplog_close(ctx) and rm -rf tmpdir.
 *
 * This exercises the core oplog parser (entry header decode, CRC32 check,
 * confirmed/unconfirmed classification, payload length bounds) without
 * requiring a network connection or running server.
 *
 */

#include "vw_oplog.h"   /* vw_oplog_open/close/replay_from; pulls in vw_err_t */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── Portable temp directory ─────────────────────────────────────────────── */

#ifdef _WIN32
#  include <windows.h>
#  include <direct.h>
static int make_tmpdir(char *buf, size_t bufsz) {
    char tmp[MAX_PATH];
    if (!GetTempPathA((DWORD)sizeof(tmp), tmp)) return -1;
    UINT r = GetTempFileNameA(tmp, "vwfz", 0, buf);
    if (!r) return -1;
    DeleteFileA(buf);
    if (_mkdir(buf) != 0) return -1;
    return 0;
}
static void rm_rf(const char *dir) {
    /* Simplified: ShFileOperation is complex; just leak on Windows fuzz builds. */
    (void)dir;
}
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <ftw.h>
static int rm_rf_cb(const char *path, const struct stat *sb, int typeflag,
                    struct FTW *fi) {
    (void)sb; (void)typeflag; (void)fi;
    return remove(path);
}
static void rm_rf(const char *dir) {
    nftw(dir, rm_rf_cb, 32, FTW_DEPTH | FTW_PHYS);
}
static int make_tmpdir(char *buf, size_t bufsz) {
    const char *base = getenv("TMPDIR");
    if (!base) base = "/tmp";
    snprintf(buf, bufsz, "%s/vwfz_XXXXXX", base);
    if (!mkdtemp(buf)) return -1;
    return 0;
}
#endif

/* ── No-op replay callback ───────────────────────────────────────────────── */

static int noop_cb(uint64_t entry_id, vw_oplog_op_t op_type,
                   const void *payload, uint32_t payload_len, void *ud)
{
    (void)entry_id; (void)op_type; (void)payload; (void)payload_len; (void)ud;
    return 0;
}

/* ── libFuzzer entry point ────────────────────────────────────────────────── */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char tmpdir[512];
    if (make_tmpdir(tmpdir, sizeof(tmpdir)) != 0) return 0;

    /* Create {tmpdir}/oplog/ */
    char oplogdir[600];
    snprintf(oplogdir, sizeof(oplogdir), "%s/oplog", tmpdir);
#ifdef _WIN32
    _mkdir(oplogdir);
#else
    mkdir(oplogdir, 0700);
#endif

    /* Write fuzzer bytes as first segment: 0000000000000001.log */
    char segpath[700];
    snprintf(segpath, sizeof(segpath), "%s/0000000000000001.log", oplogdir);

    FILE *f = fopen(segpath, "wb");
    if (!f) { rm_rf(tmpdir); return 0; }
    if (size > 0) fwrite(data, 1, size, f);
    fclose(f);

    /* Open oplog — exercises seg_scan crash recovery and CRC validation */
    vw_oplog_t *oplog = NULL;
    vw_err_t rc = vw_oplog_open(tmpdir, &oplog);
    if (rc == VW_OK && oplog) {
        /* Replay from start — exercises sequential entry read */
        vw_oplog_replay_from(oplog, 1, noop_cb, NULL);
        vw_oplog_close(oplog);
    }

    rm_rf(tmpdir);
    return 0;
}
