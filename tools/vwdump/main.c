/*
 * vwdump — VaporWault storage diagnostic tool.
 *
 * Scans a server data_dir and reports storage statistics.
 * Read-only; does not modify any data.
 *
 * Usage: vwdump --data-dir <path>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <dirent.h>
#  include <sys/stat.h>
#endif

/* ── Helpers ─────────────────────────────────────────────────────────────────*/

static void human_size(uint64_t bytes, char *buf, size_t bufsz)
{
    if (bytes < 1024ULL)
        snprintf(buf, bufsz, "%llu B",   (unsigned long long)bytes);
    else if (bytes < 1024ULL * 1024)
        snprintf(buf, bufsz, "%.1f KiB", (double)bytes / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, bufsz, "%.1f MiB", (double)bytes / (1024.0 * 1024.0));
    else
        snprintf(buf, bufsz, "%.2f GiB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
}

/* Count regular files in path (non-recursive) and accumulate their sizes. */
#ifdef _WIN32
static void scan_dir(const char *path, uint64_t *count, uint64_t *total_bytes)
{
    char pattern[4096];
    snprintf(pattern, sizeof(pattern), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        (*count)++;
        ULARGE_INTEGER sz;
        sz.LowPart  = fd.nFileSizeLow;
        sz.HighPart = fd.nFileSizeHigh;
        *total_bytes += sz.QuadPart;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static uint64_t single_file_size(const char *path)
{
    WIN32_FILE_ATTRIBUTE_DATA fi;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fi)) return 0;
    ULARGE_INTEGER sz;
    sz.LowPart  = fi.nFileSizeLow;
    sz.HighPart = fi.nFileSizeHigh;
    return sz.QuadPart;
}
#else
static void scan_dir(const char *path, uint64_t *count, uint64_t *total_bytes)
{
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char fpath[4096];
        snprintf(fpath, sizeof(fpath), "%s/%s", path, e->d_name);
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        (*count)++;
        *total_bytes += (uint64_t)st.st_size;
    }
    closedir(d);
}

static uint64_t single_file_size(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) ? (uint64_t)st.st_size : 0;
}
#endif

/* ── Main ────────────────────────────────────────────────────────────────────*/

int main(int argc, char *argv[])
{
    const char *data_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--data-dir") == 0 ||
             strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            printf("Usage: vwdump --data-dir <path>\n");
            printf("  Scan a VaporWault server data directory and report"
                   " storage statistics.\n");
            return 0;
        } else {
            fprintf(stderr, "vwdump: unknown argument: %s\n", argv[i]);
            fprintf(stderr, "Usage: vwdump --data-dir <path>\n");
            return 1;
        }
    }

    if (!data_dir) {
        fprintf(stderr, "vwdump: --data-dir is required\n");
        fprintf(stderr, "Usage: vwdump --data-dir <path>\n");
        return 1;
    }

    printf("VaporWault storage summary: %s\n", data_dir);
    printf("%-12s  %10s  %s\n", "Component", "Files", "Size");
    printf("%-12s  %10s  %s\n", "---------", "-----", "----");

    char path[4096];
    char sz[32];
    uint64_t grand_total = 0;

    /* Content-addressed chunk store */
    snprintf(path, sizeof(path), "%s/chunks", data_dir);
    uint64_t chunk_count = 0, chunk_bytes = 0;
    scan_dir(path, &chunk_count, &chunk_bytes);
    human_size(chunk_bytes, sz, sizeof(sz));
    printf("%-12s  %10llu  %s\n", "chunks", (unsigned long long)chunk_count, sz);
    grand_total += chunk_bytes;

    /* Operation log segments */
    snprintf(path, sizeof(path), "%s/oplog", data_dir);
    uint64_t oplog_segs = 0, oplog_bytes = 0;
    scan_dir(path, &oplog_segs, &oplog_bytes);
    human_size(oplog_bytes, sz, sizeof(sz));
    printf("%-12s  %10llu  %s\n", "oplog", (unsigned long long)oplog_segs, sz);
    grand_total += oplog_bytes;

    /* Flat-file databases */
    const char *dbs[] = { "refcounts.db", "users.db", "nodes.db", NULL };
    for (int i = 0; dbs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", data_dir, dbs[i]);
        uint64_t fsz = single_file_size(path);
        if (fsz == 0) continue;   /* file absent — skip */
        human_size(fsz, sz, sizeof(sz));
        char label[20];
        snprintf(label, sizeof(label), "%s", dbs[i]);
        /* strip .db suffix for display */
        char *dot = strrchr(label, '.');
        if (dot) *dot = '\0';
        printf("%-12s  %10s  %s\n", label, "--", sz);
        grand_total += fsz;
    }

    printf("%-12s  %10s  %s\n", "---------", "-----", "----");
    human_size(grand_total, sz, sizeof(sz));
    printf("%-12s  %10s  %s\n", "TOTAL", "", sz);

    return 0;
}
