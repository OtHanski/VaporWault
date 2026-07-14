/*
 * vw_watch_windows.c — ReadDirectoryChangesW filesystem watcher (Windows only).
 *
 * Pull model: caller calls vw_watcher_wait() + vw_watcher_drain().
 * Each root added via vw_watcher_add gets one overlapped I/O watch handle.
 * Ring buffer is CRITICAL_SECTION-protected.
 */

#ifdef _WIN32

#include "vw_watch.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Per-root watch state ────────────────────────────────────────────────── */

#define RDCW_BUF_SIZE 65536u

typedef struct {
    HANDLE     dir_handle;
    HANDLE     event;      /* manual-reset event for overlapped I/O */
    OVERLAPPED ov;
    char       root[512];  /* absolute local root path (UTF-8) */
    uint8_t    buf[RDCW_BUF_SIZE];
    int        pending;    /* 1 = ReadDirectoryChangesW outstanding */
} watch_root_t;

/* ── Ring helpers ────────────────────────────────────────────────────────── */

static uint32_t ring_next(uint32_t idx, uint32_t cap) { return (idx + 1) % cap; }
static int ring_full(uint32_t h, uint32_t t, uint32_t cap) {
    return ring_next(t, cap) == h;
}
static int ring_empty(uint32_t h, uint32_t t) { return h == t; }

/* ── vw_watcher struct ───────────────────────────────────────────────────── */

struct vw_watcher {
    CRITICAL_SECTION  mu;
    vw_watch_event_t *ring;
    uint32_t          cap;
    uint32_t          head;
    uint32_t          tail;
    int               overflow;

    watch_root_t *roots;
    uint32_t      nroots;
    uint32_t      roots_cap;
};

/* ── Ring push (caller holds mu) ─────────────────────────────────────────── */

static void ring_push(struct vw_watcher *w, const vw_watch_event_t *ev)
{
    uint32_t i;

    if (ev->type == VW_WATCH_MODIFIED) {
        i = w->head;
        while (i != w->tail) {
            if (w->ring[i].type == VW_WATCH_MODIFIED &&
                strncmp(w->ring[i].path, ev->path, 1023) == 0)
                return;
            i = ring_next(i, w->cap);
        }
    }

    if (ring_full(w->head, w->tail, w->cap)) {
        w->overflow = 1;
        w->head = ring_next(w->head, w->cap);
    }
    w->ring[w->tail] = *ev;
    w->tail = ring_next(w->tail, w->cap);
}

/* ── Issue ReadDirectoryChangesW for a root ──────────────────────────────── */

static int rdcw_issue(watch_root_t *r)
{
    DWORD flags = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE;
    ResetEvent(r->event);
    memset(&r->ov, 0, sizeof(r->ov));
    r->ov.hEvent = r->event;
    if (!ReadDirectoryChangesW(r->dir_handle, r->buf, RDCW_BUF_SIZE,
                                TRUE, flags, NULL, &r->ov, NULL))
        return -1;
    r->pending = 1;
    return 0;
}

/* ── Drain completed ReadDirectoryChangesW results into ring ─────────────── */

static void process_root(struct vw_watcher *w, watch_root_t *r)
{
    DWORD bytes = 0;
    FILE_NOTIFY_INFORMATION *fni;
    char *p;
    int has_rename_old = 0;
    char rename_old[1024];

    if (!r->pending) return;
    if (!GetOverlappedResult(r->dir_handle, &r->ov, &bytes, FALSE))
        goto reissue;

    r->pending = 0;
    p = (char *)r->buf;

    for (;;) {
        fni = (FILE_NOTIFY_INFORMATION *)p;
        if (fni->FileNameLength > 0) {
            /* Convert wide filename to UTF-8. */
            char rel[512];
            int wlen = (int)(fni->FileNameLength / sizeof(WCHAR));
            int n = WideCharToMultiByte(CP_UTF8, 0,
                                         fni->FileName, wlen,
                                         rel, sizeof(rel) - 1, NULL, NULL);
            if (n > 0 && n < (int)sizeof(rel)) {
                rel[n] = '\0';
                /* Replace backslashes. */
                for (int i = 0; i < n; i++) if (rel[i] == '\\') rel[i] = '/';

                char fullpath[1024];
                int sn = snprintf(fullpath, sizeof(fullpath), "%s/%s",
                                  r->root, rel);
                if (sn > 0 && sn < (int)sizeof(fullpath)) {
                    vw_watch_event_t ev;
                    memset(&ev, 0, sizeof(ev));
                    strncpy(ev.path, fullpath, 1023);

                    switch (fni->Action) {
                    case FILE_ACTION_ADDED:
                        ev.type = VW_WATCH_CREATED;
                        ring_push(w, &ev);
                        has_rename_old = 0;
                        break;
                    case FILE_ACTION_REMOVED:
                        ev.type = VW_WATCH_DELETED;
                        ring_push(w, &ev);
                        has_rename_old = 0;
                        break;
                    case FILE_ACTION_MODIFIED:
                        ev.type = VW_WATCH_MODIFIED;
                        ring_push(w, &ev);
                        has_rename_old = 0;
                        break;
                    case FILE_ACTION_RENAMED_OLD_NAME:
                        strncpy(rename_old, fullpath, 1023);
                        rename_old[1023] = '\0';
                        has_rename_old = 1;
                        break;
                    case FILE_ACTION_RENAMED_NEW_NAME:
                        if (has_rename_old) {
                            ev.type = VW_WATCH_MOVED;
                            strncpy(ev.old_path, rename_old, 1023);
                            ring_push(w, &ev);
                        } else {
                            ev.type = VW_WATCH_CREATED;
                            ring_push(w, &ev);
                        }
                        has_rename_old = 0;
                        break;
                    default:
                        has_rename_old = 0;
                        break;
                    }
                }
            }
        }

        if (fni->NextEntryOffset == 0) break;
        p += fni->NextEntryOffset;
    }

reissue:
    rdcw_issue(r);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_watcher_open(uint32_t max_events, vw_watcher_t **out)
{
    struct vw_watcher *w;

    if (!out) return VW_ERR_INVALID_ARG;
    if (max_events < 256) max_events = 256;

    w = (struct vw_watcher *)calloc(1, sizeof(*w));
    if (!w) return VW_ERR_OOM;

    InitializeCriticalSection(&w->mu);

    w->ring = (vw_watch_event_t *)calloc(max_events + 1, sizeof(*w->ring));
    if (!w->ring) {
        DeleteCriticalSection(&w->mu);
        free(w);
        return VW_ERR_OOM;
    }
    w->cap = max_events + 1;

    *out = w;
    return VW_OK;
}

vw_err_t vw_watcher_add(vw_watcher_t *w, const char *path)
{
    watch_root_t *r;

    if (!w || !path) return VW_ERR_INVALID_ARG;

    /* Convert path to wide string for CreateFileW. */
    wchar_t wpath[512];
    int wn = MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                                   (int)(sizeof(wpath) / sizeof(wchar_t)));
    if (wn <= 0) return VW_ERR_INVALID_ARG;

    HANDLE dh = CreateFileW(wpath,
                             FILE_LIST_DIRECTORY,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                             NULL);
    if (dh == INVALID_HANDLE_VALUE)
        return (GetLastError() == ERROR_FILE_NOT_FOUND ||
                GetLastError() == ERROR_PATH_NOT_FOUND)
               ? VW_ERR_NOT_FOUND : VW_ERR_IO;

    HANDLE ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ev) { CloseHandle(dh); return VW_ERR_IO; }

    EnterCriticalSection(&w->mu);

    if (w->nroots >= w->roots_cap) {
        uint32_t nc = w->roots_cap ? w->roots_cap * 2 : 4;
        watch_root_t *p = (watch_root_t *)realloc(w->roots, nc * sizeof(*p));
        if (!p) {
            LeaveCriticalSection(&w->mu);
            CloseHandle(ev); CloseHandle(dh);
            return VW_ERR_OOM;
        }
        w->roots = p;
        w->roots_cap = nc;
    }

    r = &w->roots[w->nroots++];
    memset(r, 0, sizeof(*r));
    r->dir_handle = dh;
    r->event = ev;
    strncpy(r->root, path, 511);
    r->root[511] = '\0';

    if (rdcw_issue(r) != 0) {
        CloseHandle(ev); CloseHandle(dh);
        w->nroots--;
        LeaveCriticalSection(&w->mu);
        return VW_ERR_IO;
    }

    LeaveCriticalSection(&w->mu);
    return VW_OK;
}

vw_err_t vw_watcher_remove(vw_watcher_t *w, const char *path)
{
    uint32_t i;

    if (!w || !path) return VW_ERR_INVALID_ARG;

    EnterCriticalSection(&w->mu);
    for (i = 0; i < w->nroots; i++) {
        if (strncmp(w->roots[i].root, path, 511) == 0) {
            CancelIo(w->roots[i].dir_handle);
            CloseHandle(w->roots[i].event);
            CloseHandle(w->roots[i].dir_handle);
            w->roots[i] = w->roots[--w->nroots];
            LeaveCriticalSection(&w->mu);
            return VW_OK;
        }
    }
    LeaveCriticalSection(&w->mu);
    return VW_ERR_NOT_FOUND;
}

vw_err_t vw_watcher_wait(vw_watcher_t *w, uint32_t timeout_ms)
{
    HANDLE events[MAXIMUM_WAIT_OBJECTS];
    DWORD n = 0;
    DWORD ret;
    uint32_t i;

    if (!w) return VW_ERR_INVALID_ARG;

    EnterCriticalSection(&w->mu);
    for (i = 0; i < w->nroots && n < MAXIMUM_WAIT_OBJECTS; i++)
        events[n++] = w->roots[i].event;
    LeaveCriticalSection(&w->mu);

    if (n == 0) {
        if (timeout_ms > 0) Sleep(timeout_ms);
        return VW_ERR_TIMEOUT;
    }

    ret = WaitForMultipleObjects(n, events, FALSE,
                                  timeout_ms == 0 ? INFINITE : timeout_ms);
    if (ret == WAIT_TIMEOUT) return VW_ERR_TIMEOUT;
    if (ret >= WAIT_OBJECT_0 && ret < WAIT_OBJECT_0 + n) return VW_OK;
    return VW_ERR_IO;
}

vw_err_t vw_watcher_drain(vw_watcher_t *w,
                            vw_watch_event_t *out_events, uint32_t *count)
{
    uint32_t i, n, max;

    if (!w || !out_events || !count) return VW_ERR_INVALID_ARG;
    max = *count;
    *count = 0;

    EnterCriticalSection(&w->mu);
    /* Process all roots that have signalled. */
    for (i = 0; i < w->nroots; i++) {
        if (w->roots[i].pending &&
            WaitForSingleObject(w->roots[i].event, 0) == WAIT_OBJECT_0)
        {
            process_root(w, &w->roots[i]);
        }
    }
    n = 0;
    while (n < max && !ring_empty(w->head, w->tail)) {
        out_events[n++] = w->ring[w->head];
        w->head = ring_next(w->head, w->cap);
    }
    *count = n;
    LeaveCriticalSection(&w->mu);
    return VW_OK;
}

int vw_watcher_overflowed(vw_watcher_t *w)
{
    int v;
    if (!w) return 0;
    EnterCriticalSection(&w->mu);
    v = w->overflow;
    w->overflow = 0;
    LeaveCriticalSection(&w->mu);
    return v;
}

void vw_watcher_close(vw_watcher_t *w)
{
    uint32_t i;
    if (!w) return;
    for (i = 0; i < w->nroots; i++) {
        CancelIo(w->roots[i].dir_handle);
        CloseHandle(w->roots[i].event);
        CloseHandle(w->roots[i].dir_handle);
    }
    free(w->roots);
    DeleteCriticalSection(&w->mu);
    free(w->ring);
    free(w);
}

#endif /* _WIN32 */
