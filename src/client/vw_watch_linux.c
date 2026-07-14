/*
 * vw_watch_linux.c — inotify-based filesystem watcher (Linux only).
 *
 * Pull model: caller calls vw_watcher_wait() + vw_watcher_drain().
 * Ring buffer is mutex-protected. Event deduplication coalesces repeated
 * MODIFIED events for the same path. Ring overflow drops oldest and sets a flag.
 */

#ifdef __linux__

#include "vw_watch.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <limits.h>

/* ── Watch descriptor table ──────────────────────────────────────────────── */

typedef struct {
    int  wd;
    char path[1024]; /* absolute dir path this wd watches */
} wd_entry_t;

/* ── Pending MOVED_FROM for cookie pairing ───────────────────────────────── */

typedef struct {
    uint32_t cookie;
    char     path[1024];
} move_pending_t;

/* ── Ring buffer helpers ─────────────────────────────────────────────────── */

static uint32_t ring_next(uint32_t idx, uint32_t cap) { return (idx + 1) % cap; }
static int ring_full(uint32_t head, uint32_t tail, uint32_t cap) {
    return ring_next(tail, cap) == head;
}
static int ring_empty(uint32_t head, uint32_t tail) { return head == tail; }

/* ── vw_watcher struct ───────────────────────────────────────────────────── */

struct vw_watcher {
    int            ifd;     /* inotify file descriptor */
    pthread_mutex_t mu;

    vw_watch_event_t *ring;
    uint32_t          cap;   /* ring buffer capacity */
    uint32_t          head;  /* next read index */
    uint32_t          tail;  /* next write index */
    int               overflow;

    wd_entry_t *wds;
    uint32_t    wd_count;
    uint32_t    wd_cap;

    move_pending_t *moves;
    uint32_t        move_count;
    uint32_t        move_cap;
};

/* ── wd table helpers ────────────────────────────────────────────────────── */

static const char *wd_find_path(const struct vw_watcher *w, int wd)
{
    uint32_t i;
    for (i = 0; i < w->wd_count; i++) {
        if (w->wds[i].wd == wd) return w->wds[i].path;
    }
    return NULL;
}

static int wd_add(struct vw_watcher *w, int wd, const char *path)
{
    if (w->wd_count >= w->wd_cap) {
        uint32_t new_cap = w->wd_cap ? w->wd_cap * 2 : 16;
        wd_entry_t *p = (wd_entry_t *)realloc(w->wds, new_cap * sizeof(*p));
        if (!p) return -1;
        w->wds = p;
        w->wd_cap = new_cap;
    }
    w->wds[w->wd_count].wd = wd;
    strncpy(w->wds[w->wd_count].path, path, 1023);
    w->wds[w->wd_count].path[1023] = '\0';
    w->wd_count++;
    return 0;
}

static void wd_remove(struct vw_watcher *w, int wd)
{
    uint32_t i;
    for (i = 0; i < w->wd_count; i++) {
        if (w->wds[i].wd == wd) {
            w->wds[i] = w->wds[--w->wd_count];
            return;
        }
    }
}

/* ── Move-pending helpers ────────────────────────────────────────────────── */

static int move_push(struct vw_watcher *w, uint32_t cookie, const char *path)
{
    if (w->move_count >= w->move_cap) {
        uint32_t nc = w->move_cap ? w->move_cap * 2 : 8;
        move_pending_t *p = (move_pending_t *)realloc(w->moves, nc * sizeof(*p));
        if (!p) return -1;
        w->moves = p;
        w->move_cap = nc;
    }
    w->moves[w->move_count].cookie = cookie;
    strncpy(w->moves[w->move_count].path, path, 1023);
    w->moves[w->move_count].path[1023] = '\0';
    w->move_count++;
    return 0;
}

/* Returns 1 and copies path if found; removes entry. Returns 0 if not found. */
static int move_pop(struct vw_watcher *w, uint32_t cookie, char *out_path)
{
    uint32_t i;
    for (i = 0; i < w->move_count; i++) {
        if (w->moves[i].cookie == cookie) {
            strncpy(out_path, w->moves[i].path, 1023);
            out_path[1023] = '\0';
            w->moves[i] = w->moves[--w->move_count];
            return 1;
        }
    }
    return 0;
}

/* ── Ring buffer push ────────────────────────────────────────────────────── */

/* Caller holds mu. Deduplicates MODIFIED. */
static void ring_push(struct vw_watcher *w, const vw_watch_event_t *ev)
{
    uint32_t i;

    /* Deduplicate MODIFIED: scan ring for existing entry. */
    if (ev->type == VW_WATCH_MODIFIED) {
        i = w->head;
        while (i != w->tail) {
            if (w->ring[i].type == VW_WATCH_MODIFIED &&
                strncmp(w->ring[i].path, ev->path, 1023) == 0)
            {
                return; /* already queued */
            }
            i = ring_next(i, w->cap);
        }
    }

    if (ring_full(w->head, w->tail, w->cap)) {
        /* Drop oldest. */
        w->overflow = 1;
        w->head = ring_next(w->head, w->cap);
    }
    w->ring[w->tail] = *ev;
    w->tail = ring_next(w->tail, w->cap);
}

/* ── Recursive add ───────────────────────────────────────────────────────── */

/* Forward declaration. */
static vw_err_t watcher_add_locked(struct vw_watcher *w, const char *path);

static vw_err_t watcher_add_locked(struct vw_watcher *w, const char *path)
{
    uint32_t mask = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM |
                    IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_UNMOUNT;
    int wd;
    DIR *d;
    struct dirent *de;
    char subpath[1024];

    wd = inotify_add_watch(w->ifd, path, mask);
    if (wd < 0) return (errno == ENOENT) ? VW_ERR_NOT_FOUND : VW_ERR_IO;

    /* Replace existing entry if already watched (e.g. after re-create). */
    {
        uint32_t i;
        for (i = 0; i < w->wd_count; i++) {
            if (strncmp(w->wds[i].path, path, 1023) == 0) {
                w->wds[i].wd = wd;
                goto recurse;
            }
        }
    }
    if (wd_add(w, wd, path) != 0) return VW_ERR_OOM;

recurse:
    d = opendir(path);
    if (!d) return VW_OK; /* best-effort — directory may have vanished */
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (de->d_type == DT_DIR) {
            int sn = snprintf(subpath, sizeof(subpath), "%s/%s", path, de->d_name);
            if (sn > 0 && sn < (int)sizeof(subpath))
                watcher_add_locked(w, subpath); /* ignore sub-errors */
        }
    }
    closedir(d);
    return VW_OK;
}

/* ── Read inotify events into ring (caller holds mu) ────────────────────── */

static void drain_inotify(struct vw_watcher *w)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t nread;

    for (;;) {
        nread = read(w->ifd, buf, sizeof(buf));
        if (nread <= 0) break;

        const char *p = buf;
        const char *end = buf + nread;
        while (p + sizeof(struct inotify_event) <= end) {
            const struct inotify_event *ev =
                (const struct inotify_event *)p;
            p += sizeof(struct inotify_event) + ev->len;

            const char *dir = wd_find_path(w, ev->wd);
            if (!dir) continue;

            char fullpath[1024];
            if (ev->len > 0 && ev->name[0] != '\0') {
                int sn = snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, ev->name);
                if (sn <= 0 || sn >= (int)sizeof(fullpath)) continue;
            } else {
                strncpy(fullpath, dir, 1023);
                fullpath[1023] = '\0';
            }

            /* Skip paths that would overflow vw_watch_event_t.path. */
            if (strlen(fullpath) >= 1024) continue;

            vw_watch_event_t out;
            memset(&out, 0, sizeof(out));
            strncpy(out.path, fullpath, 1023);

            if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                if (ev->mask & IN_MOVED_TO) {
                    char old_path[1024];
                    if (move_pop(w, ev->cookie, old_path)) {
                        out.type = VW_WATCH_MOVED;
                        strncpy(out.old_path, old_path, 1023);
                        ring_push(w, &out);
                    } else {
                        out.type = VW_WATCH_CREATED;
                        ring_push(w, &out);
                    }
                } else {
                    out.type = VW_WATCH_CREATED;
                    ring_push(w, &out);
                }
                /* Recursively watch new subdirectories. */
                if (ev->mask & IN_ISDIR) {
                    watcher_add_locked(w, fullpath);
                }
            } else if (ev->mask & IN_MOVED_FROM) {
                move_push(w, ev->cookie, fullpath);
                /* Emit DELETED immediately; if MOVED_TO arrives before drain
                 * we replace it. For simplicity emit DELETED; if a matching
                 * MOVED_TO arrives in the same read batch it fires CREATED.
                 * The spec allows unpaired MOVED_FROM → DELETED. */
                out.type = VW_WATCH_DELETED;
                ring_push(w, &out);
                if (ev->mask & IN_ISDIR) wd_remove(w, ev->wd);
            } else if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                out.type = VW_WATCH_MODIFIED;
                ring_push(w, &out);
            } else if (ev->mask & (IN_DELETE | IN_DELETE_SELF | IN_UNMOUNT)) {
                out.type = VW_WATCH_DELETED;
                ring_push(w, &out);
                if (ev->mask & (IN_DELETE_SELF | IN_UNMOUNT))
                    wd_remove(w, ev->wd);
            }
        }
    }
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_watcher_open(uint32_t max_events, vw_watcher_t **out)
{
    struct vw_watcher *w;

    if (!out) return VW_ERR_INVALID_ARG;
    if (max_events < 256) max_events = 256;

    w = (struct vw_watcher *)calloc(1, sizeof(*w));
    if (!w) return VW_ERR_OOM;

    w->ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (w->ifd < 0) { free(w); return VW_ERR_IO; }

    if (pthread_mutex_init(&w->mu, NULL) != 0) {
        close(w->ifd); free(w); return VW_ERR_IO;
    }

    /* Ring size is max_events + 1 (one slot wasted for full/empty distinction). */
    w->ring = (vw_watch_event_t *)calloc(max_events + 1, sizeof(*w->ring));
    if (!w->ring) {
        pthread_mutex_destroy(&w->mu);
        close(w->ifd); free(w); return VW_ERR_OOM;
    }
    w->cap = max_events + 1;

    *out = w;
    return VW_OK;
}

vw_err_t vw_watcher_add(vw_watcher_t *w, const char *path)
{
    vw_err_t err;
    if (!w || !path) return VW_ERR_INVALID_ARG;
    pthread_mutex_lock(&w->mu);
    err = watcher_add_locked(w, path);
    pthread_mutex_unlock(&w->mu);
    return err;
}

vw_err_t vw_watcher_remove(vw_watcher_t *w, const char *path)
{
    uint32_t i;
    if (!w || !path) return VW_ERR_INVALID_ARG;
    pthread_mutex_lock(&w->mu);
    for (i = 0; i < w->wd_count; i++) {
        if (strncmp(w->wds[i].path, path, 1023) == 0) {
            inotify_rm_watch(w->ifd, w->wds[i].wd);
            wd_remove(w, w->wds[i].wd);
            pthread_mutex_unlock(&w->mu);
            return VW_OK;
        }
    }
    pthread_mutex_unlock(&w->mu);
    return VW_ERR_NOT_FOUND;
}

vw_err_t vw_watcher_wait(vw_watcher_t *w, uint32_t timeout_ms)
{
    struct pollfd pfd;
    int ret;

    if (!w) return VW_ERR_INVALID_ARG;

    pfd.fd = w->ifd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    ret = poll(&pfd, 1, timeout_ms == 0 ? -1 : (int)timeout_ms);
    if (ret < 0) return VW_ERR_IO;
    if (ret == 0) return VW_ERR_TIMEOUT;
    return VW_OK;
}

vw_err_t vw_watcher_drain(vw_watcher_t *w,
                            vw_watch_event_t *out_events, uint32_t *count)
{
    uint32_t n, max;

    if (!w || !out_events || !count) return VW_ERR_INVALID_ARG;
    max = *count;
    *count = 0;

    pthread_mutex_lock(&w->mu);
    drain_inotify(w);
    n = 0;
    while (n < max && !ring_empty(w->head, w->tail)) {
        out_events[n++] = w->ring[w->head];
        w->head = ring_next(w->head, w->cap);
    }
    *count = n;
    pthread_mutex_unlock(&w->mu);
    return VW_OK;
}

int vw_watcher_overflowed(vw_watcher_t *w)
{
    int v;
    if (!w) return 0;
    pthread_mutex_lock(&w->mu);
    v = w->overflow;
    w->overflow = 0;
    pthread_mutex_unlock(&w->mu);
    return v;
}

void vw_watcher_close(vw_watcher_t *w)
{
    if (!w) return;
    close(w->ifd);
    pthread_mutex_destroy(&w->mu);
    free(w->ring);
    free(w->wds);
    free(w->moves);
    free(w);
}

#endif /* __linux__ */
