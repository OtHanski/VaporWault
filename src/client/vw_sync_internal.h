#ifndef VW_SYNC_INTERNAL_H
#define VW_SYNC_INTERNAL_H

/*
 * vw_sync_internal.h — TASK-114: internal types and functions from
 * vw_sync.c, exposed ONLY for unit testing.
 *
 * This is NOT a public API. Never include it outside vw_sync.c itself and
 * its unit test (tests/unit/test_vw_sync.c). Every function declared below
 * is `static` in vw_sync.c in every production build — VW_SYNC_TESTABLE
 * (defined in vw_sync.c) resolves to `static` unless VW_SYNC_TEST_HOOKS is
 * defined, the same compile-time gate TASK-111 already established for
 * vw_sync_test_before_list_dir, so no production target's symbol table
 * changes because this file exists. vw_sync.h — the real public API
 * consumed by vw_daemon.c, vw_client_cli.c, the GUI, and every existing
 * test — is untouched by any of this.
 *
 * These type definitions used to live directly in vw_sync.c; they moved
 * here verbatim (byte-for-byte identical layout) so the unit test can
 * declare fixtures of them. vw_sync.c includes this header in place of the
 * old inline definitions.
 */

#include "vw_sync.h"
#include "vw_client_core.h"
#include "vw_cache.h"
#include "../core/vw_proto.h"
#include <stdint.h>

/* ── Action plan ──────────────────────────────────────────────────────────── */

#define ACT_UPLOAD      1
#define ACT_DOWNLOAD    2
#define ACT_DEL_REMOTE  3
#define ACT_DEL_LOCAL   4
#define ACT_CONFLICT    5

typedef struct {
    char     virtual_path[512];
    char     local_path[512];
    char     local_root[512];  /* registered root (security anchor for DEL_LOCAL) */
    int      action;
    uint64_t size;
    int      shared;         /* TASK-106: 1 = target folder is shared (file-id
                                 addressed); 0 = owned (path-addressed), the
                                 pre-TASK-106 behavior, byte-for-byte unchanged */
    uint64_t file_id;        /* TASK-106: target file's own file_id; 0 if it
                                 doesn't exist on the server yet (new upload) */
    uint64_t parent_dir_id;  /* TASK-106: immediate parent folder's file_id —
                                 only meaningful for a shared-folder ACT_UPLOAD
                                 with file_id == 0 (vw_client_file_upload_into_folder) */
} action_t;

typedef struct {
    action_t *arr;
    uint32_t  count;
    uint32_t  cap;
} action_list_t;

/* ── Local file entries ───────────────────────────────────────────────────── */

typedef struct {
    char     local_path[512];
    char     virtual_path[512];
    int64_t  mtime;
    uint64_t size;
} lfile_t;

typedef struct {
    lfile_t *arr;
    uint32_t count;
    uint32_t cap;
    vw_err_t err;
} lfiles_t;

/* ── Server entry list ────────────────────────────────────────────────────── */

typedef struct {
    char     virtual_path[512];
    uint64_t file_id;
    uint64_t size_bytes;
    int64_t  mtime_unix;
    uint64_t version_id;
    uint64_t vault_id;   /* TASK-158: 0 = unencrypted */
    uint8_t  entry_type;
} srv_entry_t;

typedef struct {
    srv_entry_t *arr;
    uint32_t     count;
    uint32_t     cap;
} srv_list_t;

/* ── Directory id map (shared-folder sync, TASK-106) ─────────────────────── */

typedef struct {
    char     virtual_path[512];
    uint64_t dir_id;
} dir_entry_t;

typedef struct {
    dir_entry_t *arr;
    uint32_t     count;
    uint32_t     cap;
} dirmap_t;

/*
 * Sentinel dirmap value meaning "already attempted and classified as
 * unresolvable earlier THIS cycle" — distinct from 0 ("never looked up").
 * See resolve_or_create_dir()'s header comment in vw_sync.c for the full
 * rationale (TASK-113 / CQR.08 review finding on double-counting).
 */
#define VW_DIRMAP_UNRESOLVABLE ((uint64_t)-1)

#ifdef VW_SYNC_TEST_HOOKS

int      under_root(const char *path, const char *root);
int      is_net_err(vw_err_t err);

vw_err_t action_push(action_list_t *al, int act,
                      const char *vpath, const char *lpath,
                      const char *lroot, uint64_t size,
                      int shared, uint64_t file_id, uint64_t parent_dir_id);

vw_err_t lfiles_push(lfiles_t *lf, const char *lpath, const char *vpath,
                      int64_t mtime, uint64_t size);

vw_err_t srv_push(srv_list_t *sl, const char *vpath, const vw_file_entry_t *e);

vw_err_t dirmap_push(dirmap_t *dm, const char *vpath, uint64_t dir_id);
uint64_t dirmap_lookup(const dirmap_t *dm, const char *vpath);

vw_err_t compute_actions(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                          const vw_sync_folder_t *folder,
                          const lfiles_t *lfiles,
                          const srv_list_t *srv,
                          dirmap_t *dm,
                          action_list_t *out);

vw_err_t resolve_or_create_dir(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                                dirmap_t *dm, const char *root_vpath,
                                const char *vpath, int shared, uint64_t *out_id);

vw_err_t exec_action(vw_sync_ctx_t *ctx, vw_client_sess_t *sess,
                      const action_t *a);

/* Selective sync (TASK-192/193) — see vw_sync.c's own header comment on
 * this pair for the exact glob syntax supported. */
int vw_sync_glob_seg_match(const char *pat, const char *str);
int vw_sync_glob_match(const char *pattern, const char *path);

#endif /* VW_SYNC_TEST_HOOKS */

#endif /* VW_SYNC_INTERNAL_H */
