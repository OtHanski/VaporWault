#include "vw_gateway_remember.h"
#include "vw_gateway_session.h"   /* VW_GATEWAY_COOKIE_HEX_LEN */
#include "../core/vw_fs.h"
#include "../core/vw_crypto.h"    /* vw_crypto_constant_time_eq */

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <aclapi.h>
#  pragma comment(lib, "advapi32.lib")
#else
#  include <sys/stat.h>
#endif

#define REMEMBER_FILE "remember.db"

/* Fixed-size on-disk record (this codebase's established vw_cache.c-style
 * convention). cookie_hex[0] == '\0' marks a free slot. 162 bytes of real
 * content, padded to a round 192 — no alignment requirement of its own
 * (no trailing numeric field), just matching this convention's habit of
 * a deliberate, asserted total size. */
typedef struct {
    char    cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    uint8_t token[32];
    char    username[VW_MAX_USERNAME_BYTES + 1];
    uint8_t _pad[30];
} remember_record_t;
_Static_assert(sizeof(remember_record_t) == 192,
               "remember_record_t must be 192 bytes");

struct vw_gateway_remember_store {
    char              path[512];
    remember_record_t records[VW_GATEWAY_REMEMBER_MAX_ENTRIES];
};

/*
 * SECURITY (TASK-165): this file is a bearer-credential store — anyone
 * who can read it can impersonate every remembered account
 * (ARCHITECTURE.md's Risks table already flags exactly this gap for
 * vw_daemon.c's session.tok and warns against carrying it into "a richer
 * multi-session gateway target"). POSIX: chmod 0600. Windows: a REAL ACL
 * restricting access to the current user only — PROTECTED_DACL_SECURITY_
 * INFORMATION explicitly blocks inherited ACEs, per this task's own
 * requirement ("not just relying on default NTFS inheritance"), unlike
 * vw_daemon.c's tok_save() on Windows, which is the known gap this task
 * exists to not repeat.
 */
#ifdef _WIN32
static vw_err_t harden_file_perms(const char *path) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return VW_ERR_IO;

    DWORD needed = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &needed);
    vw_err_t ret = VW_ERR_IO;
    uint8_t *buf = needed ? (uint8_t *)malloc(needed) : NULL;
    if (buf != NULL && GetTokenInformation(tok, TokenUser, buf, needed, &needed)) {
        PSID sid = ((TOKEN_USER *)buf)->User.Sid;

        EXPLICIT_ACCESSA ea;
        memset(&ea, 0, sizeof(ea));
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = (LPSTR)sid;

        PACL acl = NULL;
        if (SetEntriesInAclA(1, &ea, NULL, &acl) == ERROR_SUCCESS) {
            if (SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                    PROTECTED_DACL_SECURITY_INFORMATION,
                    sid, NULL, acl, NULL) == ERROR_SUCCESS) {
                ret = VW_OK;
            }
            LocalFree(acl);
        }
    }
    free(buf);
    CloseHandle(tok);
    return ret;
}

vw_err_t vw_gateway_remember_verify_perms(const vw_gateway_remember_store_t *store) {
    if (store == NULL) return VW_ERR_INVALID_ARG;

    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return VW_ERR_IO;
    DWORD needed = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &needed);
    uint8_t *tokbuf = needed ? (uint8_t *)malloc(needed) : NULL;
    vw_err_t ret = VW_ERR_PERMISSION;
    if (tokbuf != NULL && GetTokenInformation(tok, TokenUser, tokbuf, needed, &needed)) {
        PSID self_sid = ((TOKEN_USER *)tokbuf)->User.Sid;

        PACL dacl = NULL;
        PSECURITY_DESCRIPTOR sd = NULL;
        if (GetNamedSecurityInfoA((LPSTR)store->path, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
            dacl != NULL) {
            /* Exactly one ACE, granting the current user (and no one
             * else) access — anything else (extra ACEs from inherited
             * or additional grants, or a missing/empty DACL) fails this
             * check. Deliberately strict: a "verify" that tolerates
             * extra access isn't actually verifying the hardening. */
            ACL_SIZE_INFORMATION size_info;
            if (GetAclInformation(dacl, &size_info, sizeof(size_info), AclSizeInformation) &&
                size_info.AceCount == 1) {
                ACCESS_ALLOWED_ACE *ace = NULL;
                if (GetAce(dacl, 0, (LPVOID *)&ace) &&
                    EqualSid(self_sid, (PSID)&ace->SidStart)) {
                    ret = VW_OK;
                }
            }
            if (sd != NULL) LocalFree(sd);
        }
    }
    free(tokbuf);
    CloseHandle(tok);
    return ret;
}
#else
static vw_err_t harden_file_perms(const char *path) {
    if (chmod(path, 0600) != 0) return VW_ERR_IO;
    return VW_OK;
}

vw_err_t vw_gateway_remember_verify_perms(const vw_gateway_remember_store_t *store) {
    if (store == NULL) return VW_ERR_INVALID_ARG;
    struct stat st;
    if (stat(store->path, &st) != 0) return VW_ERR_PERMISSION;
    if ((st.st_mode & 0777) != 0600) return VW_ERR_PERMISSION;
    return VW_OK;
}
#endif

vw_err_t vw_gateway_remember_open(const char *state_dir,
                                   vw_gateway_remember_store_t **out_store) {
    if (state_dir == NULL || out_store == NULL) return VW_ERR_INVALID_ARG;

    vw_err_t err = vw_fs_ensure_dir(state_dir);
    if (err != VW_OK) return err;

    vw_gateway_remember_store_t *store = calloc(1, sizeof(*store));
    if (store == NULL) return VW_ERR_OOM;

    err = vw_fs_path_join(store->path, sizeof(store->path), state_dir, REMEMBER_FILE);
    if (err != VW_OK) { free(store); return err; }

    if (!vw_fs_exists(store->path)) {
        /* All-zero (every record's cookie_hex[0] == '\0' -> free slot). */
        err = vw_fs_atomic_write(store->path, store->records, sizeof(store->records));
        if (err != VW_OK) { free(store); return err; }
        err = harden_file_perms(store->path);
        if (err != VW_OK) { free(store); return err; }
    } else {
        void *data = NULL; size_t len = 0;
        err = vw_fs_read_file(store->path, &data, &len);
        if (err != VW_OK) { free(store); return err; }
        if (len != sizeof(store->records)) {
            /* Foreign/corrupt file - fail loud rather than silently
             * reinitialise (which would look like a normal cold start
             * but actually discard every existing remembered login). */
            free(data);
            free(store);
            return VW_ERR_IO;
        }
        memcpy(store->records, data, len);
        free(data);
    }

    *out_store = store;
    return VW_OK;
}

void vw_gateway_remember_close(vw_gateway_remember_store_t *store) {
    free(store);
}

static int find_by_cookie(vw_gateway_remember_store_t *store, const char *cookie_hex) {
    size_t clen = strlen(cookie_hex);
    if (clen != VW_GATEWAY_COOKIE_HEX_LEN) return -1;
    for (unsigned i = 0; i < VW_GATEWAY_REMEMBER_MAX_ENTRIES; i++) {
        /* Same constant-time rationale as vw_gateway_session.c's own
         * find_by_cookie: cookie_hex's content, not its length, is the
         * secret being compared. */
        if (store->records[i].cookie_hex[0] != '\0' &&
            vw_crypto_constant_time_eq(store->records[i].cookie_hex, cookie_hex,
                                         VW_GATEWAY_COOKIE_HEX_LEN)) {
            return (int)i;
        }
    }
    return -1;
}

static vw_err_t persist_record(vw_gateway_remember_store_t *store, unsigned idx) {
    uint64_t offset = (uint64_t)idx * sizeof(remember_record_t);
    vw_err_t err = vw_fs_pwrite(store->path, offset, &store->records[idx],
                                 sizeof(remember_record_t));
    if (err != VW_OK) return err;
    return vw_fs_sync_file(store->path);
}

vw_err_t vw_gateway_remember_put(vw_gateway_remember_store_t *store,
                                  const char *cookie_hex,
                                  const uint8_t token[32],
                                  const char *username) {
    if (store == NULL || cookie_hex == NULL || token == NULL) return VW_ERR_INVALID_ARG;
    if (strlen(cookie_hex) != VW_GATEWAY_COOKIE_HEX_LEN) return VW_ERR_INVALID_ARG;

    int idx = find_by_cookie(store, cookie_hex);
    if (idx < 0) {
        for (unsigned i = 0; i < VW_GATEWAY_REMEMBER_MAX_ENTRIES; i++) {
            if (store->records[i].cookie_hex[0] == '\0') { idx = (int)i; break; }
        }
        if (idx < 0) return VW_ERR_QUOTA_EXCEEDED;
    }

    remember_record_t *rec = &store->records[idx];
    memset(rec, 0, sizeof(*rec));
    memcpy(rec->cookie_hex, cookie_hex, VW_GATEWAY_COOKIE_HEX_LEN);
    rec->cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN] = '\0';
    memcpy(rec->token, token, sizeof(rec->token));
    if (username != NULL && username[0] != '\0') {
        size_t n = strlen(username);
        if (n > VW_MAX_USERNAME_BYTES) n = VW_MAX_USERNAME_BYTES;
        memcpy(rec->username, username, n);
        rec->username[n] = '\0';
    }

    return persist_record(store, (unsigned)idx);
}

vw_err_t vw_gateway_remember_get(vw_gateway_remember_store_t *store,
                                  const char *cookie_hex,
                                  uint8_t out_token[32],
                                  char *out_username, size_t out_username_size) {
    if (store == NULL || cookie_hex == NULL || out_token == NULL) return VW_ERR_INVALID_ARG;
    int idx = find_by_cookie(store, cookie_hex);
    if (idx < 0) return VW_ERR_NOT_FOUND;

    memcpy(out_token, store->records[idx].token, sizeof(store->records[idx].token));
    if (out_username != NULL && out_username_size > 0) {
        size_t n = strlen(store->records[idx].username);
        if (n >= out_username_size) n = out_username_size - 1;
        memcpy(out_username, store->records[idx].username, n);
        out_username[n] = '\0';
    }
    return VW_OK;
}

void vw_gateway_remember_remove(vw_gateway_remember_store_t *store,
                                 const char *cookie_hex) {
    if (store == NULL || cookie_hex == NULL) return;
    int idx = find_by_cookie(store, cookie_hex);
    if (idx < 0) return;
    memset(&store->records[idx], 0, sizeof(store->records[idx]));
    persist_record(store, (unsigned)idx);
}
