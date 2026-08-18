#include "vw_gateway_session.h"
#include "../core/vw_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int                in_use;
    char               cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    vw_client_sess_t  *sess;
    time_t             last_active;
    /* Display-only (TASK-164) — empty for a redeemed-public-link session
     * (no real logged-in user). Never used for authorization. */
    char               username[VW_MAX_USERNAME_BYTES + 1];
    /* TASK-176: 1 if sess is connected to the configured read-only
     * fallback rather than the primary. Every "free" slot is zeroed
     * (calloc at pool creation; memset on remove/reap), so this is 0 by
     * construction unless vw_gateway_session_create explicitly set it —
     * vw_gateway_session_reinsert (remember-me resume) never does, since
     * a resume token is only ever meaningful against the primary that
     * issued it (docs/PROTOCOL.md §7.1) — resuming is never a fallback
     * path, only a fresh login is. */
    int                read_only;
} gateway_session_slot_t;

struct vw_gateway_session_pool {
    gateway_session_slot_t slots[VW_GATEWAY_MAX_SESSIONS];
    uint32_t               count;
};

vw_err_t vw_gateway_session_pool_create(vw_gateway_session_pool_t **out_pool) {
    if (out_pool == NULL) return VW_ERR_INVALID_ARG;
    vw_gateway_session_pool_t *pool = calloc(1, sizeof(*pool));
    if (pool == NULL) return VW_ERR_OOM;
    *out_pool = pool;
    return VW_OK;
}

void vw_gateway_session_pool_destroy(vw_gateway_session_pool_t *pool) {
    if (pool == NULL) return;
    for (uint32_t i = 0; i < VW_GATEWAY_MAX_SESSIONS; i++) {
        if (pool->slots[i].in_use) {
            vw_client_close(pool->slots[i].sess);
        }
    }
    free(pool);
}

/*
 * SEC.07 finding (TASK-144): this used to compare cookies with strcmp(),
 * which short-circuits on the first mismatched byte - a textbook timing
 * side-channel for a secret value (this project already has
 * vw_crypto_constant_time_eq specifically "for token and hash
 * comparison", per its own doc comment; this code just hadn't used it).
 * The length check below is safe to short-circuit on - cookie_hex's
 * LENGTH isn't secret (both `wrong length` and `right length, wrong
 * content` end up rejected either way), only its CONTENT is, which is
 * why the actual byte comparison goes through the constant-time helper.
 */
static int find_by_cookie(vw_gateway_session_pool_t *pool, const char *cookie_hex) {
    if (strlen(cookie_hex) != VW_GATEWAY_COOKIE_HEX_LEN) return -1;
    for (uint32_t i = 0; i < VW_GATEWAY_MAX_SESSIONS; i++) {
        if (pool->slots[i].in_use &&
            vw_crypto_constant_time_eq(pool->slots[i].cookie_hex, cookie_hex,
                                        VW_GATEWAY_COOKIE_HEX_LEN)) {
            return (int)i;
        }
    }
    return -1;
}

vw_err_t vw_gateway_session_create(vw_gateway_session_pool_t *pool,
                                    vw_client_sess_t *sess,
                                    const char *username,
                                    int read_only,
                                    char *out_cookie_hex) {
    if (pool == NULL || sess == NULL || out_cookie_hex == NULL) {
        return VW_ERR_INVALID_ARG;
    }
    if (pool->count >= VW_GATEWAY_MAX_SESSIONS) {
        return VW_ERR_QUOTA_EXCEEDED;
    }

    int slot_idx = -1;
    for (uint32_t i = 0; i < VW_GATEWAY_MAX_SESSIONS; i++) {
        if (!pool->slots[i].in_use) {
            slot_idx = (int)i;
            break;
        }
    }
    if (slot_idx < 0) return VW_ERR_QUOTA_EXCEEDED; /* shouldn't happen if count is accurate */

    uint8_t raw[VW_GATEWAY_COOKIE_BYTES];
    vw_err_t err = vw_crypto_random(raw, sizeof(raw));
    if (err != VW_OK) return err;

    gateway_session_slot_t *slot = &pool->slots[slot_idx];
    vw_crypto_hex_encode(raw, sizeof(raw), slot->cookie_hex);
    slot->sess = sess;
    slot->last_active = time(NULL);
    slot->in_use = 1;
    slot->read_only = read_only ? 1 : 0;
    if (username != NULL && username[0] != '\0') {
        size_t n = strlen(username);
        if (n > VW_MAX_USERNAME_BYTES) n = VW_MAX_USERNAME_BYTES;
        memcpy(slot->username, username, n);
        slot->username[n] = '\0';
    } else {
        slot->username[0] = '\0';
    }
    pool->count++;

    memcpy(out_cookie_hex, slot->cookie_hex, VW_GATEWAY_COOKIE_HEX_LEN + 1);
    return VW_OK;
}

vw_err_t vw_gateway_session_get(vw_gateway_session_pool_t *pool,
                                 const char *cookie_hex,
                                 vw_client_sess_t **out_sess) {
    if (pool == NULL || cookie_hex == NULL || out_sess == NULL) {
        return VW_ERR_INVALID_ARG;
    }
    int idx = find_by_cookie(pool, cookie_hex);
    if (idx < 0) return VW_ERR_AUTH_REQUIRED;

    pool->slots[idx].last_active = time(NULL);
    *out_sess = pool->slots[idx].sess;
    return VW_OK;
}

vw_err_t vw_gateway_session_reinsert(vw_gateway_session_pool_t *pool,
                                      const char *cookie_hex,
                                      vw_client_sess_t *sess,
                                      const char *username) {
    if (pool == NULL || cookie_hex == NULL || sess == NULL) return VW_ERR_INVALID_ARG;
    if (strlen(cookie_hex) != VW_GATEWAY_COOKIE_HEX_LEN) return VW_ERR_INVALID_ARG;
    if (find_by_cookie(pool, cookie_hex) >= 0) return VW_ERR_ALREADY_EXISTS;
    if (pool->count >= VW_GATEWAY_MAX_SESSIONS) return VW_ERR_QUOTA_EXCEEDED;

    int slot_idx = -1;
    for (uint32_t i = 0; i < VW_GATEWAY_MAX_SESSIONS; i++) {
        if (!pool->slots[i].in_use) { slot_idx = (int)i; break; }
    }
    if (slot_idx < 0) return VW_ERR_QUOTA_EXCEEDED;

    gateway_session_slot_t *slot = &pool->slots[slot_idx];
    memcpy(slot->cookie_hex, cookie_hex, VW_GATEWAY_COOKIE_HEX_LEN + 1);
    slot->sess = sess;
    slot->last_active = time(NULL);
    slot->in_use = 1;
    if (username != NULL && username[0] != '\0') {
        size_t n = strlen(username);
        if (n > VW_MAX_USERNAME_BYTES) n = VW_MAX_USERNAME_BYTES;
        memcpy(slot->username, username, n);
        slot->username[n] = '\0';
    } else {
        slot->username[0] = '\0';
    }
    pool->count++;
    return VW_OK;
}

vw_err_t vw_gateway_session_get_username(vw_gateway_session_pool_t *pool,
                                          const char *cookie_hex,
                                          char *out_buf, size_t out_buf_size) {
    if (pool == NULL || cookie_hex == NULL || out_buf == NULL || out_buf_size == 0) {
        return VW_ERR_INVALID_ARG;
    }
    int idx = find_by_cookie(pool, cookie_hex);
    if (idx < 0) return VW_ERR_AUTH_REQUIRED;

    size_t n = strlen(pool->slots[idx].username);
    if (n >= out_buf_size) n = out_buf_size - 1;
    memcpy(out_buf, pool->slots[idx].username, n);
    out_buf[n] = '\0';
    return VW_OK;
}

vw_err_t vw_gateway_session_is_read_only(vw_gateway_session_pool_t *pool,
                                          const char *cookie_hex,
                                          int *out_read_only) {
    if (pool == NULL || cookie_hex == NULL || out_read_only == NULL) {
        return VW_ERR_INVALID_ARG;
    }
    int idx = find_by_cookie(pool, cookie_hex);
    if (idx < 0) return VW_ERR_AUTH_REQUIRED;

    *out_read_only = pool->slots[idx].read_only;
    return VW_OK;
}

void vw_gateway_session_remove(vw_gateway_session_pool_t *pool,
                                const char *cookie_hex) {
    if (pool == NULL || cookie_hex == NULL) return;
    int idx = find_by_cookie(pool, cookie_hex);
    if (idx < 0) return;

    vw_client_logout(pool->slots[idx].sess);
    memset(&pool->slots[idx], 0, sizeof(pool->slots[idx]));
    pool->count--;
}

void vw_gateway_session_reap_idle(vw_gateway_session_pool_t *pool) {
    if (pool == NULL) return;
    time_t now = time(NULL);
    for (uint32_t i = 0; i < VW_GATEWAY_MAX_SESSIONS; i++) {
        if (!pool->slots[i].in_use) continue;
        if ((now - pool->slots[i].last_active) >= (time_t)VW_GATEWAY_SESSION_IDLE_SECS) {
            vw_client_close(pool->slots[i].sess);
            memset(&pool->slots[i], 0, sizeof(pool->slots[i]));
            pool->count--;
        }
    }
}

uint32_t vw_gateway_session_count(const vw_gateway_session_pool_t *pool) {
    if (pool == NULL) return 0;
    return pool->count;
}
