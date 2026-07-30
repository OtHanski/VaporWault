/*
 * vw_conn_registry.c — see vw_conn_registry.h for the design description.
 */

#include "vw_conn_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef SRWLOCK vw_rwlock_t;
#   define rwlock_init(l)      InitializeSRWLock(l)
#   define rwlock_rdlock(l)    AcquireSRWLockShared(l)
#   define rwlock_rdunlock(l)  ReleaseSRWLockShared(l)
#   define rwlock_wrlock(l)    AcquireSRWLockExclusive(l)
#   define rwlock_wrunlock(l)  ReleaseSRWLockExclusive(l)
#else
#   include <pthread.h>
typedef pthread_rwlock_t vw_rwlock_t;
#   define rwlock_init(l)      pthread_rwlock_init(l, NULL)
#   define rwlock_rdlock(l)    pthread_rwlock_rdlock(l)
#   define rwlock_rdunlock(l)  pthread_rwlock_unlock(l)
#   define rwlock_wrlock(l)    pthread_rwlock_wrlock(l)
#   define rwlock_wrunlock(l)  pthread_rwlock_unlock(l)
#endif

/* conn_id == 0 marks a free slot (never a real id — see next_conn_id init). */
typedef struct {
    uint64_t conn_id;
    uint64_t user_id;
    char     peer_addr[64];
    int64_t  connected_since;
} slot_t;

struct vw_conn_registry {
    vw_rwlock_t lock;
    slot_t     *slots;
    uint32_t    cap;
    uint32_t    count;      /* number of occupied slots */
    uint64_t    next_conn_id;
};

vw_err_t vw_conn_registry_open(vw_conn_registry_t **out) {
    if (!out) return VW_ERR_INVALID_ARG;

    vw_conn_registry_t *reg = (vw_conn_registry_t *)calloc(1, sizeof(*reg));
    if (!reg) return VW_ERR_OOM;

    reg->cap = 64;
    reg->slots = (slot_t *)calloc((size_t)reg->cap, sizeof(slot_t));
    if (!reg->slots) { free(reg); return VW_ERR_OOM; }

    rwlock_init(&reg->lock);
    reg->count = 0;
    reg->next_conn_id = 1; /* 0 is reserved for "free slot" */

    *out = reg;
    return VW_OK;
}

void vw_conn_registry_close(vw_conn_registry_t *reg) {
    if (!reg) return;
    free(reg->slots);
    free(reg);
}

vw_err_t vw_conn_registry_add(vw_conn_registry_t *reg, const char *peer_addr,
                               uint64_t *out_conn_id) {
    if (!reg || !out_conn_id) return VW_ERR_INVALID_ARG;

    rwlock_wrlock(&reg->lock);

    /* Find a free slot, or grow the table. */
    uint32_t slot = reg->cap; /* sentinel: none found yet */
    for (uint32_t i = 0; i < reg->cap; i++) {
        if (reg->slots[i].conn_id == 0) { slot = i; break; }
    }
    if (slot == reg->cap) {
        uint32_t new_cap = reg->cap * 2;
        slot_t *p = (slot_t *)realloc(reg->slots, (size_t)new_cap * sizeof(slot_t));
        if (!p) { rwlock_wrunlock(&reg->lock); return VW_ERR_OOM; }
        memset(p + reg->cap, 0, (size_t)(new_cap - reg->cap) * sizeof(slot_t));
        slot = reg->cap;
        reg->slots = p;
        reg->cap   = new_cap;
    }

    reg->slots[slot].conn_id         = reg->next_conn_id++;
    reg->slots[slot].user_id         = 0;
    reg->slots[slot].connected_since = (int64_t)time(NULL);
    if (peer_addr)
        snprintf(reg->slots[slot].peer_addr, sizeof(reg->slots[slot].peer_addr),
                 "%s", peer_addr);
    else
        reg->slots[slot].peer_addr[0] = '\0';

    reg->count++;
    *out_conn_id = reg->slots[slot].conn_id;

    rwlock_wrunlock(&reg->lock);
    return VW_OK;
}

void vw_conn_registry_set_user(vw_conn_registry_t *reg, uint64_t conn_id,
                                uint64_t user_id) {
    if (!reg || conn_id == 0) return;

    rwlock_wrlock(&reg->lock);
    for (uint32_t i = 0; i < reg->cap; i++) {
        if (reg->slots[i].conn_id == conn_id) {
            reg->slots[i].user_id = user_id;
            break;
        }
    }
    rwlock_wrunlock(&reg->lock);
}

void vw_conn_registry_remove(vw_conn_registry_t *reg, uint64_t conn_id) {
    if (!reg || conn_id == 0) return;

    rwlock_wrlock(&reg->lock);
    for (uint32_t i = 0; i < reg->cap; i++) {
        if (reg->slots[i].conn_id == conn_id) {
            memset(&reg->slots[i], 0, sizeof(reg->slots[i])); /* conn_id -> 0 = free */
            reg->count--;
            break;
        }
    }
    rwlock_wrunlock(&reg->lock);
}

vw_err_t vw_conn_registry_list(vw_conn_registry_t *reg,
                                vw_conn_info_t **out_entries, uint32_t *out_count) {
    if (!reg || !out_entries || !out_count) return VW_ERR_INVALID_ARG;

    rwlock_rdlock(&reg->lock);

    if (reg->count == 0) {
        rwlock_rdunlock(&reg->lock);
        *out_entries = NULL;
        *out_count   = 0;
        return VW_OK;
    }

    vw_conn_info_t *arr = (vw_conn_info_t *)malloc((size_t)reg->count * sizeof(*arr));
    if (!arr) { rwlock_rdunlock(&reg->lock); return VW_ERR_OOM; }

    uint32_t n = 0;
    for (uint32_t i = 0; i < reg->cap && n < reg->count; i++) {
        if (reg->slots[i].conn_id == 0) continue;
        arr[n].conn_id         = reg->slots[i].conn_id;
        arr[n].user_id         = reg->slots[i].user_id;
        arr[n].connected_since = reg->slots[i].connected_since;
        memcpy(arr[n].peer_addr, reg->slots[i].peer_addr, sizeof(arr[n].peer_addr));
        n++;
    }

    rwlock_rdunlock(&reg->lock);

    *out_entries = arr;
    *out_count   = n;
    return VW_OK;
}
