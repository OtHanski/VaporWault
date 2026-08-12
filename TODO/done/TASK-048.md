---
id:          TASK-048
title:       Implement vw_cluster — node store and NODE_HELLO handshake
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-13
priority:    high
depends_on:  [TASK-047]
blocks:      [TASK-049]
review_by:   [CQR.08, SEC.07]
tags:        [server, cluster, phase-7, security-sensitive]
---

Create the `vw_cluster` module (new files: `src/server/vw_cluster.{h,c}`)
implementing the node record store and the NODE_HELLO / NODE_HELLO_OK
handshake, per the spec published in TASK-047.

## Acceptance criteria

### 1. `vw_node_record_t` (256 bytes, fixed)

```c
typedef struct {
    uint64_t node_id;           /* assigned by admin; unique */
    uint8_t  auth_token[32];    /* 256-bit random secret */
    uint8_t  hostname[128];     /* NUL-terminated, max 127 chars */
    uint64_t sync_watermark;    /* last confirmed entry_id from this node */
    uint8_t  is_active;         /* 1 = enabled; 0 = disabled/deregistered */
    uint8_t  role;              /* 0 = REPLICA, 1 = PRIMARY (self-record only) */
    uint8_t  _pad[62];
} vw_node_record_t;
```

`_Static_assert(sizeof(vw_node_record_t) == 256, ...)` must be present.

### 2. Flat-file node store

- File: `{data_dir}/cluster/nodes.db`
- Fixed-size records, one per slot (same append-on-create + free-list pattern
  as other stores).
- In-memory index: `nid_to_slot[node_id]` array (same `fid_to_slot` pattern).
- API:
  - `vw_cluster_open(cfg, *out)` — opens or creates `nodes.db`.
  - `vw_cluster_close(ctx)` — flush + free.
  - `vw_cluster_node_add(ctx, hostname, *out_node_id, *out_token)` — generates
    a 256-bit `auth_token` via `vw_crypto_random`, assigns a new node_id,
    appends the record, returns the token to the caller (never stored in logs).
  - `vw_cluster_node_get(ctx, node_id, *out_rec)` — returns a copy of the
    record (zeroes `auth_token` in the returned copy — callers must not log
    or return the token).
  - `vw_cluster_node_update_watermark(ctx, node_id, watermark)` — in-place
    update of `sync_watermark` field; single pwrite (8 bytes, naturally aligned).
  - `vw_cluster_node_set_active(ctx, node_id, is_active)` — enable/disable.
  - `vw_cluster_min_sync_watermark(ctx, *out)` — returns
    `min(sync_watermark)` across all records where `is_active == 1 && role == 0`.
    Returns `UINT64_MAX` if no active replicas (meaning GC can freely truncate).

### 3. ALPN `vw-cluster/1` listener

Add a second TLS listener in `vw_server_main.c` on the cluster port
(`cfg.cluster_port`, default 9010). The cluster port uses the same
`cert.pem`/`key.pem` as the main port but ALPN token `vw-cluster/1`.

### 4. NODE_HELLO handler

Accept a connection on the cluster port:
1. Read one message (8-byte frame header + payload).
2. Verify `msg_type == 0x0701` (NODE_HELLO).
3. Look up `node_id` in the in-memory index.
4. Constant-time compare `auth_token` using `vw_crypto_const_eq`.
5. If either check fails: send `NODE_HELLO_FAIL` (error_code=0), close.
6. If the node record has `is_active == 0`: same — send fail, close.
7. On success: send `NODE_HELLO_OK`, then hand the connection to the
   replication loop (TASK-049 will implement this; for now, the connection
   is closed gracefully after NODE_HELLO_OK).

The NODE_HELLO handler must **rate-limit** failed attempts per source IP:
- Track failure counts in a fixed-size in-memory array (LRU or ring-buffer
  of at most 256 source IPs).
- 5 failures within 60 seconds from one IP → close immediately without
  replying (connection silently dropped).
- Rate-limit state is in-memory only (reset on restart); this is acceptable.

### 5. CMake

Add `vw_cluster.c` to `src/server/CMakeLists.txt`.

### 6. Security invariants

- `auth_token` is compared with `vw_crypto_const_eq` (never `memcmp`).
- `vw_cluster_node_get` zeroes `auth_token` in the returned copy.
- `auth_token` is never written to any log or returned in any admin response.
- Unknown `node_id` and wrong `auth_token` produce indistinguishable
  NODE_HELLO_FAIL responses (same code, same timing within ~1ms).
- Failed NODE_HELLO attempts are rate-limited per source IP (5/60s).

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: The `auth_token` zeroing in `vw_cluster_node_get` mirrors
the pattern in `vw_store_user_get_*` (password_hash zeroed for non-auth callers).
The cluster port must be firewalled from public internet; only other cluster
nodes need to reach it. The rate-limiter uses a ring-buffer approach — no heap
allocation after init. SEC.07: the constant-time comparison and
timing-equalization between unknown-node and wrong-token paths are the
critical security properties here.

SRV.01 [2026-07-13]: Implementation complete. Files created/modified:
- `src/server/vw_cluster.h` — `vw_node_record_t` (256 B, `_Static_assert`), opaque `vw_cluster_t`, `vw_cluster_cfg_t`, full API.
- `src/server/vw_cluster.c` — full implementation:
  - `struct vw_cluster_ctx`: cfg, nodes_path, nodes_lock (rwlock), nid_to_slot + cap, node_slots, next_node_id, net_ctx, accept thread, shutdown flag, rate_table[256] ring-buffer.
  - `vw_cluster_open`: ensures `{data_dir}/cluster/`, scans `nodes.db` to build nid_to_slot index.
  - Node CRUD: `node_add` (vw_crypto_random token, append + sync, token returned once then zeroed), `node_get` (zeroes auth_token in copy), `node_update_watermark` (single 8-byte pwrite at natural alignment), `node_set_active` (pwrite + sync, write-locked), `node_list` (all copies, auth_token zeroed).
  - Rate-limit: `rate_is_blocked` (read-only check) and `rate_record_failure` (increment) are separate functions — no speculative-increment anti-pattern.
  - NODE_HELLO handler: fixed 512-byte stack buffer (not VW_MAX_MSG_BYTES), blocks on rate_is_blocked, decodes payload, does locked lookup, `vw_crypto_constant_time_eq` with zero_token fallback, zeroes token bytes immediately after comparison, records failure and sends NODE_HELLO_FAIL for both unknown-node and wrong-token paths.
  - Accept thread: POSIX pthread / Windows CreateThread.
- `src/server/CMakeLists.txt` — `vw_cluster.c` uncommented.
- `src/server/vw_server_main.h` — `#include "vw_cluster.h"`, `vw_cluster_cfg_t cluster` field in `vw_server_main_cfg_t`.
- `src/server/vw_server_main.c` — `#include "vw_cluster.h"`, config defaults (port=9010, poll=5s), config file parsing (cluster_port, cluster_is_replica, cluster_primary_host, cluster_primary_port, cluster_poll_interval_secs), startup (vw_cluster_open + vw_cluster_start after GC), shutdown (vw_cluster_close before GC stop).

CQR.08 and SEC.07 review requested.

CQR.08 [2026-07-13]: Review complete. No blocking findings.

- `_Static_assert(sizeof(vw_node_record_t) == 256)` present. ✓
- `nodes_pread` opens/closes file per call — acceptable at cluster scale (tens of nodes), consistent with other store patterns. ✓
- `index_ensure` doubles capacity on growth — prevents quadratic allocation. ✓
- Rate-limit logic correctly split into `rate_is_blocked` (read-only) and `rate_record_failure` (mutate) — no speculative-increment anti-pattern. ✓
- `handle_cluster_conn` uses a 512-byte stack buffer (not `VW_MAX_MSG_BYTES`); comment documents why. ✓
- `recv_token` and `stored_rec.auth_token` zeroed immediately after `vw_crypto_constant_time_eq`. ✓
- `vw_cluster_node_add` zeroes `rec.auth_token` before returning to caller (after copying to `out_token`). ✓
- `vw_cluster_node_get` zeroes `auth_token` in returned copy. ✓
- `vw_cluster_node_list` zeroes `auth_token` in every entry of returned array. ✓
- `#include <fcntl.h>` added on POSIX path for `open()`. ✓
- Config keys follow the `vw_server_main` key naming convention (`smtp_*`, `acme_*`, `gc_*`, now `cluster_*`). ✓
- `vw_cluster_close` calls `vw_cluster_stop` internally — no double-stop in shutdown sequence. ✓
- One advisory: `cluster_log` writes to stderr; in production the main logging should be integrated (already noted as a TASK-049 concern). Not blocking.

**CQR.08 sign-off granted.**

SEC.07 [2026-07-13]: Review complete. No blocking findings.

- `auth_token` compared exclusively via `vw_crypto_constant_time_eq(recv_token, cmp_token, 32)`. Never via `memcmp`. ✓
- When `node_id` is unknown, `cmp_token = zero_token` (static zero buffer) — comparison still runs, equalizing timing between unknown-node and wrong-token paths. ✓
- `NODE_HELLO_FAIL` (error_code=0) sent identically for unknown-node and wrong-token; no timing or content difference visible to the attacker. ✓
- `recv_token` cleared with `memset` immediately after comparison, before any branch that could reveal timing. ✓
- `stored_rec.auth_token` cleared with `memset` after comparison (copy on stack, not the on-disk record). ✓
- `rate_is_blocked` drops connection silently (no reply, no `send_hello_fail`) when IP is rate-limited — correct per spec §7.9. ✓
- `rate_record_failure` called for: unexpected msg type, truncated payload, hostname overrun, auth failure. All four failure paths covered. ✓
- `rate_reset_on_success` called on successful NODE_HELLO — prevents accumulated failures from blocking a legitimately reconnecting node. ✓ (Acceptable trade-off: a correctly-authed attacker that knows the token can clear the rate limit. The token is the security boundary.)
- `is_active == 0` nodes: `found` is set to 0 (the `&&stored_rec.is_active` guard), so a disabled node gets the same timing-equalized fail path. ✓
- `node_id == 0` explicitly rejected (the `node_id != 0` guard in lookup). ✓
- `vw_cluster_node_add` generates token with `vw_crypto_random` (CSPRNG). ✓
- Token returned to caller exactly once from `node_add`; `node_get` and `node_list` always zero the token field. ✓
- One advisory: `cluster_log` calls may log `node_id` — this is safe, node_id is not a secret. auth_token is never logged. ✓
- TLS termination is handled by `vw_net_listen_cluster` (same cert as main listener, ALPN `vw-cluster/1`) — implementation delegates TLS 1.3 enforcement to the net layer, consistent with all other server listeners. ✓

**SEC.07 sign-off granted.**

ARCH.00 [2026-07-13]: Both reviewers signed off, no blocking findings. TASK-048 done. TASK-049 is now unblocked.
