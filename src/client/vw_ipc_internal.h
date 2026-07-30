#ifndef VW_IPC_INTERNAL_H
#define VW_IPC_INTERNAL_H

/*
 * vw_ipc_internal.h — declarations shared between vw_ipc.c and its unit test
 * (tests/unit/test_vw_ipc.c) only. NOT part of vw_ipc.h's public API and not
 * installed/exported; exists purely so the test file and the implementation
 * can't silently drift out of sync on this function's signature.
 */

#ifdef __linux__

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Scans a /proc/net/tcp-formatted stream `f` for the ESTABLISHED entry whose
 * local port is `local_port` and whose remote port is `peer_port`, and
 * writes its owning uid to *out_uid.
 *
 * Returns 0 on a match, 1 if no matching ESTABLISHED entry is found (the
 * stream was read successfully either way — distinguish "unreadable" at the
 * call site by checking whether fopen() itself failed).
 *
 * See vw_ipc.c's vw_ipc_server_accept() for the critical, non-obvious detail
 * on which way round (local_port, peer_port) must be passed: a loopback TCP
 * connection has two /proc/net/tcp rows, one per socket, and only one of
 * them belongs to the connecting peer.
 */
int vw_ipc_linux_proc_net_tcp_uid(FILE *f, uint16_t local_port, uint16_t peer_port,
                                   unsigned long *out_uid);

#ifdef __cplusplus
}
#endif

#endif /* __linux__ */

#endif /* VW_IPC_INTERNAL_H */
