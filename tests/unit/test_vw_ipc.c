/*
 * test_vw_ipc.c — regression coverage for TASK-093 (real peer-UID
 * verification on the daemon IPC channel) plus a basic same-uid
 * accept/connect round trip.
 *
 * The Linux /proc/net/tcp parser (vw_ipc_linux_proc_net_tcp_uid) is
 * exercised directly with fabricated /proc/net/tcp content via fmemopen(),
 * so a uid mismatch / no-match / non-ESTABLISHED case can be tested without
 * actually running this binary as a second user.
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE  /* fmemopen() */
#endif

#include "vw_test.h"
#include "vw_ipc.h"

#ifdef __linux__
#include "vw_ipc_internal.h"

/*
 * A single loopback TCP connection between a daemon (port 0xBABE) and a
 * client (ephemeral port 0x1234) produces TWO rows in /proc/net/tcp — one
 * per socket, each owned by whichever process holds that socket:
 *
 *   local=BABE remote=1234  → the daemon's own accepted socket (uid 1000,
 *                              the daemon's own uid — NOT the client's)
 *   local=1234 remote=BABE  → the client's connecting socket (uid 4242,
 *                              the actual connecting user)
 *
 * vw_ipc_server_accept() must query with the pair SWAPPED relative to its
 * own (our_port, peer_port) view — i.e. (peer_port, our_port) — to land on
 * the client's row. Querying un-swapped is a tautology that always returns
 * the daemon's own uid, silently verifying nothing (this was a real bug
 * caught by SEC.07 review before this test existed). These fixtures encode
 * both rows with deliberately different uids so a regression back to the
 * un-swapped query is caught: it would return 1000, not 4242.
 */
static const char *PROC_NET_TCP_SAMPLE =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:9999 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:BABE 0100007F:1234 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0\n"
    "   2: 0100007F:1234 0100007F:BABE 01 00000000:00000000 00:00000000 00000000  4242        0 33333 1 0000000000000000 100 0 0 10 0\n"
    "   3: 7F000001:5678 0100007F:BABE 01 00000000:00000000 00:00000000 00000000  9999        0 44444 1 0000000000000000 100 0 0 10 0\n";
#endif

#ifdef _WIN32
#include "vw_ipc_internal.h"

/*
 * Windows analogue of the /proc/net/tcp fixture above, as an in-memory
 * MIB_TCPROW_OWNER_PID array instead of parsed text — same two-rows-per-
 * connection structure, same deliberately-different PIDs so a regression
 * back to an un-swapped query is caught (it would return 1000, not 4242).
 */
#define WIN_LOOPBACK_BE     ((uint32_t)0x0100007Fu) /* 127.0.0.1, network byte order */
#define WIN_NON_LOOPBACK_BE ((uint32_t)0x0100007Eu) /* deliberately not loopback */

static MIB_TCPROW_OWNER_PID win_mk_row(DWORD state, uint32_t local_addr, uint16_t local_port,
                                        uint32_t remote_addr, uint16_t remote_port, DWORD pid)
{
    MIB_TCPROW_OWNER_PID r;
    memset(&r, 0, sizeof(r));
    r.dwState      = state;
    r.dwLocalAddr  = local_addr;
    r.dwLocalPort  = (DWORD)htons(local_port);
    r.dwRemoteAddr = remote_addr;
    r.dwRemotePort = (DWORD)htons(remote_port);
    r.dwOwningPid  = pid;
    return r;
}

static void win_mk_table(MIB_TCPROW_OWNER_PID *rows)
{
    rows[0] = win_mk_row(MIB_TCP_STATE_LISTEN, WIN_LOOPBACK_BE, 0x9999, 0, 0, 1000);
    rows[1] = win_mk_row(MIB_TCP_STATE_ESTAB,  WIN_LOOPBACK_BE, 0xBABE, WIN_LOOPBACK_BE, 0x1234, 1000);
    rows[2] = win_mk_row(MIB_TCP_STATE_ESTAB,  WIN_LOOPBACK_BE, 0x1234, WIN_LOOPBACK_BE, 0xBABE, 4242);
    rows[3] = win_mk_row(MIB_TCP_STATE_ESTAB,  WIN_NON_LOOPBACK_BE, 0x5678, WIN_LOOPBACK_BE, 0xBABE, 9999);
}
#endif

VW_TEST_SUITE("vw_ipc") {

#ifdef __linux__
    VW_TEST_CASE("proc_net_tcp_uid: un-swapped query returns the daemon's own uid (the tautology this task fixed)") {
        FILE *f = fmemopen((void *)PROC_NET_TCP_SAMPLE, strlen(PROC_NET_TCP_SAMPLE), "r");
        unsigned long uid = 0;
        VW_ASSERT(f != NULL);
        /* our_port=0xBABE, peer_port=0x1234, queried un-swapped (local=our_port) */
        VW_ASSERT_EQ(0, vw_ipc_linux_proc_net_tcp_uid(f, 0xBABE, 0x1234, &uid));
        VW_ASSERT_EQ(1000ul, uid);
        fclose(f);
    }

    VW_TEST_CASE("proc_net_tcp_uid: swapped query (the fix) returns the actual connecting client's uid") {
        FILE *f = fmemopen((void *)PROC_NET_TCP_SAMPLE, strlen(PROC_NET_TCP_SAMPLE), "r");
        unsigned long uid = 0;
        VW_ASSERT(f != NULL);
        /* our_port=0xBABE, peer_port=0x1234, queried swapped (local=peer_port, rem=our_port)
         * — this is exactly what vw_ipc_server_accept() now does. */
        VW_ASSERT_EQ(0, vw_ipc_linux_proc_net_tcp_uid(f, 0x1234, 0xBABE, &uid));
        VW_ASSERT_EQ(4242ul, uid);
        VW_ASSERT(uid != 1000ul);
        fclose(f);
    }

    VW_TEST_CASE("proc_net_tcp_uid: LISTEN-state entries never match (state filter)") {
        FILE *f = fmemopen((void *)PROC_NET_TCP_SAMPLE, strlen(PROC_NET_TCP_SAMPLE), "r");
        unsigned long uid = 0;
        VW_ASSERT(f != NULL);
        VW_ASSERT_EQ(1, vw_ipc_linux_proc_net_tcp_uid(f, 0x9999, 0x0000, &uid));
        fclose(f);
    }

    VW_TEST_CASE("proc_net_tcp_uid: a matching port pair on a non-loopback address is rejected") {
        FILE *f = fmemopen((void *)PROC_NET_TCP_SAMPLE, strlen(PROC_NET_TCP_SAMPLE), "r");
        unsigned long uid = 0;
        VW_ASSERT(f != NULL);
        /* Row 3 has local port 0x5678 but a non-loopback local address
         * (7F000001, i.e. big-endian-printed 127.0.0.1 — deliberately NOT
         * loopback_be on this (little-endian test) host) paired with
         * rem=BABE — must not match even though the port pair looks right. */
        VW_ASSERT_EQ(1, vw_ipc_linux_proc_net_tcp_uid(f, 0x5678, 0xBABE, &uid));
        fclose(f);
    }

    VW_TEST_CASE("proc_net_tcp_uid: no matching port pair returns 1 (not found)") {
        FILE *f = fmemopen((void *)PROC_NET_TCP_SAMPLE, strlen(PROC_NET_TCP_SAMPLE), "r");
        unsigned long uid = 0;
        VW_ASSERT(f != NULL);
        VW_ASSERT_EQ(1, vw_ipc_linux_proc_net_tcp_uid(f, 0x0001, 0x0002, &uid));
        fclose(f);
    }

    VW_TEST_CASE("proc_net_tcp_uid: NULL stream returns 1 rather than crashing") {
        unsigned long uid = 0;
        VW_ASSERT_EQ(1, vw_ipc_linux_proc_net_tcp_uid(NULL, 1, 2, &uid));
    }
#endif /* __linux__ */

#ifdef _WIN32
    VW_TEST_CASE("win_tcp_table_pid: un-swapped query returns the daemon's own pid (the tautology this task fixed)") {
        MIB_TCPROW_OWNER_PID rows[4];
        DWORD pid = 0;
        win_mk_table(rows);
        /* our_port=0xBABE, peer_port=0x1234, queried un-swapped (local=our_port) */
        VW_ASSERT_EQ(0, vw_ipc_win_tcp_table_pid(rows, 4, 0xBABE, 0x1234, WIN_LOOPBACK_BE, &pid));
        VW_ASSERT_EQ(1000, (int)pid);
    }

    VW_TEST_CASE("win_tcp_table_pid: swapped query (the fix) returns the actual connecting client's pid") {
        MIB_TCPROW_OWNER_PID rows[4];
        DWORD pid = 0;
        win_mk_table(rows);
        /* our_port=0xBABE, peer_port=0x1234, queried swapped (local=peer_port, rem=our_port)
         * — this is exactly what vw_ipc_server_accept() now does. */
        VW_ASSERT_EQ(0, vw_ipc_win_tcp_table_pid(rows, 4, 0x1234, 0xBABE, WIN_LOOPBACK_BE, &pid));
        VW_ASSERT_EQ(4242, (int)pid);
        VW_ASSERT(pid != 1000);
    }

    VW_TEST_CASE("win_tcp_table_pid: LISTEN-state entries never match (state filter)") {
        MIB_TCPROW_OWNER_PID rows[4];
        DWORD pid = 0;
        win_mk_table(rows);
        VW_ASSERT_EQ(1, vw_ipc_win_tcp_table_pid(rows, 4, 0x9999, 0x0000, WIN_LOOPBACK_BE, &pid));
    }

    VW_TEST_CASE("win_tcp_table_pid: a matching port pair on a non-loopback address is rejected") {
        MIB_TCPROW_OWNER_PID rows[4];
        DWORD pid = 0;
        win_mk_table(rows);
        /* Row 3 has local port 0x5678 but a non-loopback local address,
         * paired with rem=BABE — must not match even though the port pair
         * looks right. */
        VW_ASSERT_EQ(1, vw_ipc_win_tcp_table_pid(rows, 4, 0x5678, 0xBABE, WIN_LOOPBACK_BE, &pid));
    }

    VW_TEST_CASE("win_tcp_table_pid: no matching port pair returns 1 (not found)") {
        MIB_TCPROW_OWNER_PID rows[4];
        DWORD pid = 0;
        win_mk_table(rows);
        VW_ASSERT_EQ(1, vw_ipc_win_tcp_table_pid(rows, 4, 0x0001, 0x0002, WIN_LOOPBACK_BE, &pid));
    }

    VW_TEST_CASE("win_tcp_table_pid: NULL rows returns 1 rather than crashing") {
        DWORD pid = 0;
        VW_ASSERT_EQ(1, vw_ipc_win_tcp_table_pid(NULL, 4, 1, 2, WIN_LOOPBACK_BE, &pid));
    }
#endif /* _WIN32 */

    VW_TEST_CASE("server_accept: same-uid loopback connection is accepted (regression: TASK-093's discovery broke every connection)") {
        vw_ipc_server_t *srv = NULL;
        vw_ipc_conn_t   *cconn = NULL, *sconn = NULL;

        VW_ASSERT_OK(vw_ipc_server_open((uint16_t)57123, &srv));
        VW_ASSERT_OK(vw_ipc_connect((uint16_t)57123, &cconn));
        VW_ASSERT_OK(vw_ipc_server_accept(srv, &sconn));

        vw_ipc_conn_close(cconn);
        vw_ipc_conn_close(sconn);
        vw_ipc_server_close(srv);
    }
}
VW_TEST_SUITE_END()
