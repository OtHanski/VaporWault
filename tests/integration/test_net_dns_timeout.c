/*
 * test_net_dns_timeout.c — TASK-00305 regression.
 *
 * connect_with_timeout()'s bounded-DNS-resolution helper
 * (dns_resolve_bounded() in src/core/vw_net.c) must bound the TOTAL
 * wall-clock time of DNS resolution + connect by (approximately)
 * connect_timeout_ms, not just the connect phase alone — before this fix,
 * getaddrinfo() had no timeout of its own and could stall a caller for
 * the OS resolver's own internal retry budget (well past a minute in the
 * sandbox that found this; see TASK-00305 for the full incident).
 *
 * Compiles src/core/vw_net.c directly (not vw_core, which already
 * contains an un-hooked build of the same file) with
 * -DVW_NET_DNS_TEST_HOOK so vw_net_test_set_dns_resolver() can substitute
 * a fake resolver — simulating a real slow/unresponsive DNS scenario
 * deterministically, rather than depending on actual network conditions.
 * Same test-hook convention as VW_UPDATE_NET_TEST_HOOKS elsewhere in this
 * codebase.
 *
 * TC-1: a resolver that sleeps well past connect_timeout_ms before
 *       returning a valid address — the connect call must still return
 *       within roughly connect_timeout_ms, not the full sleep duration.
 * TC-2: a resolver that fails immediately (simulating NXDOMAIN) — must
 *       fail promptly, no timing regression from the fix.
 * TC-3: no hook installed — the real getaddrinfo() fast path (numeric
 *       loopback address, refused port) behaves exactly as it did before
 *       this fix — same case as test_vw_net.c's TC-6.
 */

#include "vw_test.h"
#include "vw_net.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <time.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

static void sleep_ms(unsigned ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

/* TC-1: sleeps 3000ms (well past any timeout used below), then resolves
 * to loopback via the real resolver — proving it's the WAIT that gets
 * bounded, not just the fact that resolution eventually succeeds. */
static int slow_resolver(const char *host, const char *port_str,
                          struct addrinfo **out_res) {
    (void)host;
    sleep_ms(3000);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    return getaddrinfo("127.0.0.1", port_str, &hints, out_res);
}

/* TC-2: fails immediately (simulates NXDOMAIN / resolver error). */
static int failing_resolver(const char *host, const char *port_str,
                             struct addrinfo **out_res) {
    (void)host; (void)port_str;
    *out_res = NULL;
    return -1;
}

VW_TEST_SUITE("vw_net_dns_timeout") {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    VW_TEST_CASE("TC-1: slow DNS resolver is bounded by connect_timeout_ms") {
        vw_net_test_set_dns_resolver(slow_resolver);

        vw_conn_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.connect_timeout_ms = 300;

        vw_conn_t *c = NULL;
        uint64_t start = now_ms();
        vw_err_t err = vw_net_connect_generic("dns-timeout-test.invalid", 1,
                                               VW_CERT_VERIFY_NONE, NULL,
                                               &opts, &c);
        uint64_t elapsed = now_ms() - start;

        vw_net_test_set_dns_resolver(NULL);

        VW_ASSERT(err != VW_OK);
        VW_ASSERT(c == NULL);
        /* Generous slack for CI scheduling jitter around the 300ms bound,
         * while still being nowhere near the resolver's 3000ms sleep —
         * before TASK-00305's fix this would have taken >=3000ms here. */
        VW_ASSERT(elapsed < 2000);
    }

    VW_TEST_CASE("TC-2: a resolver that fails immediately fails promptly") {
        vw_net_test_set_dns_resolver(failing_resolver);

        vw_conn_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.connect_timeout_ms = 2000;

        vw_conn_t *c = NULL;
        uint64_t start = now_ms();
        vw_err_t err = vw_net_connect_generic("dns-timeout-test.invalid", 1,
                                               VW_CERT_VERIFY_NONE, NULL,
                                               &opts, &c);
        uint64_t elapsed = now_ms() - start;

        vw_net_test_set_dns_resolver(NULL);

        VW_ASSERT(err != VW_OK);
        VW_ASSERT(c == NULL);
        VW_ASSERT(elapsed < 1000);
    }

    VW_TEST_CASE("TC-3: no hook installed — real getaddrinfo fast path unaffected") {
        /* Same case as test_vw_net.c's TC-6: port 1 on loopback is
         * virtually guaranteed refused, and 127.0.0.1 is a numeric
         * address a resolver answers immediately — this proves the
         * bounded-DNS change didn't regress the ordinary path. */
        vw_conn_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.connect_timeout_ms = 2000;

        vw_conn_t *c = NULL;
        uint64_t start = now_ms();
        vw_err_t err = vw_net_connect_generic("127.0.0.1", 1,
                                               VW_CERT_VERIFY_NONE, NULL,
                                               &opts, &c);
        uint64_t elapsed = now_ms() - start;

        VW_ASSERT(err != VW_OK);
        VW_ASSERT(c == NULL);
        VW_ASSERT(elapsed < 1000);
    }
}
VW_TEST_SUITE_END()
