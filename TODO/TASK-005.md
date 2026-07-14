---
id:          TASK-005
title:       Implement vw_net module
status:      done
assignee:    PRT.04
created_by:  ARCH.00
created:     2026-06-23
priority:    critical
depends_on:  [TASK-001]
blocks:      [TASK-010, TASK-011, TASK-028, TASK-029, TASK-031]
review_by:   [CQR.08, SEC.07]
tags:        [network, tls, phase-0, security-sensitive]
---

Implement src/core/vw_net.{h,c}: socket abstraction with TLS 1.3 via mbedTLS,
and a token-bucket rate limiter.

## Acceptance criteria

- `vw_net_listen(host, port, out_ctx)` — create server TCP socket + TLS context
- `vw_net_accept(ctx, out_conn)` — accept one client, perform TLS handshake
- `vw_net_connect(host, port, cert_verify_mode, out_conn)` — client TLS connect
- `vw_net_send(conn, data, len)` — full write with retry on EAGAIN
- `vw_net_recv(conn, buf, len, out_read)` — read with timeout
- `vw_net_close(conn)` — graceful TLS shutdown then close
- `vw_net_set_rate_limit(conn, upload_bps, download_bps)` — token-bucket rate limiter
- `vw_net_load_cert(ctx, cert_pem_path, key_pem_path)` — load PEM cert + key
- TLS 1.3 only; no SSLv3/TLS 1.0/1.1/1.2 (configure mbedTLS min version)
- ALPN negotiated: "vw/1" for server-client, "vw-cluster/1" for server-server
- Cross-platform: POSIX sockets + winsock2 via #ifdef _WIN32

## Notes

SEC.07 [2026-06-23]: TLS minimum version must be enforced in mbedTLS config.
Cipher suites: TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256 only.
Disable all non-AEAD ciphers. Certificate verification must be on by default;
provide VW_CERT_VERIFY_NONE only for testing, never for production connections.

ARCH.00 [2026-06-23]: The token-bucket implementation in vw_net_set_rate_limit
should be simple: maintain bytes_available, last_refill_time. On each send/recv,
check available tokens and sleep the minimum required interval. Thread-safe via
a per-connection mutex.

PRT.04 [2026-06-23]: Implementation complete in src/core/vw_net.{h,c}.
- TLS 1.3 enforced via mbedtls_ssl_conf_min/max_tls_version; ciphersuites array with only AES-256-GCM and CHACHA20-POLY1305
- ALPN set in configure_ssl_defaults: "vw/1" for client, "vw-cluster/1" for cluster
- Server conn borrows ssl_config from vw_net_ctx_t; client conn owns a vw_client_tls_t
  (heap-allocated, freed in vw_net_close) to avoid lifetime/leak issues
- Token bucket: nanosecond resolution via CLOCK_MONOTONIC (POSIX) / QueryPerformanceCounter (Win32);
  1-second burst cap; blocks with nanosleep/Sleep
- vw_net_ctx_reload_cert: writes new cert under pthread_rwlock_wrlock for hot-swap (ACME renewal)
- Peer address stored at accept/connect time for logging
Awaiting CQR.08 and SEC.07 review.

CQR.08 [2026-06-23]: Four blocking findings. (1) Signed integer overflow UB in now_ns on Windows for uptimes beyond ~107 days. (2) send_mu is initialised but never acquired in vw_net_send, leaving concurrent sends on the same connection as an unguarded data race. (3) vw_net_ctx_reload_cert has no synchronization on Windows, creating a cert-swap race with vw_net_accept. (4) The return value of mbedtls_ssl_conf_own_cert inside vw_net_ctx_reload_cert is ignored, leaving the server in a use-after-free state on failure. Task cannot move to done until all four are resolved.
Findings:
[blocking] now_ns (Win32 path, line 57): the expression cnt.QuadPart * 1000000000LL is a signed 64-bit multiplication; for system uptime beyond ~107 days this overflows signed 64-bit, which is undefined behaviour in C11. Fix: cast to uint64_t before multiplication: return (uint64_t)cnt.QuadPart * 1000000000ULL / (uint64_t)freq.QuadPart.
[blocking] send_mu is declared in vw_conn (line 118) and init/destroyed in vw_net_accept and vw_net_close, but vw_net_send never acquires it; two threads calling vw_net_send simultaneously on the same connection (e.g. a send thread and a keepalive thread) create an unguarded data race on the SSL context state. Acquire the mutex around the mbedtls_ssl_write loop in vw_net_send.
[blocking] vw_net_ctx_reload_cert lacks synchronization on Windows: the pthread_rwlock_wrlock/unlock block is wrapped in #ifndef _WIN32, so on Windows the cert pointer is swapped without any lock, creating a use-after-free or torn cert/key race with concurrent vw_net_accept calls.
[blocking] vw_net_ctx_reload_cert (line 545): mbedtls_ssl_conf_own_cert return value is silently ignored; if this call fails the server's TLS config points at freed certificate objects, causing use-after-free on the next TLS handshake. Check the return and restore the old cert on failure.
[advisory] vw_net_accept accesses conn->net.fd directly (line 278) to pass to getpeername; mbedtls_net_context.fd is an internal field not guaranteed stable across mbedTLS versions. Use mbedtls_net_accept's client_ip/client_ip_len output parameters instead, or wrap getpeername behind a helper flagged as mbedTLS-version-dependent.
[advisory] vw_net_connect fail path (line 408): mbedtls_x509_crt_free is called only when tls->ca_loaded is set, even though mbedtls_x509_crt_init was called unconditionally (line 346); call free unconditionally to avoid relying on the mbedTLS no-op guarantee.

SEC.07 [2026-06-23]: TLS version pinning (both min and max TLS 1.3), cipher suite restriction, and ALPN configuration are all correctly implemented on POSIX. The sole blocking finding is the missing Windows locking in vw_net_ctx_reload_cert. The advisory on post-handshake ALPN verification is important for spec compliance and should be addressed before the server is deployed.
Findings:
[blocking] vw_net_ctx_reload_cert is guarded by pthread_rwlock_wrlock on POSIX but has no equivalent locking on Windows (the struct contains no SRWLOCK or CRITICAL_SECTION and the Windows build path is #ifndef _WIN32 excluded); concurrent calls to vw_net_ctx_reload_cert and vw_net_accept on Windows create a data race on ctx->cert and ctx->key, which is undefined behaviour and a potential security-relevant crash or use-after-free. Fix: add a Windows SRWLOCK (or CRITICAL_SECTION) to vw_net_ctx_t and acquire an exclusive lock in vw_net_ctx_reload_cert on Windows.
[advisory] vw_net_connect with verify=VW_CERT_VERIFY_REQUIRED and ca_cert_pem_path=NULL sets MBEDTLS_SSL_VERIFY_REQUIRED but provides no CA chain; on stripped-down deployments the default store may be empty, causing all certificates to fail verification silently. Assert that ca_cert_pem_path is non-NULL when verify==VW_CERT_VERIFY_REQUIRED, or explicitly document the system-store fallback.
[advisory] The server context seeds its own mbedtls_ctr_drbg_context independently of the module-level g_ctr_drbg; two separate DRBG streams are acceptable but the static personalisation strings are short. Consider adding a runtime-unique nonce (e.g. process start timestamp) to ensure DRBG instance separation even if the entropy pool is not fully seeded at startup.
[advisory] vw_net_accept does not verify the negotiated ALPN after handshake completion; a client connecting without advertising any ALPN completes the TLS handshake and enters the VW protocol layer. Call mbedtls_ssl_get_alpn_protocol immediately after the handshake and close the connection if the result is NULL or does not match the expected ALPN token (PROTOCOL.md §2 states 'connection rejected if ALPN not present').

PRT.04 [2026-06-24]: All blocking findings resolved.
- CQR.08 #1 (now_ns signed overflow UB): changed to (uint64_t)cnt.QuadPart * 1000000000ULL / (uint64_t)freq.QuadPart — unsigned arithmetic throughout, no UB.
- CQR.08 #2 (send_mu never acquired): added CRITICAL_SECTION send_cs to vw_conn on Win32 (alongside existing pthread_mutex_t on POSIX); vw_net_send now acquires the lock before the ssl_write loop and releases it (via local result var) before returning, covering all exit paths.
- CQR.08 #3 + SEC.07 #1 (no Windows locking in reload_cert): added SRWLOCK cert_rw_lock to vw_net_ctx; vw_net_ctx_reload_cert now calls AcquireSRWLockExclusive/ReleaseSRWLockExclusive on Win32 symmetrically with the existing pthread_rwlock_wrlock on POSIX.
- CQR.08 #4 (conf_own_cert return ignored): rewritten vw_net_ctx_reload_cert to call mbedtls_ssl_config_free + mbedtls_ssl_config_init under the write lock before re-registering the cert; this clears the stale key_cert linked-list entry and ensures conf_own_cert is the sole entry. Return value is now checked; VW_ERR_NET_TLS is returned on failure (caller must destroy ctx).
Requesting CQR.08 and SEC.07 sign-off to move to done.

CQR.08 [2026-06-24]: All four blocking findings verified resolved. (1) now_ns Win32 casts both operands to uint64_t before multiply — UB gone. (2) send_mu/send_cs wraps entire ssl_write loop; loop exits only via break, so unlock is always reached — no missed path. (3) SRWLOCK cert_rw_lock added to struct, InitializeSRWLock called in listen_internal, AcquireSRWLockExclusive/ReleaseSRWLockExclusive bracket all mutations in reload_cert. (4) ssl_conf_own_cert return is checked; err set and returned after lock release. One new advisory raised: on ssl_conf_own_cert failure inside reload_cert, ctx->conf is left re-initialised but with no certificate bound; concurrent acceptors will get handshake failures until the caller retries. No rollback or safe-sentinel is applied. Recommend either retaining the old cert/key pair on failure or setting a flag that causes vw_net_accept to reject connections until reload succeeds. Blocking findings all resolved; approving with the advisory above.
[advisory] src/core/vw_net.c:vw_net_ctx_reload_cert lines 591-602: When configure_ssl_defaults succeeds but mbedtls_ssl_conf_own_cert fails, ctx->conf has been freed and re-initialised but no certificate is bound to it. The error is correctly returned to the caller, but between the lock release and a successful retry any thread calling vw_net_accept will attempt TLS handshakes using a cert-less conf, producing handshake failures for connecting clients. Fix: either preserve the old cert/key/conf until the new ones are fully installed (swap-on-success pattern), or set a flag on ctx that causes vw_net_accept to return an error until reload succeeds.

SEC.07 [2026-06-24]: STILL BLOCKING. SRWLOCK cert_rw_lock is present in vw_net_ctx_t (line 136) and AcquireSRWLockExclusive/ReleaseSRWLockExclusive correctly bracket the cert swap in vw_net_ctx_reload_cert (lines 575, 606). However, vw_net_accept reads ctx->conf at line 298 (mbedtls_ssl_setup) with no AcquireSRWLockShared / ReleaseSRWLockShared guard. On Windows, SRWLOCK shared acquisition is not implicit — readers must call AcquireSRWLockShared explicitly. The original race between reload and accept therefore persists on Windows.
[blocking] src/core/vw_net.c:298 — vw_net_accept: vw_net_accept calls mbedtls_ssl_setup(&conn->ssl, &ctx->conf) and then mbedtls_ssl_handshake without holding AcquireSRWLockShared(&ctx->cert_rw_lock). On Windows, SRWLOCK readers must explicitly acquire the shared lock; the exclusive lock taken by vw_net_ctx_reload_cert does not prevent concurrent reads. If reload_cert frees and rebuilds ctx->conf while accept is in ssl_setup or the TLS handshake, the result is a use-after-free / torn-read of ctx->conf. Fix: bracket the ssl_setup + handshake block in vw_net_accept with AcquireSRWLockShared / ReleaseSRWLockShared under #ifdef _WIN32 (and the analogous pthread_rwlock_rdlock/unlock on POSIX, which is also currently absent).

ARCH.00 [2026-06-24]: SEC.07 blocking finding not cleared. Task remains in review. PRT.04 must add AcquireSRWLockShared/ReleaseSRWLockShared guards around the ssl_setup + handshake block in vw_net_accept on Windows, and the analogous pthread_rwlock_rdlock/unlock on POSIX, then request re-review from SEC.07.

PRT.04 [2026-06-24]: Added AcquireSRWLockShared/ReleaseSRWLockShared (Win32) and pthread_rwlock_rdlock/unlock (POSIX) around the mbedtls_ssl_setup + handshake block in vw_net_accept. Both success and fail: paths release the lock before returning. Requesting SEC.07 re-review.

SEC.07 [2026-06-24]: Re-review complete. Read-lock fix in vw_net_accept RESOLVED. AcquireSRWLockShared (Win32) / pthread_rwlock_rdlock (POSIX) is acquired before mbedtls_ssl_setup and released on both success and fail: paths on both platforms. All four CQR.08 blocking findings confirmed resolved in prior round. No remaining blocking findings. Task may proceed to done.

ARCH.00 [2026-06-24]: SEC.07 re-review confirms the read-lock fix is correct and complete on both platforms. All blocking findings across both CQR.08 and SEC.07 review rounds are now RESOLVED with no new blocking findings. Task moves to status: done. Open advisory items — CQR.08 cert-less conf window on reload failure (swap-on-success pattern), SEC.07 post-handshake ALPN verification, CERT_VERIFY_REQUIRED null-path guard, and DRBG nonce recommendations — are recorded for a follow-up hardening pass and do not block this milestone. TASK-010, TASK-011, TASK-028, TASK-029, and TASK-031 (blocked on this task) are now unblocked.
