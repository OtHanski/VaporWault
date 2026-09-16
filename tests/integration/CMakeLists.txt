# Integration tests — run a real server over localhost TLS.
#
# test_auth_handshake: full login roundtrip (TASK-011 acceptance criterion).
# Links server and client modules directly into the test binary so it needs
# no running processes.
#
# Argon2id is slow (64 MiB, 3 passes per hash).  Allow up to 120 s in CI.

cmake_minimum_required(VERSION 3.18)

add_executable(test_auth_handshake
    ${CMAKE_CURRENT_SOURCE_DIR}/test_auth_handshake.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_server_core.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth_provider.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_recovery.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_invite.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_share.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
)

target_include_directories(test_auth_handshake PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_auth_handshake PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_auth_handshake PRIVATE pthread)
endif()

if(WIN32)
    target_link_libraries(test_auth_handshake PRIVATE ws2_32)
endif()

add_test(NAME integration_auth_handshake
         COMMAND test_auth_handshake)

set_tests_properties(integration_auth_handshake PROPERTIES
    TIMEOUT 120
    LABELS  "integration;auth"
)

# test_proto_recv_drain: TASK-155 regression — vw_proto_recv used to leave
# a too-large message's payload bytes queued on the wire when it returned
# VW_ERR_PROTO_TOO_LARGE, permanently desyncing the connection's next
# recv. Only needs vw_core (vw_proto.c + vw_net.c) — no server/auth stack,
# unlike test_auth_handshake.

add_executable(test_proto_recv_drain
    ${CMAKE_CURRENT_SOURCE_DIR}/test_proto_recv_drain.c
)

target_include_directories(test_proto_recv_drain PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_proto_recv_drain PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_proto_recv_drain PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_proto_recv_drain PRIVATE ws2_32)
endif()

add_test(NAME integration_proto_recv_drain
         COMMAND test_proto_recv_drain)

set_tests_properties(integration_proto_recv_drain PROPERTIES
    TIMEOUT 60
    LABELS  "integration;protocol"
)

# test_net_dns_timeout: TASK-00305 — connect_with_timeout()'s bounded-DNS
# helper must bound total wall-clock time (DNS + connect), not just the
# connect phase. Compiles its own copy of vw_net.c (not vw_core, which
# already contains an un-hooked build of it) with VW_NET_DNS_TEST_HOOK so
# a fake resolver can simulate slow/unresponsive DNS deterministically.
# Links MbedTLS directly (same as vw_core's own PUBLIC dependency in
# src/core/CMakeLists.txt) rather than vw_core itself, since this target
# supplies its own vw_net.c object and must not pull the un-hooked one
# from the vw_core archive.

add_executable(test_net_dns_timeout
    ${CMAKE_CURRENT_SOURCE_DIR}/test_net_dns_timeout.c
    ${CMAKE_SOURCE_DIR}/src/core/vw_net.c
)
target_compile_definitions(test_net_dns_timeout PRIVATE VW_NET_DNS_TEST_HOOK)
target_include_directories(test_net_dns_timeout PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_net_dns_timeout PRIVATE MbedTLS::mbedtls)
if(UNIX)
    target_link_libraries(test_net_dns_timeout PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_net_dns_timeout PRIVATE ws2_32)
endif()

add_test(NAME integration_net_dns_timeout COMMAND test_net_dns_timeout)
set_tests_properties(integration_net_dns_timeout PROPERTIES
    TIMEOUT 60
    LABELS  "integration;network"
)

# test_update_net: TASK-00296 — outbound HTTPS GET client for the client
# auto-update feature. Compiles its own copy of vw_update_net.c with
# VW_UPDATE_NET_TEST_HOOKS (redirects the connect step at a local
# self-signed test server instead of the real system-trust-store path,
# which no local server can satisfy) and a short VW_UPDATE_RECV_TIMEOUT_MS
# (same VW_ECC_MAX_DATA_SHARDS-style override convention as
# test_repair_pipeline) so the timeout-enforcement case is fast.

add_executable(test_update_net
    ${CMAKE_CURRENT_SOURCE_DIR}/test_update_net.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update_net.c
)
target_compile_definitions(test_update_net PRIVATE
    VW_UPDATE_NET_TEST_HOOKS
    VW_UPDATE_RECV_TIMEOUT_MS=1500
    VW_UPDATE_CONNECT_TIMEOUT_MS=2000
    VW_UPDATE_TOTAL_READ_DEADLINE_SECS=3
    VW_UPDATE_REDIRECT_ALLOWED_SUFFIX_1=\"127.0.0.1\"
)
target_include_directories(test_update_net PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_update_net PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_update_net PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_update_net PRIVATE ws2_32)
endif()
add_test(NAME integration_update_net COMMAND test_update_net)
set_tests_properties(integration_update_net PROPERTIES
    TIMEOUT 60
    LABELS  "integration;update"
)

# test_update_manifest: TASK-00297 — update-manifest fetch/verify/parse/
# rollback-ratchet pipeline. VW_UPDATE_NET_TEST_HOOKS (vw_update_net.c) +
# VW_UPDATE_GITHUB_HOST/_PORT/_MANIFEST_PATH/_SIG_PATH (vw_update_manifest.c)
# together redirect the whole pipeline at a local self-signed test server;
# every test manifest is signed with the real update-manifest private key
# and verified against the real compiled-in VW_UPDATE_MANIFEST_PUBKEY.
add_executable(test_update_manifest
    ${CMAKE_CURRENT_SOURCE_DIR}/test_update_manifest.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update_net.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update_manifest.c
)
target_compile_definitions(test_update_manifest PRIVATE
    VW_UPDATE_NET_TEST_HOOKS
    VW_UPDATE_GITHUB_HOST=\"127.0.0.1\"
    VW_UPDATE_PORT=43771
    VW_UPDATE_MANIFEST_PATH=\"/update-manifest.json\"
    VW_UPDATE_MANIFEST_SIG_PATH=\"/update-manifest.json.sig\"
)
target_include_directories(test_update_manifest PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_update_manifest PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_update_manifest PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_update_manifest PRIVATE ws2_32)
endif()
add_test(NAME integration_update_manifest COMMAND test_update_manifest)
set_tests_properties(integration_update_manifest PROPERTIES
    TIMEOUT 60
    LABELS  "integration;update"
)

# test_proto_update_hint: TASK-00292 — HELLO_OK/VERSION_REJECT's new optional
# trailing update-hint block. Only needs vw_core (vw_proto.c + vw_net.c) —
# no server/auth stack, same rationale as test_proto_recv_drain above.

add_executable(test_proto_update_hint
    ${CMAKE_CURRENT_SOURCE_DIR}/test_proto_update_hint.c
)

target_include_directories(test_proto_update_hint PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_proto_update_hint PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_proto_update_hint PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_proto_update_hint PRIVATE ws2_32)
endif()

add_test(NAME integration_proto_update_hint
         COMMAND test_proto_update_hint)

set_tests_properties(integration_proto_update_hint PROPERTIES
    TIMEOUT 60
    LABELS  "integration;protocol"
)

# test_update_apply, test_ipc_update, test_updater_main all need the real
# built vapourwault-updater/-daemon/-cli binaries (VW_BUILD_CLIENT targets,
# defined in src/client/CMakeLists.txt), which don't exist in a
# VW_BUILD_CLIENT=OFF configuration (e.g. the server-only Fuzz build) — CI
# fix, 2026-09-16: CMake configure failed with "No target
# vapourwault-updater" et al. when this file was still unconditionally
# generating these three targets.
if(VW_BUILD_CLIENT)

# test_update_apply: TASK-00298 — vw_update_download_and_verify_asset()
# and vw_update_stage_and_apply()'s extraction/payload-directory-resolution
# logic. Compiles its own copy of vw_update_net.c + vw_update.c with
# VW_UPDATE_NET_TEST_HOOKS (connect hook) plus VW_UPDATE_GITHUB_HOST/_PORT
# (vw_update.c now follows the same override-macro convention
# vw_update_manifest.c already established — CQR.08 finding, TASK-00298
# review — so this target no longer needs a host-ignoring connect hook).
# Needs the real built vapourwault-updater binary (VW_UPDATER_EXE_PATH)
# copied into a fake install_dir so vw_update_stage_and_apply's own spawn
# step succeeds.

add_executable(test_update_apply
    ${CMAKE_CURRENT_SOURCE_DIR}/test_update_apply.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update_net.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update_manifest.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_update.c
)
add_dependencies(test_update_apply vapourwault-updater)
target_compile_definitions(test_update_apply PRIVATE
    VW_UPDATE_NET_TEST_HOOKS
    VW_UPDATE_GITHUB_HOST=\"127.0.0.1\"
    VW_UPDATE_PORT=43772
    VW_UPDATER_EXE_PATH=\"$<TARGET_FILE:vapourwault-updater>\"
    VW_TEST_SCRATCH_ROOT=\"${CMAKE_BINARY_DIR}/test_scratch\"
)
target_include_directories(test_update_apply PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_update_apply PRIVATE vw_core vw_version)
if(UNIX)
    target_link_libraries(test_update_apply PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_update_apply PRIVATE ws2_32)
endif()
add_test(NAME integration_update_apply COMMAND test_update_apply)
set_tests_properties(integration_update_apply PROPERTIES
    TIMEOUT 60
    LABELS  "integration;update"
)

# test_ipc_update: TASK-00299 — the UPDATE_* IPC messages and the
# "vapourwault-cli update ..." subcommand group, exercised end-to-end
# against the real built vapourwault-daemon + vapourwault-cli binaries.
# No server/account needed — every UPDATE_* message is daemon-global.

add_executable(test_ipc_update
    ${CMAKE_CURRENT_SOURCE_DIR}/test_ipc_update.c
)
add_dependencies(test_ipc_update vapourwault-daemon vapourwault-cli)
target_compile_definitions(test_ipc_update PRIVATE
    VW_DAEMON_EXE_PATH=\"$<TARGET_FILE:vapourwault-daemon>\"
    VW_CLI_EXE_PATH=\"$<TARGET_FILE:vapourwault-cli>\"
)
# Root-caused (CLI.02, 2026-09-16 — see TASK-00299's Notes for the full
# investigation and TASK-00306 for the underlying daemon-loop finding
# filed separately): this test's daemon.conf pins sync_interval_ms to 200
# (not the real 30000 default) specifically to avoid tripping
# vw_watcher_wait()'s "blocks for the full timeout when there are zero
# watched roots" behavior — with the real default, two IPC requests
# issued moments apart (exactly what this test does) could
# non-deterministically make the second one wait up to 30 real seconds
# for the daemon's main loop to cycle back to its IPC-accept step. This
# was originally misdiagnosed as a ctest-launch-specific sandbox artifact
# before being root-caused via a debug build; see git history on this
# file for that earlier (incorrect) comment.
add_test(NAME integration_ipc_update COMMAND test_ipc_update)
set_tests_properties(integration_ipc_update PROPERTIES
    TIMEOUT 60
    LABELS  "integration;update;ipc"
)

# test_updater_main: TASK-00298 — the standalone vapourwault-updater helper
# (src/client/vw_updater_main.c). Invokes the REAL built binary as a
# subprocess (it deliberately has no vw_core linkage — see its own header
# comment — so this is the only way to test it as what actually ships)
# rather than compiling its source into the test.

add_executable(test_updater_main
    ${CMAKE_CURRENT_SOURCE_DIR}/test_updater_main.c
)
add_dependencies(test_updater_main vapourwault-updater)
target_compile_definitions(test_updater_main PRIVATE
    VW_UPDATER_EXE_PATH=\"$<TARGET_FILE:vapourwault-updater>\"
)
target_include_directories(test_updater_main PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/unit
)
add_test(NAME integration_updater_main COMMAND test_updater_main)
set_tests_properties(integration_updater_main PROPERTIES
    TIMEOUT 60
    LABELS  "integration;update"
)

endif() # VW_BUILD_CLIENT

# test_file_list_vault_id: TASK-156 regression — FILE_LIST_RESP now carries
# a per-entry vault_id (it never did before). Needs the full server module
# set (same list as vw_server_lib / test_vw_file_handlers, duplicated here
# for the same reason those two do — see vw_server_lib's own CMakeLists
# comment) since handle_file_list's dispatch path pulls in most of it.

add_executable(test_file_list_vault_id
    ${CMAKE_CURRENT_SOURCE_DIR}/test_file_list_vault_id.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_server_core.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_file_handlers.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_storage.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ecc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth_provider.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_admin.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_acme.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ddns.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_scrub.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_repair.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_invite.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_recovery.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_cluster.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_conn_registry.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_share.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_vault.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
)

target_include_directories(test_file_list_vault_id PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_file_list_vault_id PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_file_list_vault_id PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_file_list_vault_id PRIVATE ws2_32)
endif()

add_test(NAME integration_file_list_vault_id
         COMMAND test_file_list_vault_id)

set_tests_properties(integration_file_list_vault_id PROPERTIES
    TIMEOUT 60
    LABELS  "integration;protocol;vault"
)

# test_cluster_repair_fetch (TASK-259): real primary+replica pair, real
# TLS/NODE_HELLO/primary_repl_loop/replica_repl_session machinery — same
# full server-module set as test_file_list_vault_id above (a proven-to-link
# combination for anything pulling in vw_cluster.c), minus the client-only
# vw_client_core.c this test doesn't need.
add_executable(test_cluster_repair_fetch
    ${CMAKE_CURRENT_SOURCE_DIR}/test_cluster_repair_fetch.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_server_core.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_file_handlers.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_storage.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ecc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth_provider.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_admin.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_acme.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ddns.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_scrub.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_repair.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_invite.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_recovery.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_cluster.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_conn_registry.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_share.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_vault.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
)

target_include_directories(test_cluster_repair_fetch PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_cluster_repair_fetch PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_cluster_repair_fetch PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_cluster_repair_fetch PRIVATE ws2_32)
endif()
add_test(NAME integration_cluster_repair_fetch COMMAND test_cluster_repair_fetch)
set_tests_properties(integration_cluster_repair_fetch PROPERTIES
    TIMEOUT 60
    LABELS  "integration;cluster"
)

# test_repair_pipeline (TASK-260): full vw_repair_chunk pipeline against a
# real primary+replica pair — same full server-module set as
# test_cluster_repair_fetch above, plus VW_ECC_MAX_DATA_SHARDS overridden
# small (same reasoning as test_vw_storage_parity's own override) so a
# parity group seals after a handful of chunks. Safe to apply build-wide
# for this target: vw_cluster.c/vw_file_handlers.c include vw_storage.h
# (hence see the override) but never reference the macro's value
# themselves.
add_executable(test_repair_pipeline
    ${CMAKE_CURRENT_SOURCE_DIR}/test_repair_pipeline.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_server_core.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_file_handlers.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_storage.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ecc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_repair.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth_provider.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_admin.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_acme.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ddns.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_scrub.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_invite.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_recovery.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_cluster.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_conn_registry.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_share.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_vault.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
)

target_compile_definitions(test_repair_pipeline PRIVATE
    VW_ECC_MAX_DATA_SHARDS=4
)

target_include_directories(test_repair_pipeline PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_repair_pipeline PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_repair_pipeline PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_repair_pipeline PRIVATE ws2_32)
endif()
add_test(NAME integration_repair_pipeline COMMAND test_repair_pipeline)
set_tests_properties(integration_repair_pipeline PROPERTIES
    TIMEOUT 60
    LABELS  "integration;cluster"
)

# test_vault_e2ee: TASK-099 client vault module, end-to-end against a real
# already-running server (unlike test_auth_handshake, this does NOT self-host
# one — see test_vault_e2ee.c's file header). No ctest add_test entry here:
# it needs a live server + a created user, which only the pytest wrapper
# (test_vault_e2ee.py, which reuses conftest.py's `server`/`admin_client`
# fixtures) knows how to provide — same reason the rest of the pytest
# integration suite isn't wired into ctest either.

add_executable(test_vault_e2ee
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vault_e2ee.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_vault.c
)

target_include_directories(test_vault_e2ee PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_vault_e2ee PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vault_e2ee PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_vault_e2ee PRIVATE ws2_32)
endif()

# test_vault_regression: TASK-101 E2EE regression suite (dedup-defeat,
# key-loss scoping, multi-chunk round-trip, realistic-scale retry safety).
# Same rationale as test_vault_e2ee for not using ctest add_test directly.

add_executable(test_vault_regression
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vault_regression.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_vault.c
)

target_include_directories(test_vault_regression PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_vault_regression PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vault_regression PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_vault_regression PRIVATE ws2_32)
endif()

# test_shared_sync: TASK-106 sync engine shared-folder support, end-to-end
# against a real already-running server. Drives vw_sync.c's shared-folder
# branch directly (there is no daemon process involved, unlike the IPC
# plumbing added for TASK-106 Task #20 — this exercises the sync engine
# itself, the thing that actually moves bytes). Same rationale as
# test_vault_e2ee for not using ctest add_test directly: needs a live
# server + two created users, which only the pytest wrapper
# (test_shared_sync.py) knows how to provide.

add_executable(test_shared_sync
    ${CMAKE_CURRENT_SOURCE_DIR}/test_shared_sync.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_cache.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_sync.c
)

target_include_directories(test_shared_sync PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_shared_sync PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_shared_sync PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_shared_sync PRIVATE ws2_32)
endif()

# test_search: TASK-198 SEARCH/SEARCH_RESP (docs/PROTOCOL.md §7.12),
# end-to-end against a real already-running server with three real users
# (owner, grantee, stranger). No vw_client_search() wrapper exists yet
# (TASK-199) so this hand-drives the raw wire message via vw_client_conn()
# + vw_proto_send/recv directly, rather than waiting for that wrapper —
# same "needs a live server + created users" rationale as test_shared_sync
# for using the pytest wrapper (test_search.py) instead of ctest add_test.

add_executable(test_search
    ${CMAKE_CURRENT_SOURCE_DIR}/test_search.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
)

target_include_directories(test_search PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_search PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_search PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_search PRIVATE ws2_32)
endif()

# test_daemon_multi_account: TASK-161 daemon multi-account core. Replicates
# vw_daemon_run()'s new round-robin loop (one vw_sync_run() per account per
# tick) directly against a real already-running server with two real users,
# rather than spawning the actual vapourwault-daemon binary and speaking
# real IPC (TASK-168's job, for the fuller multi-account IPC surface) — same
# "drive the real sync engine directly" rationale as test_shared_sync above.

add_executable(test_daemon_multi_account
    ${CMAKE_CURRENT_SOURCE_DIR}/test_daemon_multi_account.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_cache.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_sync.c
)

target_include_directories(test_daemon_multi_account PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_daemon_multi_account PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_daemon_multi_account PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_daemon_multi_account PRIVATE ws2_32)
endif()

# test_shared_sync_hardening: TASK-111 regression tests for the two advisory
# findings from TASK-106's independent review (revocation-detection too
# coarse; unbounded shared-tree BFS). Built with VW_SYNC_TEST_HOOKS so its
# own compiled copy of vw_sync.c exposes vw_sync_test_before_list_dir — a
# hook that exists in NO other target here (including test_shared_sync
# above), letting this test deterministically inject the subdirectory-
# delete TOCTOU race instead of racing real threads against real network
# timing. Same rationale as test_shared_sync for not using ctest add_test
# directly.

add_executable(test_shared_sync_hardening
    ${CMAKE_CURRENT_SOURCE_DIR}/test_shared_sync_hardening.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_cache.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_sync.c
)

target_include_directories(test_shared_sync_hardening PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_compile_definitions(test_shared_sync_hardening PRIVATE VW_SYNC_TEST_HOOKS)

target_link_libraries(test_shared_sync_hardening PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_shared_sync_hardening PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_shared_sync_hardening PRIVATE ws2_32)
endif()

# test_shared_sync_mkdir: TASK-113 regression tests — a shared folder's
# locally-new subdirectory (with no server-side counterpart) auto-creates
# it via FILE_MKDIR when the grantee has EDIT permission, recursively for
# however many missing ancestor levels, instead of retrying the same no-op
# forever; a VIEW-only grantee's blocked attempt is counted distinctly
# (vw_sync_permission_denied_count) rather than folded into the generic
# action-error count, without auto-pausing the folder or allowing an
# unauthorized write. Same rationale as test_shared_sync for not using
# ctest add_test directly.

add_executable(test_shared_sync_mkdir
    ${CMAKE_CURRENT_SOURCE_DIR}/test_shared_sync_mkdir.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_cache.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_sync.c
)

target_include_directories(test_shared_sync_mkdir PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
)

target_link_libraries(test_shared_sync_mkdir PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_shared_sync_mkdir PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_shared_sync_mkdir PRIVATE ws2_32)
endif()

# ── Python integration test suite (TASK-038) ─────────────────────────────────
# Starts real vapourwaultd + vapourwault-daemon binaries, exercises IT-1..IT-8.
# Requires: openssl (for cert generation), Python 3.7+, POSIX.
# Guard: only built/registered when both server and client targets are present.

if(VW_BUILD_TESTS AND VW_BUILD_SERVER AND VW_BUILD_CLIENT AND NOT WIN32)
    find_package(Python3 QUIET COMPONENTS Interpreter)

    if(Python3_FOUND)
        add_test(NAME integration
            COMMAND
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/run_integration.py
                --server $<TARGET_FILE:vapourwaultd>
                --daemon $<TARGET_FILE:vapourwault-daemon>
                --admin-cli $<TARGET_FILE:vapourwault-server-cli>
                --cli $<TARGET_FILE:vapourwault-cli>
        )

        set_tests_properties(integration PROPERTIES
            TIMEOUT 180
            LABELS  "integration;phase5"
        )
    endif()
endif()
