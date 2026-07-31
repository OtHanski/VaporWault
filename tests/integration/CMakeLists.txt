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
