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
