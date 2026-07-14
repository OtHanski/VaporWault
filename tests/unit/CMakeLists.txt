# Unit test harness — pure C, hand-rolled TAP v13, no external framework.
# Each test executable exits 0 on pass, non-zero on failure.
#
# vw_add_unit_test(name source) — standard helper for tests that only need
# vw_core.  Oplog tests use a custom add_executable below (vw_oplog.c is a
# server-only source; must be compiled directly into the test binary with a
# reduced VW_OPLOG_SEGMENT_MAX to make segment-rotation tests practical).

cmake_minimum_required(VERSION 3.16)

function(vw_add_unit_test name source)
    add_executable(test_${name} ${source})
    target_include_directories(test_${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_${name} PRIVATE vw_core pthread)
    add_test(NAME unit_${name} COMMAND test_${name})
endfunction()

# ── Phase 0 / 1 unit tests ────────────────────────────────────────────────

vw_add_unit_test(vw_crypto  ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_crypto.c)
vw_add_unit_test(vw_fs      ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_fs.c)

# ── Oplog crash-injection tests (CJ-1 through CJ-5) ──────────────────────
#
# vw_oplog.c lives in src/server and is not part of vw_core.  Compile it
# directly into the test binary.
#
# VW_OPLOG_SEGMENT_MAX is overridden to 512 bytes so CJ-5 can trigger
# segment rotation with ~25 appends instead of the production 64 MiB.
# Both the test source and vw_oplog.c are compiled with this definition,
# so the embedded implementation uses the test-scoped value.

add_executable(test_vw_oplog
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
)

target_compile_definitions(test_vw_oplog PRIVATE
    VW_OPLOG_SEGMENT_MAX=512
)

target_include_directories(test_vw_oplog PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_vw_oplog PRIVATE vw_core pthread)

add_test(NAME unit_vw_oplog COMMAND test_vw_oplog)

vw_add_unit_test(vw_proto ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_proto.c)

# ── Phase 3 unit tests ────────────────────────────────────────────────────

# vw_net lives in vw_core, so the standard helper suffices.
vw_add_unit_test(vw_net ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_net.c)

# vw_smtp.c lives in src/server and is not part of vw_core.  Compile it
# directly into the test binary (same pattern as test_vw_oplog).
add_executable(test_vw_smtp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
)
target_include_directories(test_vw_smtp PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_vw_smtp PRIVATE vw_core pthread)
add_test(NAME unit_vw_smtp COMMAND test_vw_smtp)

# ── Phase 8 unit tests ────────────────────────────────────────────────────
#
# vw_auth and vw_store tests link against vw_server_lib (all server modules
# compiled with default settings).
#
# vw_gc test compiles the relevant server sources directly with a reduced
# VW_OPLOG_SEGMENT_MAX=512 (same as the oplog crash-injection tests) so that
# segment rotation — and therefore oplog truncation — can be triggered with
# ~50 small entries instead of requiring 64 MiB of oplog data.
# vw_cluster.c is NOT included; test_vw_gc.c provides stubs for the two
# cluster functions called by vw_gc.c.

if(TARGET vw_server_lib)
    add_executable(test_vw_auth
        ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_auth.c
    )
    target_include_directories(test_vw_auth PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_vw_auth PRIVATE vw_server_lib)
    add_test(NAME unit_vw_auth COMMAND test_vw_auth)

    add_executable(test_vw_store
        ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_store.c
    )
    target_include_directories(test_vw_store PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_vw_store PRIVATE vw_server_lib)
    add_test(NAME unit_vw_store COMMAND test_vw_store)
endif()

# test_vw_gc: compiled directly (no vw_server_lib) so VW_OPLOG_SEGMENT_MAX
# can be overridden without conflicting with vw_server_lib's vw_oplog.c.
add_executable(test_vw_gc
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_storage.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
)

target_compile_definitions(test_vw_gc PRIVATE
    VW_OPLOG_SEGMENT_MAX=512
)

target_include_directories(test_vw_gc PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)

target_link_libraries(test_vw_gc PRIVATE vw_core pthread)

add_test(NAME unit_vw_gc COMMAND test_vw_gc)
