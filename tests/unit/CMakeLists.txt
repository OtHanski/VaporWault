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
    target_link_libraries(test_${name} PRIVATE vw_core)
    if(UNIX)
        target_link_libraries(test_${name} PRIVATE pthread)
    endif()
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

target_link_libraries(test_vw_oplog PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_oplog PRIVATE pthread)
endif()

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
target_link_libraries(test_vw_smtp PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_smtp PRIVATE pthread)
endif()
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

    add_executable(test_vw_share
        ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_share.c
    )
    target_include_directories(test_vw_share PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_vw_share PRIVATE vw_server_lib)
    add_test(NAME unit_vw_share COMMAND test_vw_share)

    add_executable(test_vw_vault
        ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_vault.c
    )
    target_include_directories(test_vw_vault PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_vw_vault PRIVATE vw_server_lib)
    add_test(NAME unit_vw_vault COMMAND test_vw_vault)

    add_executable(test_vw_notify
        ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_notify.c
    )
    target_include_directories(test_vw_notify PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/client
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    target_link_libraries(test_vw_notify PRIVATE vw_server_lib)
    add_test(NAME unit_vw_notify COMMAND test_vw_notify)
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
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
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

target_link_libraries(test_vw_gc PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_gc PRIVATE pthread)
endif()

add_test(NAME unit_vw_gc COMMAND test_vw_gc)

# ── vw_ipc (TASK-093: peer-UID verification) ─────────────────────────────
#
# vw_ipc.c lives in src/client and is not part of vw_core. Compile it
# directly into the test binary (same pattern as test_vw_oplog/test_vw_smtp).
add_executable(test_vw_ipc
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_ipc.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_ipc.c
)
target_include_directories(test_vw_ipc PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_vw_ipc PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_ipc PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_vw_ipc PRIVATE ws2_32)
endif()
add_test(NAME unit_vw_ipc COMMAND test_vw_ipc)

# ── vw_sync (TASK-114) ────────────────────────────────────────────────────
#
# vw_sync.c lives in src/client and is not part of vw_core; compiled
# directly into the test binary (same pattern as test_vw_ipc/test_vw_smtp).
# vw_cache.c + vw_client_core.c are compiled in too since vw_sync.c needs
# real (non-mocked) vw_cache_t/vw_sync_folder_t and the vw_file_entry_t
# type — no network code from vw_client_core.c is ever exercised here since
# every scenario in test_vw_sync.c runs with sess = NULL.
#
# VW_SYNC_TEST_HOOKS gives external linkage to functions that are `static`
# in every other target compiling vw_sync.c (vapourwault-daemon,
# test_shared_sync, test_shared_sync_mkdir) — see vw_sync_internal.h. This
# is the SAME macro test_shared_sync_hardening already defines for a
# different purpose (TASK-111's BFS race-injection hook); both purposes
# coexist under one flag without conflict since neither test binary links
# against the other's compiled vw_sync.o.
add_executable(test_vw_sync
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_sync.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_sync.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_cache.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
)
target_compile_definitions(test_vw_sync PRIVATE VW_SYNC_TEST_HOOKS)
target_include_directories(test_vw_sync PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_vw_sync PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_sync PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_vw_sync PRIVATE ws2_32)
endif()
add_test(NAME unit_vw_sync COMMAND test_vw_sync)

# ── vw_file_handlers (TASK-115) ───────────────────────────────────────────
#
# vw_file_handlers.c is normally only compiled as part of vw_server_lib
# (src/server/CMakeLists.txt) alongside 18 other server sources it depends
# on transitively (vw_cluster.c, vw_invite.c, vw_vault.c, etc. — anything
# vw_server_lib bundles). Linking test_vw_auth/test_vw_store/test_vw_share/
# test_vw_vault against the pre-built vw_server_lib works for them because
# they only need PUBLIC functions from it. This target can't do that: it
# needs VW_FILE_HANDLERS_TEST_HOOKS applied specifically to
# vw_file_handlers.c's compilation (to expose effective_permission()/
# permission_on_dir_or_root() — see vw_file_handlers_internal.h), and
# vw_server_lib is built exactly once, without that define. Linking both
# vw_server_lib AND a separately-compiled vw_file_handlers.c together
# would duplicate-define vw_path_validate/vw_server_dispatch_file_op (both
# already plain public functions regardless of the test-hooks define).
#
# So this target compiles vw_server_lib's ENTIRE source list directly
# instead of linking the library — mirrors src/server/CMakeLists.txt's
# add_library(vw_server_lib ...) source list exactly. target_compile_
# definitions applies VW_FILE_HANDLERS_TEST_HOOKS to the whole target,
# which is harmless: no other file here references that macro.
#
# CQR.08 (TASK-115 review): this list is a manual mirror, not a shared
# CMake variable, so it WILL silently go stale if src/server/CMakeLists.txt's
# vw_server_lib source list changes without a matching update here (a
# missing/extra file here won't fail the build, it'll just mean this test
# target no longer reflects the real library). That file has a matching
# comment pointing back here.
add_executable(test_vw_file_handlers
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_file_handlers.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_server_core.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_file_handlers.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_store_files.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_storage.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_oplog.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_auth_provider.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_smtp.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_admin.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_acme.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_ddns.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_gc.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_invite.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_recovery.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_cluster.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_conn_registry.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_share.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_vault.c
    ${CMAKE_SOURCE_DIR}/src/server/vw_notify.c
)
target_compile_definitions(test_vw_file_handlers PRIVATE VW_FILE_HANDLERS_TEST_HOOKS)
target_include_directories(test_vw_file_handlers PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_vw_file_handlers PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_file_handlers PRIVATE pthread)
endif()
if(WIN32)
    target_link_libraries(test_vw_file_handlers PRIVATE ws2_32)
endif()
add_test(NAME unit_vw_file_handlers COMMAND test_vw_file_handlers)

# ── vw_gateway_remember (TASK-165) ────────────────────────────────────────
#
# vw_gateway_remember.c lives in src/gateway and is not part of vw_core.
# Compiled directly into the test binary (same pattern as test_vw_ipc/
# test_vw_smtp). Its Windows ACL code links advapi32 via its own
# #pragma comment (mirrors src/client/vw_ipc.c's precedent), so no
# target_link_libraries entry for it is needed here.
add_executable(test_vw_gateway_remember
    ${CMAKE_CURRENT_SOURCE_DIR}/test_vw_gateway_remember.c
    ${CMAKE_SOURCE_DIR}/src/gateway/vw_gateway_remember.c
)
target_include_directories(test_vw_gateway_remember PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/src/gateway
    ${CMAKE_SOURCE_DIR}/tests/unit
)
target_link_libraries(test_vw_gateway_remember PRIVATE vw_core)
if(UNIX)
    target_link_libraries(test_vw_gateway_remember PRIVATE pthread)
endif()
add_test(NAME unit_vw_gateway_remember COMMAND test_vw_gateway_remember)
