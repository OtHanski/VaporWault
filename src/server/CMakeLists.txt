# vw_server_lib — static library containing all server modules except startup.
# Linked by vapourwaultd and by unit tests that need server-layer APIs.
#
# CQR.08 (TASK-115 review): tests/unit/CMakeLists.txt's test_vw_file_handlers
# target duplicates this exact source list (it needs VW_FILE_HANDLERS_TEST_HOOKS
# applied to vw_file_handlers.c specifically, which this shared library can't
# give it without breaking every other consumer — see that target's comment).
# If you add/remove a source here, update that list too, or it will silently
# stop reflecting what actually ships.
add_library(vw_server_lib STATIC
    vw_server_core.c
    vw_file_handlers.c
    vw_store.c
    vw_store_files.c
    vw_storage.c
    vw_ecc.c
    vw_oplog.c
    vw_auth.c
    vw_auth_provider.c
    vw_smtp.c
    vw_admin.c
    vw_acme.c
    vw_ddns.c
    vw_gc.c
    vw_scrub.c
    vw_repair.c
    vw_invite.c
    vw_recovery.c
    vw_cluster.c
    vw_conn_registry.c
    vw_share.c
    vw_vault.c
    vw_notify.c
)

target_include_directories(vw_server_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vw_server_lib PUBLIC vw_core)

if(UNIX)
    target_link_libraries(vw_server_lib PUBLIC pthread)
endif()

# Server daemon — startup wiring + the server library.
add_executable(vapourwaultd
    main.c
    vw_server_main.c
    $<$<PLATFORM_ID:Windows>:vw_winsvc.c>
)

target_include_directories(vapourwaultd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vapourwaultd PRIVATE vw_server_lib vw_version)

# Admin CLI — always built when VW_BUILD_SERVER=ON
add_executable(vapourwault-server-cli
    main_server_cli.c
    vw_server_cli.c
)

target_include_directories(vapourwault-server-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vapourwault-server-cli PRIVATE vw_core vw_version)

if(WIN32)
    target_link_libraries(vapourwault-server-cli PRIVATE ws2_32)
endif()
