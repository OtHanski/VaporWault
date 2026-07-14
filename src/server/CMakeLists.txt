# vw_server_lib — static library containing all server modules except startup.
# Linked by vapourwaultd and by unit tests that need server-layer APIs.
add_library(vw_server_lib STATIC
    vw_server_core.c
    vw_file_handlers.c
    vw_store.c
    vw_store_files.c
    vw_storage.c
    vw_oplog.c
    vw_auth.c
    vw_auth_provider.c
    vw_smtp.c
    vw_admin.c
    vw_acme.c
    vw_ddns.c
    vw_gc.c
    vw_invite.c
    vw_recovery.c
    vw_cluster.c
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
target_link_libraries(vapourwaultd PRIVATE vw_server_lib)

# Admin CLI — always built when VW_BUILD_SERVER=ON
add_executable(vapourwault-server-cli
    main_server_cli.c
    vw_server_cli.c
)

target_include_directories(vapourwault-server-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vapourwault-server-cli PRIVATE vw_core)

if(WIN32)
    target_link_libraries(vapourwault-server-cli PRIVATE ws2_32)
endif()
