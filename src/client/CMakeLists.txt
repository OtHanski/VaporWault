set(VW_CLIENT_SOURCES
    vw_daemon.c
    vw_ipc.c
    vw_client_core.c
    vw_sync.c
    vw_cache.c
)

if(UNIX)
    list(APPEND VW_CLIENT_SOURCES vw_watch_linux.c)
elseif(WIN32)
    list(APPEND VW_CLIENT_SOURCES vw_watch_windows.c)
endif()

# Background daemon (vapourwault-daemon)
add_executable(vapourwault-daemon
    main.c
    ${VW_CLIENT_SOURCES}
)

target_include_directories(vapourwault-daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vapourwault-daemon PRIVATE vw_core)

if(UNIX)
    target_link_libraries(vapourwault-daemon PRIVATE pthread)
endif()

if(WIN32)
    target_link_libraries(vapourwault-daemon PRIVATE ws2_32)
endif()

# CLI tool (connects to running daemon via IPC)
add_executable(vapourwault-cli
    main_cli.c
    vw_ipc.c
    vw_client_cli.c
)

target_include_directories(vapourwault-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vapourwault-cli PRIVATE vw_core)

if(WIN32)
    target_link_libraries(vapourwault-cli PRIVATE ws2_32)
endif()
