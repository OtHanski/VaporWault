set(VW_CLIENT_SOURCES
    vw_daemon.c
    vw_ipc.c
    vw_client_core.c
    vw_vault.c
    vw_sync.c
    vw_cache.c
    vw_update_net.c
    vw_update_manifest.c
    vw_update.c
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
target_link_libraries(vapourwault-daemon PRIVATE vw_core vw_version)

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
target_link_libraries(vapourwault-cli PRIVATE vw_core vw_version)

if(WIN32)
    target_link_libraries(vapourwault-cli PRIVATE ws2_32)
endif()

# Update helper (TASK-00298) — deliberately no vw_core/vw_version linkage,
# just raw file rename/unlink + wait-for-pid + spawn-process, so it can
# safely swap the daemon binary (and, in principle, anything else this
# update might replace) without depending on any file it might be
# replacing. Ships inside the portable tar.gz/zip archives (TASK-00301),
# never installed via CPack's .deb/.rpm/.msi rules.
add_executable(vapourwault-updater
    vw_updater_main.c
)
