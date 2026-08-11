# vapourwault-web-gateway — standalone vw/1 client + HTTP/JSON API for the
# browser frontend (TASK-127/128). Reuses vw_core and src/client/vw_client_core.c
# directly (same "no shared lib, reuse the source file" pattern
# src/gui/client/CMakeLists.txt already uses for vw_ipc.c) — does NOT link
# vw_sync/vw_cache/vw_daemon; the gateway is request/response per browser
# action, not a persistent local-folder sync engine.

add_executable(vapourwault-web-gateway
    main.c
    vw_http.c
    vw_json.c
    vw_gateway_session.c
    vw_gateway_api.c
    ${CMAKE_SOURCE_DIR}/src/client/vw_client_core.c
)

target_include_directories(vapourwault-web-gateway PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/src/core
)

target_link_libraries(vapourwault-web-gateway PRIVATE vw_core)

if(UNIX)
    target_link_libraries(vapourwault-web-gateway PRIVATE pthread)
endif()

if(WIN32)
    target_link_libraries(vapourwault-web-gateway PRIVATE ws2_32)
endif()
