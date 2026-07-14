add_executable(vapourwault-server-gui
    main.cpp
    ServerApp.cpp
    vw_server_conn.cpp
    views/vw_view_login.cpp
    views/vw_view_dashboard.cpp
    views/vw_view_cluster.cpp
    views/vw_view_users.cpp
    views/vw_view_audit.cpp
)

target_include_directories(vapourwault-server-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/server
)

target_link_libraries(vapourwault-server-gui PRIVATE
    vw_core
    imgui
)

if(WIN32)
    target_link_libraries(vapourwault-server-gui PRIVATE ws2_32)
else()
    target_link_libraries(vapourwault-server-gui PRIVATE pthread)
endif()
