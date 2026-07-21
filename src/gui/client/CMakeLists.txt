add_executable(vapourwault-gui
    main.cpp
    ClientApp.cpp
    vw_gui_ipc.cpp
    views/vw_view_login.cpp
    views/vw_view_browser.cpp
    views/vw_view_queue.cpp
    views/vw_view_settings.cpp
    ${CMAKE_SOURCE_DIR}/src/client/vw_ipc.c
)

target_include_directories(vapourwault-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/src/core
)

target_link_libraries(vapourwault-gui PRIVATE
    vw_core
    imgui
)

if(WIN32)
    target_link_libraries(vapourwault-gui PRIVATE ws2_32)
else()
    target_link_libraries(vapourwault-gui PRIVATE pthread)
endif()
