add_executable(vwdump
    main.c
)

target_include_directories(vwdump PRIVATE
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/core
)

target_link_libraries(vwdump PRIVATE vw_core)

if(UNIX)
    target_link_libraries(vwdump PRIVATE pthread)
endif()
