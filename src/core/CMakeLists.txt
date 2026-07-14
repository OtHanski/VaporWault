add_library(vw_core STATIC
    vw_crypto.c
    vw_fs.c
    vw_net.c
    vw_proto.c
)

target_include_directories(vw_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(vw_core
    PUBLIC  MbedTLS::mbedtls
    PRIVATE argon2
)

if(WIN32)
    target_link_libraries(vw_core PRIVATE ws2_32)
endif()
