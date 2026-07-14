add_library(argon2 STATIC
    src/argon2.c
    src/core.c
    src/encoding.c
    src/ref.c
    src/thread.c
    src/blake2/blake2b.c
)

target_include_directories(argon2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(UNIX)
    target_link_libraries(argon2 PRIVATE pthread)
endif()
