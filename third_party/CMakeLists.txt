# Third-party vendored libraries.
# These subdirectories are populated by the developer; see README in each.

# mbedTLS — TLS 1.3, crypto primitives
# Vendor: git clone https://github.com/Mbed-TLS/mbedtls third_party/mbedtls
# Point mbedTLS at our trimmed config header before including its CMake tree.
set(MBEDTLS_CONFIG_FILE "${CMAKE_SOURCE_DIR}/third_party/mbedtls_config.h"
    CACHE STRING "Path to the project-specific mbedTLS config header" FORCE)
if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    add_subdirectory(mbedtls)
else()
    message(FATAL_ERROR
        "mbedTLS not found at third_party/mbedtls/.\n"
        "Run: git clone https://github.com/Mbed-TLS/mbedtls third_party/mbedtls")
endif()

# Argon2 reference implementation (~600 lines, public domain)
# Vendor: copy src/argon2.{h,c} and src/blake2/ from https://github.com/P-H-C/phc-winner-argon2
if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/argon2)
    add_subdirectory(argon2)
else()
    message(FATAL_ERROR
        "Argon2 not found at third_party/argon2/.\n"
        "Copy src/argon2.h, src/argon2.c, src/blake2/ from https://github.com/P-H-C/phc-winner-argon2")
endif()

# Dear ImGui + SDL2 backend (C++ GUI library, vendored) — only needed for GUI targets
if(VW_BUILD_GUI)
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/imgui)
        add_subdirectory(imgui)
    else()
        message(FATAL_ERROR
            "Dear ImGui not found at third_party/imgui/.\n"
            "Run: git clone --branch docking https://github.com/ocornut/imgui third_party/imgui\n"
            "     cd third_party/imgui && git checkout v1.91.6")
    endif()
endif()
