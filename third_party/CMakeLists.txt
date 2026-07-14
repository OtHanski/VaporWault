# Third-party vendored libraries.
#
# mbedTLS and Argon2 are downloaded at configure time via FetchContent.
# Dear ImGui is still a manual vendor (only needed for GUI targets, which are
# disabled in CI).  See VENDOR_SETUP.md for manual-vendor instructions.

include(FetchContent)

# ── mbedTLS — TLS 1.3, crypto primitives ─────────────────────────────────────
# Point mbedTLS at our trimmed config header before its CMake tree is loaded.
set(MBEDTLS_CONFIG_FILE "${CMAKE_SOURCE_DIR}/third_party/mbedtls_config.h"
    CACHE STRING "Path to the project-specific mbedTLS config header" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(mbedtls)

# ── Argon2 reference implementation (~600 lines, public domain) ───────────────
# We define our own STATIC target rather than using the upstream CMakeLists.txt
# (which produces different target names and doesn't match our include layout).
FetchContent_Declare(argon2_fetch
    GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
    GIT_TAG        20190702
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(argon2_fetch)
if(NOT argon2_fetch_POPULATED)
    FetchContent_Populate(argon2_fetch)
endif()

add_library(argon2 STATIC
    ${argon2_fetch_SOURCE_DIR}/src/argon2.c
    ${argon2_fetch_SOURCE_DIR}/src/core.c
    ${argon2_fetch_SOURCE_DIR}/src/encoding.c
    ${argon2_fetch_SOURCE_DIR}/src/ref.c
    ${argon2_fetch_SOURCE_DIR}/src/thread.c
    ${argon2_fetch_SOURCE_DIR}/src/blake2/blake2b.c
)
target_include_directories(argon2 PUBLIC ${argon2_fetch_SOURCE_DIR}/include)
if(UNIX)
    target_link_libraries(argon2 PRIVATE pthread)
endif()

# ── Dear ImGui + SDL2 backend (C++ GUI library) ───────────────────────────────
# Only needed when VW_BUILD_GUI=ON (disabled in CI).
# Vendor manually: git clone --branch docking https://github.com/ocornut/imgui third_party/imgui
# See VENDOR_SETUP.md for the exact checkout tag.
if(VW_BUILD_GUI)
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/imgui)
        add_subdirectory(imgui)
    else()
        message(FATAL_ERROR
            "Dear ImGui not found at third_party/imgui/.\n"
            "Run: git clone --branch docking https://github.com/ocornut/imgui third_party/imgui\n"
            "     cd third_party/imgui && git checkout v1.91.6\n"
            "See VENDOR_SETUP.md for details.")
    endif()
endif()
