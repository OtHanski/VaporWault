# Third-party vendored libraries.
#
# mbedTLS and Argon2 are downloaded at configure time via FetchContent.
# Dear ImGui + SDL2 are still manually vendored (only needed when
# VW_BUILD_GUI=ON). See VENDOR_SETUP.md for manual-vendor instructions.

include(FetchContent)

# ── mbedTLS — TLS 1.3, crypto primitives ─────────────────────────────────────
# Point mbedTLS at our trimmed config header before its CMake tree is loaded.
set(MBEDTLS_CONFIG_FILE "${CMAKE_SOURCE_DIR}/third_party/mbedtls_config.h"
    CACHE STRING "Path to the project-specific mbedTLS config header" FORCE)
set(ENABLE_TESTING        OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS       OFF CACHE BOOL "" FORCE)
# mbedTLS defaults MBEDTLS_FATAL_WARNINGS=ON, which appends -Werror (GCC/Clang)
# or /WX (MSVC) to CMAKE_C_FLAGS — a cache variable that bleeds into our own
# targets. Force it off so mbedTLS never touches CMAKE_C_FLAGS for warnings.
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

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
# Vendor manually: git clone --branch docking https://github.com/ocornut/imgui third_party/imgui
# See VENDOR_SETUP.md for the exact checkout tag.
#
# Dear ImGui does not ship its own CMakeLists.txt upstream — it's designed to be
# compiled directly into the consuming project, not add_subdirectory()'d as a
# self-contained subproject. We define our own STATIC target here instead, the
# same approach already used for Argon2 above: list the exact source files we
# need (core + the SDL2/OpenGL3 backend, matching what src/gui/* actually uses)
# rather than assume the vendored tree builds itself.
if(VW_BUILD_GUI)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/imgui/imgui.cpp)
        message(FATAL_ERROR
            "Dear ImGui not found at third_party/imgui/.\n"
            "Run: git clone --branch docking https://github.com/ocornut/imgui third_party/imgui\n"
            "     cd third_party/imgui && git checkout 81c008f90\n"
            "See VENDOR_SETUP.md for details.")
    endif()

    find_package(OpenGL REQUIRED)

    if(WIN32)
        # The vendored VC devel package ships its own CMake config (targets
        # SDL2::SDL2 / SDL2::SDL2main) — see VENDOR_SETUP.md for how to place it.
        if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/SDL2/cmake/sdl2-config.cmake)
            message(FATAL_ERROR
                "SDL2 not found at third_party/SDL2/. See VENDOR_SETUP.md for the "
                "Windows vendoring steps (download the official VC devel package).")
        endif()
        find_package(SDL2 REQUIRED CONFIG
            PATHS ${CMAKE_CURRENT_SOURCE_DIR}/SDL2/cmake
            NO_DEFAULT_PATH)
        set(VW_SDL2_LIBS SDL2::SDL2main SDL2::SDL2)
    else()
        # Linux/macOS: the system package (apt install libsdl2-dev / brew install
        # sdl2) ships a pkg-config file, not a CMake config.
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
        set(VW_SDL2_LIBS PkgConfig::SDL2)
    endif()

    add_library(imgui STATIC
        imgui/imgui.cpp
        imgui/imgui_demo.cpp
        imgui/imgui_draw.cpp
        imgui/imgui_tables.cpp
        imgui/imgui_widgets.cpp
        imgui/backends/imgui_impl_sdl2.cpp
        imgui/backends/imgui_impl_opengl3.cpp
    )
    target_include_directories(imgui PUBLIC
        imgui
        imgui/backends
    )
    target_link_libraries(imgui PUBLIC ${VW_SDL2_LIBS} OpenGL::GL)
endif()
