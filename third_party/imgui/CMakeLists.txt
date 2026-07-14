# ── SDL2 (minimum 2.26.0) ─────────────────────────────────────────────────────
set(_VW_SDL2_VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/../SDL2")

if(WIN32 AND IS_DIRECTORY "${_VW_SDL2_VENDOR}")
    # Vendored SDL2 VC prebuilt (third_party/SDL2/ — MSVC x64 VC build).
    find_library(_sdl2_lib SDL2
        PATHS "${_VW_SDL2_VENDOR}/lib/x64" NO_DEFAULT_PATH REQUIRED)
    add_library(SDL2::SDL2 IMPORTED SHARED GLOBAL)
    set_target_properties(SDL2::SDL2 PROPERTIES
        IMPORTED_IMPLIB               "${_sdl2_lib}"
        IMPORTED_LOCATION             "${_VW_SDL2_VENDOR}/lib/x64/SDL2.dll"
        INTERFACE_INCLUDE_DIRECTORIES "${_VW_SDL2_VENDOR}/include"
    )
else()
    find_package(SDL2 REQUIRED)
    if(NOT TARGET SDL2::SDL2)
        # Older SDL2 CMake config: normalise to a modern target
        add_library(SDL2::SDL2 INTERFACE IMPORTED GLOBAL)
        set_target_properties(SDL2::SDL2 PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SDL2_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES      "${SDL2_LIBRARIES}"
        )
    endif()
endif()

# ── OpenGL ────────────────────────────────────────────────────────────────────
find_package(OpenGL REQUIRED)

# ── imgui static library ──────────────────────────────────────────────────────
add_library(imgui STATIC
    imgui.cpp
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    backends/imgui_impl_sdl2.cpp
    backends/imgui_impl_opengl3.cpp
)

# imgui_demo.cpp is large; include only in Debug builds
target_sources(imgui PRIVATE
    $<$<CONFIG:Debug>:${CMAKE_CURRENT_SOURCE_DIR}/imgui_demo.cpp>
)

target_include_directories(imgui PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/backends
)

target_link_libraries(imgui PUBLIC SDL2::SDL2 OpenGL::GL)
