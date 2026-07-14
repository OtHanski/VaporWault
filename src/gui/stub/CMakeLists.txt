add_executable(vw_gui_stub main.cpp)
target_link_libraries(vw_gui_stub PRIVATE imgui)
# Not registered as a ctest test — headless CI cannot render a window.
# Run manually to verify the imgui + SDL2 + OpenGL wiring is correct.
