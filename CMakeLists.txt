cmake_minimum_required(VERSION 3.18)
project(VaporWault C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Third-party vendored libraries — pulled in BEFORE -Werror so FetchContent
# targets don't inherit our strict warning flags.
add_subdirectory(third_party)

# Treat warnings as errors in CI; off by default for local builds
option(VW_WERROR "Treat compiler warnings as errors" OFF)

if(VW_WERROR)
    if(MSVC)
        add_compile_options(/W4 /WX)
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    endif()
else()
    if(MSVC)
        add_compile_options(/W3)
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
    else()
        add_compile_options(-Wall -Wextra)
    endif()
endif()

# ── Fuzz build type (Clang + libFuzzer + ASan + UBSan) ───────────────────────
# Usage: cmake -B build-fuzz -DCMAKE_BUILD_TYPE=Fuzz -DCMAKE_C_COMPILER=clang
#
# Libraries are compiled with -fsanitize=fuzzer-no-link so they receive
# coverage instrumentation without pulling in LLVMFuzzerTestOneInput.
# Individual fuzz target executables must add -fsanitize=fuzzer to their own
# target_link_options() — see tests/fuzz/CMakeLists.txt.
if(CMAKE_BUILD_TYPE STREQUAL "Fuzz")
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "Fuzz build type requires Clang. "
            "Pass -DCMAKE_C_COMPILER=clang to cmake.")
    endif()
    add_compile_options(
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer
        -g -O1
    )
    add_link_options(-fsanitize=address,undefined)
endif()

# Build options
option(VW_BUILD_SERVER "Build the server executable" ON)
option(VW_BUILD_CLIENT "Build the client daemon and CLI" ON)
option(VW_BUILD_GUI    "Build GUI targets (requires VW_BUILD_SERVER or VW_BUILD_CLIENT)" ON)
option(VW_BUILD_TOOLS  "Build admin tools (vwdump)" ON)
option(VW_BUILD_TESTS  "Build unit and integration tests" ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Shared core library (vw_net, vw_proto, vw_crypto, vw_fs)
add_subdirectory(src/core)

if(VW_BUILD_SERVER)
    add_subdirectory(src/server)
    if(VW_BUILD_GUI)
        add_subdirectory(src/gui/server)
    endif()
endif()

if(VW_BUILD_CLIENT)
    add_subdirectory(src/client)
    if(VW_BUILD_GUI)
        add_subdirectory(src/gui/client)
    endif()
endif()

if(VW_BUILD_GUI)
    add_subdirectory(src/gui/stub)
endif()

if(VW_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(VW_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Fuzz targets live in tests/fuzz/ and are only built in the Fuzz build type.
if(CMAKE_BUILD_TYPE STREQUAL "Fuzz" AND VW_BUILD_TESTS)
    add_subdirectory(tests/fuzz)
endif()

# ── Install targets ───────────────────────────────────────────────────────────
# Usage: cmake --install <build-dir> [--prefix /usr/local]
# Installs binaries to <prefix>/bin and (on Linux) the systemd unit file.

if(VW_BUILD_SERVER)
    install(TARGETS vapourwaultd vapourwault-server-cli
            RUNTIME DESTINATION bin)
endif()

if(VW_BUILD_SERVER AND VW_BUILD_GUI)
    install(TARGETS vapourwault-server-gui
            RUNTIME DESTINATION bin
            OPTIONAL)
endif()

if(VW_BUILD_CLIENT)
    install(TARGETS vapourwault-daemon vapourwault-cli
            RUNTIME DESTINATION bin)
endif()

if(UNIX AND NOT APPLE)
    install(FILES packaging/linux/vapourwaultd.service
            DESTINATION lib/systemd/system
            OPTIONAL)
    if(VW_BUILD_CLIENT)
        install(FILES packaging/linux/vapourwault-daemon.service
                DESTINATION lib/systemd/user
                OPTIONAL)
    endif()
endif()

# ── Integration test convenience target ──────────────────────────────────────
# Usage (Linux/macOS, requires pytest and openssl in PATH):
#   cmake --build build --target vw_integration_test
if(UNIX AND VW_BUILD_SERVER AND VW_BUILD_TESTS)
    set(_VW_CERT "${CMAKE_SOURCE_DIR}/tests/integration/test.crt")
    set(_VW_KEY  "${CMAKE_SOURCE_DIR}/tests/integration/test.key")
    add_custom_target(vw_integration_test
        COMMAND ${CMAKE_COMMAND} -E echo "-- Generating test TLS cert if needed..."
        COMMAND bash "${CMAKE_SOURCE_DIR}/tests/integration/gen_test_cert.sh"
                     "${CMAKE_SOURCE_DIR}/tests/integration"
        COMMAND ${CMAKE_COMMAND} -E echo "-- Running integration tests..."
        COMMAND pytest "${CMAKE_SOURCE_DIR}/tests/integration" -v
                       -m "not cluster"
                       --server-bin "$<TARGET_FILE:vapourwaultd>"
                       --admin-cli  "$<TARGET_FILE:vapourwault-server-cli>"
                       --test-cert  "${_VW_CERT}"
                       --test-key   "${_VW_KEY}"
        DEPENDS vapourwaultd vapourwault-server-cli
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Running VaporWault integration tests (not cluster)"
        USES_TERMINAL
    )
endif()
