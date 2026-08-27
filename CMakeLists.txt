cmake_minimum_required(VERSION 3.18)

# TASK-203: a checked-in VERSION file is the single source of truth for the
# project version — unlike `git describe`, it works identically for local
# builds, CI, and a source tarball with no tag/commit history at all.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VW_VERSION_FILE_CONTENTS LIMIT_COUNT 1)
string(STRIP "${VW_VERSION_FILE_CONTENTS}" VW_VERSION_FILE_CONTENTS)

project(VaporWault VERSION ${VW_VERSION_FILE_CONTENTS} LANGUAGES C CXX)

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
        # TASK-071: /wd4200 suppresses C4200 ("nonstandard extension used:
        # zero-sized array in struct/union") project-wide under MSVC. This
        # isn't about our own code (which doesn't use zero-length arrays —
        # this codebase's convention is fixed-size records with
        # _Static_assert) — it fires on vendored mbedTLS's
        # psa/crypto_struct.h whenever one of OUR translation units
        # (vw_crypto.c, vw_net.c, vw_smtp.c) transitively #includes it.
        # MBEDTLS_FATAL_WARNINGS is already forced off (see
        # third_party/CMakeLists.txt) so this isn't mbedTLS's own -Werror/
        # /WX bleeding in — /W4 /WX is applied to OUR targets, and the
        # vendored header's content is parsed as part of compiling OUR
        # file, under OUR flags. FetchContent-ing mbedTLS before this
        # add_compile_options() call keeps /W4 /WX off mbedTLS's own build
        # targets already; it can't do anything about a warning raised
        # while compiling a file that is itself one of our targets.
        add_compile_options(/W4 /WX /wd4200)
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
option(VW_BUILD_WEB_GATEWAY "Build vapourwault-web-gateway (TASK-127/128)" OFF)

# Release version for installer packages (TASK-145/146). Defaults to the
# checked-in VERSION file's contents (TASK-203) so a local/dev build reports
# a real, meaningful version instead of a placeholder; CI passes the real
# tag with the leading "v" stripped (e.g. -DVW_VERSION=0.2.0 for tag v0.2.0),
# since .deb/.rpm/MSI version fields don't accept an arbitrary leading letter.
set(VW_VERSION "${VW_VERSION_FILE_CONTENTS}" CACHE STRING "VaporWault release version (no leading 'v')")

# ── Embedded version string for `--version` output (TASK-203) ───────────────
# Best-effort short git hash appended when this is a git checkout and `git`
# is on PATH; must not fail configure otherwise (e.g. a source tarball with
# no .git directory, or a machine with no git installed).
set(VW_GIT_HASH "")
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE VW_GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE VW_GIT_HASH_RC
    )
    if(NOT VW_GIT_HASH_RC EQUAL 0)
        set(VW_GIT_HASH "")
    endif()
endif()

if(VW_GIT_HASH)
    set(VW_VERSION_STRING "${VW_VERSION}+${VW_GIT_HASH}")
else()
    set(VW_VERSION_STRING "${VW_VERSION}")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vw_version.h.in"
    "${CMAKE_BINARY_DIR}/generated/vw_version.h"
    @ONLY
)

# INTERFACE-only: every binary links this for the generated header's include
# path, not for any actual object code.
add_library(vw_version INTERFACE)
target_include_directories(vw_version INTERFACE "${CMAKE_BINARY_DIR}/generated")

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

if(VW_BUILD_WEB_GATEWAY)
    add_subdirectory(src/gateway)
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

# COMPONENT tags below (server/client) drive TASK-146's CPack packaging —
# see cmake/Packaging.cmake. The web gateway has no installer component yet
# (TASK-128 built it as a plain executable only); file a follow-up if/when
# it needs one.

if(VW_BUILD_SERVER)
    install(TARGETS vapourwaultd vapourwault-server-cli
            RUNTIME DESTINATION bin
            COMPONENT server)
endif()

if(VW_BUILD_SERVER AND VW_BUILD_GUI)
    install(TARGETS vapourwault-server-gui
            RUNTIME DESTINATION bin
            OPTIONAL
            COMPONENT server)
endif()

if(VW_BUILD_SERVER AND VW_BUILD_TOOLS)
    install(TARGETS vwdump
            RUNTIME DESTINATION bin
            COMPONENT server)
endif()

if(VW_BUILD_CLIENT)
    install(TARGETS vapourwault-daemon vapourwault-cli
            RUNTIME DESTINATION bin
            COMPONENT client)
endif()

if(VW_BUILD_CLIENT AND VW_BUILD_GUI)
    install(TARGETS vapourwault-gui
            RUNTIME DESTINATION bin
            OPTIONAL
            COMPONENT client)
endif()

if(VW_BUILD_WEB_GATEWAY)
    install(TARGETS vapourwault-web-gateway
            RUNTIME DESTINATION bin)
endif()

if(UNIX AND NOT APPLE)
    install(FILES packaging/linux/vapourwaultd.service
            DESTINATION lib/systemd/system
            OPTIONAL
            COMPONENT server)
    if(VW_BUILD_CLIENT)
        # NOT vapourwault-daemon.service (that one is for
        # client_install.sh's manual/tarball path, ExecStart=%h/.local/bin/...
        # which doesn't exist for a package install) -- see
        # vapourwault-daemon-pkg.service's own header comment. Installed
        # under the package's real name so `systemctl --user` sees
        # "vapourwault-daemon.service" either way.
        install(FILES packaging/linux/vapourwault-daemon-pkg.service
                DESTINATION lib/systemd/user
                RENAME vapourwault-daemon.service
                OPTIONAL
                COMPONENT client)
    endif()
    if(VW_BUILD_WEB_GATEWAY)
        install(FILES packaging/linux/vapourwault-web-gateway.service
                DESTINATION lib/systemd/system
                OPTIONAL)
    endif()
    # Config templates for the DEB/RPM postinst scripts (TASK-149/150) to
    # install as /etc/vapourwault/server.conf / daemon.conf, only if absent.
    if(VW_BUILD_SERVER)
        install(FILES packaging/linux/server.conf.example
                DESTINATION share/vapourwault
                COMPONENT server)
    endif()
    if(VW_BUILD_CLIENT)
        install(FILES packaging/linux/client.conf.example
                DESTINATION share/vapourwault
                COMPONENT client)
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

# ── Installer packaging (CPack: DEB/RPM/WIX) ─────────────────────────────────
# TASK-145/146. Split into its own file for readability; see
# cmake/Packaging.cmake and docs/RELEASE.md.
include(cmake/Packaging.cmake)
