cmake_minimum_required(VERSION 3.18)

# This file is only included when CMAKE_BUILD_TYPE == "Fuzz".
# The top-level CMakeLists.txt guards the add_subdirectory call.
# All compilation flags (-fsanitize=fuzzer-no-link,address,undefined) and the
# link flags (-fsanitize=address,undefined) are already set globally.
# Each fuzz executable ALSO needs -fsanitize=fuzzer at link time so the
# libFuzzer driver (LLVMFuzzerRunDriver) is linked in.

if(NOT CMAKE_BUILD_TYPE STREQUAL "Fuzz")
    message(FATAL_ERROR "tests/fuzz/ must only be included in Fuzz builds.")
endif()

# ── Helper macro ──────────────────────────────────────────────────────────────
#
# fuzz_target(name [SRCS extra.c ...] [LIBS extra_lib ...])
#
# Builds a libFuzzer executable named `name` from tests/fuzz/<name>.c plus
# any SRCS and links against vw_server_lib, vw_core, and pthreads.
# Appends -fsanitize=fuzzer to the link line so the fuzzer driver is included.

macro(fuzz_target name)
    cmake_parse_arguments(FT "" "" "SRCS;LIBS" ${ARGN})

    add_executable(${name}
        ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c
        ${FT_SRCS}
    )

    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/server
        ${CMAKE_SOURCE_DIR}/src/core
    )

    target_link_libraries(${name} PRIVATE
        vw_server_lib
        vw_core
        ${FT_LIBS}
    )

    if(UNIX)
        target_link_libraries(${name} PRIVATE pthread)
    endif()

    # Pull in the libFuzzer driver (in addition to ASan/UBSan from the global flags).
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endmacro()

# ── Fuzz targets ──────────────────────────────────────────────────────────────

# 1. Wire protocol frame decoder + payload bounds
fuzz_target(fuzz_proto_recv)

# 2. Path validator (vw_path_validate)
fuzz_target(fuzz_path_validate)

# 3. Oplog segment file parser (vw_oplog_open + vw_oplog_replay_from)
fuzz_target(fuzz_oplog_replay)

# 4. Cluster NODE_HELLO payload parser (inline replication of handle_cluster_conn logic)
#    fuzz_cluster_hello.c is self-contained — no VW API calls, no library linkage needed
#    beyond headers.  Still link vw_server_lib for the sanitizer runtime symbols.
fuzz_target(fuzz_cluster_hello)

# 5. Admin socket message parser (inline replication of handle_admin_connection logic)
fuzz_target(fuzz_admin_dispatch)
