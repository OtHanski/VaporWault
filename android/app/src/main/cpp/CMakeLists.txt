cmake_minimum_required(VERSION 3.22.1)
project(vaporwault_jni C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# VaporWault's own VW_WERROR strict-warnings flag is deliberately NOT applied
# here (see top-level CMakeLists.txt) — the NDK toolchain build is not part of
# the CI matrix that flag targets (TASK-233 covers wiring an Android CI job
# separately), and applying it retroactively to code that already builds
# clean under desktop CI adds no value here.

# ── Reuse the real vw_core target (+ its mbedTLS/Argon2 deps) unmodified ────
# TASK-224/225: same source tree as every other client (CLI/daemon/GUI/
# gateway) — no Android-specific fork, no vendored copy. third_party/ must be
# added before src/core/, same order the repo-root CMakeLists.txt uses,
# since src/core's target_link_libraries() references the MbedTLS::mbedtls/
# argon2 targets third_party/CMakeLists.txt defines.
set(VW_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")
add_subdirectory("${VW_REPO_ROOT}/third_party" vw_third_party_build)
add_subdirectory("${VW_REPO_ROOT}/src/core" vw_core_build)

# ── JNI bridge: compiles the two client-core source files directly, matching
# this repo's existing "no intermediate library, compile the source file into
# each consumer" convention (see src/client/CMakeLists.txt, src/gateway/
# CMakeLists.txt, and every tests/unit/CMakeLists.txt target) ───────────────
add_library(vaporwault_jni SHARED
    vw_jni_bridge.c
    "${VW_REPO_ROOT}/src/client/vw_client_core.c"
    "${VW_REPO_ROOT}/src/client/vw_vault.c"
)

target_include_directories(vaporwault_jni PRIVATE
    "${VW_REPO_ROOT}/src/client"
    "${VW_REPO_ROOT}/src/core"
)

target_link_libraries(vaporwault_jni PRIVATE
    vw_core
    log
)
