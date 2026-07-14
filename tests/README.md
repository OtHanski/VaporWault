# VaporWault Test Suite

This document describes how to build, run, and extend the VaporWault test suite.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| CMake       | ≥ 3.18  | Required for the `cmake --preset` and `--build` workflow |
| C compiler  | GCC ≥ 12, Clang ≥ 16, or MSVC 2022 | C11 required |
| mbedTLS     | 3.x     | Vendored under `third_party/` — no system install needed |
| Argon2      | any     | Vendored under `third_party/` |
| pthreads    | POSIX   | Required for integration tests (Windows: pthreads-win32 via vendor) |

All vendored dependencies are fetched and built automatically by CMake.

---

## Quick Start

```sh
# From the repository root:
cmake -B build -DVW_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

For a Debug build with warnings-as-errors:

```sh
cmake -B build -DVW_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DVW_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

---

## Test Categories

### Unit tests (`tests/unit/`)

Pure C, hand-rolled TAP v13 format, no external test framework.
Each executable can be run standalone; output is parseable by ctest and CI tools.

| Binary             | Module     | Key coverage                                           |
|--------------------|------------|--------------------------------------------------------|
| `test_vw_crypto`   | vw_crypto  | CRC32 known-vector, CSPRNG, Argon2id round-trip, HMAC-SHA256, hex encode/decode |
| `test_vw_fs`       | vw_fs      | atomic_write, pwrite, list_dir, ensure_dir, delete     |
| `test_vw_oplog`    | vw_oplog   | CJ-1 through CJ-5 crash-injection, segment rotation, overflow guard |
| `test_vw_proto`    | vw_proto   | AUTH_* encode/decode round-trips, boundary conditions, LE encoding correctness |

**Note:** `test_vw_crypto` and `test_vw_oplog` are slow due to Argon2id (64 MiB, 3 passes per invocation) and oplog segment I/O respectively. Expect 10–30 seconds per run.

Run a single unit test directly:

```sh
./build/bin/test_vw_proto
./build/bin/test_vw_oplog
```

### Integration tests (`tests/integration/`)

Full client-server round-trips over localhost TLS.

| Binary                   | Coverage                                              |
|--------------------------|-------------------------------------------------------|
| `test_auth_handshake`    | TC-1 login, TC-2 wrong password, TC-3 SESSION_RESUME  |

The integration test embeds a self-signed EC P-256 certificate and writes it to a temp directory at runtime. It uses `VW_CERT_VERIFY_NONE` (the cert has no SAN for localhost). Two Argon2id hashes are computed during setup and TC-1; allow up to 120 seconds.

---

## Running Specific Tests

```sh
# Run only unit tests:
ctest --test-dir build -R "^unit_" --output-on-failure

# Run only integration tests:
ctest --test-dir build -R "^integration_" --output-on-failure

# Run a single named test:
ctest --test-dir build -R unit_vw_proto --output-on-failure

# Run with verbose TAP output:
./build/bin/test_vw_proto
```

---

## Adding a New Unit Test

1. Create `tests/unit/test_<module>.c` following the pattern in `test_vw_crypto.c`.
2. Wrap the body in `VW_TEST_SUITE("name") { ... } VW_TEST_SUITE_END()`.
3. For modules in `src/core/` (linked by `vw_core`): add one line to `tests/unit/CMakeLists.txt`:
   ```cmake
   vw_add_unit_test(module_name ${CMAKE_CURRENT_SOURCE_DIR}/test_<module>.c)
   ```
4. For modules outside `vw_core` (e.g. `src/server/`): use the custom `add_executable` pattern shown for `test_vw_oplog` in `CMakeLists.txt`, compiling the module source directly into the test binary.

### Framework macros

```c
VW_TEST_SUITE("suite name") { ... }
VW_TEST_CASE("description")  { ... }  /* optional grouping comment */
VW_ASSERT(expr)
VW_ASSERT_EQ(a, b)
VW_ASSERT_NE(a, b)
VW_ASSERT_STR_EQ(a, b)
VW_ASSERT_MEM_EQ(a, b, n)
VW_ASSERT_ERR(expr, expected_vw_err_t)
VW_ASSERT_OK(expr)
VW_TEST_SUITE_END()
```

Output is TAP v13 (`ok N - description` / `not ok N - description`). The process exits non-zero if any assertion fails.

---

## Known Limitations

- **Windows MSVC**: the unit tests build and pass on MSVC 2022. The integration tests require pthreads; the vendor provides pthreads-win32. Report any MSVC-specific failures as bugs.
- **Fuzz tests**: fuzz targets (`tests/fuzz/`) are not yet implemented. Planned for the Phase 8 hardening milestone (TASK-012).
- **SMTP tests**: `test_vw_smtp.c` requires a local SMTP server fixture configured via the `VW_SMTP_TEST_HOST` environment variable. Without it, only the helper-function tests run. Not yet implemented.
- **Integration scaffold**: the full client-server process-spawn scaffold (`tests/integration/framework/`) is planned for Phase 2 (file upload/download). Currently only the in-process auth handshake test exists.

---

## CI

Tests are run via ctest. BLD.05 is responsible for the GitHub Actions workflow. The recommended invocation for CI is:

```sh
cmake -B build -DVW_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DVW_WERROR=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure --timeout 180
```
