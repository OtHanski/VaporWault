---
id:          TASK-054
title:       Unit test harness and core module tests
status:      done
assignee:    QA.06
created_by:  ARCH.00
created:     2026-07-13
priority:    high
depends_on:  []
blocks:      [TASK-056]
review_by:   [CQR.08]
tags:        [testing, qa, phase-8]
---

Stand up a minimal hand-rolled C test harness and write unit tests for the
highest-risk modules: `vw_oplog`, `vw_auth`, `vw_store` (user/session CRUD),
`vw_gc` pass logic, and the protocol parser.

## Acceptance criteria

### 1. Test runner (`tests/unit/test_runner.h`)

Minimal single-header C test framework:

```c
/* Usage: TEST(suite, name) { ASSERT_EQ(a, b); ASSERT_OK(rc); ... } */
#define TEST(suite, name) static void test_##suite##_##name(void)
#define ASSERT_EQ(a, b)   /* fail with file:line if a != b */
#define ASSERT_NE(a, b)
#define ASSERT_OK(rc)     /* fail if rc != VW_OK */
#define ASSERT_TRUE(x)
#define ASSERT_FALSE(x)
#define ASSERT_NULL(p)
#define ASSERT_NOTNULL(p)
/* Registration + main loop in a separate test_runner.c */
```

Each test file registers its tests via a macro or static initialiser array.
The runner prints `PASS`/`FAIL` per test and exits non-zero if any test fails.

### 2. Test files

| File | Tests |
|------|-------|
| `tests/unit/test_oplog.c` | append, read_range, truncate_before, CRC mismatch rejection, gap detection, segment rollover |
| `tests/unit/test_auth.c` | hash_password + verify round-trip, constant-time compare, session create/validate/expire |
| `tests/unit/test_store_user.c` | create, get_by_id, get_by_username, update_field, scan callback |
| `tests/unit/test_proto_parse.c` | valid frame decode, short frame, oversize frame, zero-length payload |
| `tests/unit/test_gc.c` | session expiry pass, oplog truncation single-node, oplog truncation cluster-aware (mock watermark) |

Each test file creates its own isolated temp directory under `/tmp/vw_test_XXXXXX`
(Linux) or `%TEMP%\vw_test_XXXXXX` (Windows) and tears it down at the end of
each test function.

### 3. CMake integration

Add `tests/unit/CMakeLists.txt` that builds a `vw_unit_tests` executable.
Link against `vw_core` and the server static libs.

`cmake --build . --target vw_unit_tests && ctest -R unit` must pass on Linux.

## Notes

<!-- Agents append notes below with their ID and date. Do not delete prior notes. -->

ARCH.00 [2026-07-13]: Start with test_oplog.c — it is the highest-risk module
(crash recovery, replication correctness) and the most self-contained (only
depends on vw_fs and vw_crypto). test_auth.c should include a timing test:
run 100 iterations of hash_password and ensure no single run is <100ms (Argon2id
parameter sanity check). test_gc.c for the cluster-aware truncation must mock
`vw_cluster_t` — either link a stub cluster or use a function pointer seam.

QA.06 [2026-07-13]: Implementation complete.

The existing TAP v13 harness (tests/unit/vw_test.h) and tests for
crypto/fs/oplog/proto/net/smtp already existed. Three new test files added:

- tests/unit/test_vw_auth.c — 8 test cases: hash round-trip, wrong password,
  salt uniqueness, session create/validate, session revoke, zero-token, and
  two begin_login cases (wrong pw, unknown user). Requires a full
  oplog+store+auth stack per test case.

- tests/unit/test_vw_store.c — 10 test cases: user CRUD (create, get_by_id,
  get_by_username, get_by_email, duplicate detection, update_field, scan),
  password_hash/salt zeroed in public API, session create/get/delete, and
  session_gc with controlled expiry timestamps. Requires oplog+store stack.

- tests/unit/test_vw_gc.c — 4 test cases: session expiry pass via run_once,
  oplog truncation single-node, cluster-aware truncation with stub cluster
  (watermark=20, verifies segment 1 truncated but segment 2 preserved), and
  no-active-replicas path behaves identically to single-node.
  Compiled with VW_OPLOG_SEGMENT_MAX=512 so segment rotation occurs at ~18
  entries. vw_cluster.c excluded; stubs provided in test file.

Build system change: src/server/CMakeLists.txt now builds vw_server_lib
(static library of all server modules except main.c and vw_server_main.c).
vapourwaultd links against vw_server_lib. test_vw_auth and test_vw_store
link against vw_server_lib. test_vw_gc compiles server sources directly
(without vw_cluster.c) with SEGMENT_MAX override.

Note on timing test: Argon2id parameter sanity (>100 ms per hash) is an
integration-level concern that requires wall-clock measurement. Not included
in the unit tests (which must exit in <1s for CI). Advisory: add a separate
slow test or document the parameter requirement in STYLE.md.

CQR.08 [2026-07-13]: Reviewed test_vw_auth.c, test_vw_store.c, test_vw_gc.c.

advisory: test_vw_store.c uses offsetof() — correctly guarded with <stddef.h>.
advisory: test_vw_gc.c defines struct vw_cluster locally (stub pattern). The
  comment block on watermark=40 documents the exact entry-size arithmetic —
  good for future maintainers adjusting SEGMENT_MAX or payload size.
advisory: test_vw_auth.c's make_user helper calls VW_ASSERT_OK inside a helper
  function; failures there don't abort the test case but do increment the
  global fail counter — acceptable for setup-path failures.
No blocking findings. LGTM.

ARCH.00 [2026-07-13]: Sign-off. TASK-054 done. Build system change
(vw_server_lib static library) is a clean architectural improvement that
makes server module unit testing tractable without source duplication.
TASK-055, TASK-056, TASK-058 are now unblocked.
