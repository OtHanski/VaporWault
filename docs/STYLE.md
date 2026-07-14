# VaporWault C/C++ Style Guide

**Owner:** CQR.08  
**Applies to:** All `.c`, `.h`, and `.cpp` files in the repository

---

## 1. Language standards

| Component     | Standard            |
|---------------|---------------------|
| Server / core | C11 (`-std=c11`)    |
| Client core   | C11 (`-std=c11`)    |
| GUI           | C++17 (`-std=c++17`) |

Compiler flags: `-Wall -Wextra -Wpedantic`. With `VW_WERROR=ON` (CI default): `-Werror`.

---

## 2. Naming

| Entity                | Convention            | Example                     |
|-----------------------|-----------------------|-----------------------------|
| Types (structs/enums) | `snake_case_t`        | `vw_conn_t`, `vw_err_t`    |
| Functions             | `module_verb_noun`    | `vw_net_send`, `vw_fs_exists` |
| Constants / macros    | `SCREAMING_SNAKE`     | `VW_MAX_MSG_BYTES`          |
| Enum values           | `MODULE_SCREAMING`    | `VW_ERR_NET_TLS`            |
| Local variables       | `snake_case`          | `payload_len`, `out_buf`    |
| Static module-global  | `g_snake_case`        | `g_initialized`             |
| Private helper funcs  | `snake_case` (static) | `build_tmp_path`            |

Module prefix rules:
- `vw_` prefix on every public symbol.
- Module-local helpers (static functions) do not need the `vw_` prefix.

---

## 3. File layout

```
<copyright/licence header — one line>
#include "<own_module>.h"

#include <standard library headers>   /* alphabetical */

#include <third-party headers>        /* mbedTLS, argon2 */

/* ── Section heading ─── */

static helpers
module state (g_ vars)
public API implementation
```

No file should exceed ~1 000 lines. If it does, split by subsystem.

---

## 4. Header guards

```c
#ifndef MODULE_NAME_H
#define MODULE_NAME_H
/* ... */
#endif /* MODULE_NAME_H */
```

No `#pragma once`. The guard name is the file name uppercased with dots replaced by underscores.

---

## 5. Error handling

- All non-trivial functions return `vw_err_t`.
- Output values are returned through pointer parameters (`*out_foo`).
- On error, output parameters are **not** modified (or set to NULL/0 explicitly).
- Always check every return value. Never silently discard a `vw_err_t`.
- Use `goto fail` for cleanup paths with multiple resources. Label every fail target descriptively when there is more than one.

```c
/* Preferred pattern */
vw_err_t my_function(args) {
    resource_a = acquire_a();
    if (!resource_a) return VW_ERR_OOM;

    resource_b = acquire_b();
    if (!resource_b) { release_a(resource_a); return VW_ERR_IO; }

    /* ... */
    release_b(resource_b);
    release_a(resource_a);
    return VW_OK;
}
```

For more than two resources, use `goto fail`:

```c
vw_err_t my_function(args) {
    resource_a = NULL; resource_b = NULL;

    resource_a = acquire_a();
    if (!resource_a) { err = VW_ERR_OOM; goto fail; }

    resource_b = acquire_b();
    if (!resource_b) { err = VW_ERR_IO; goto fail; }

    /* ... */
    err = VW_OK;
fail:
    if (resource_b) release_b(resource_b);
    if (resource_a) release_a(resource_a);
    return err;
}
```

---

## 6. Memory

- Every allocation has a matching free on every exit path.
- Functions that return heap-allocated buffers (`*out_buf`) document the caller's responsibility to `free()` in the header comment.
- No VLAs. Fixed-size stack buffers with explicit size checks.
- Zero out sensitive data before freeing: `memset(secret, 0, len); free(secret);`

---

## 7. Platform portability

- `#ifdef _WIN32` / `#else` blocks for platform-specific code.
- Portable integer types: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int64_t` from `<stdint.h>`. Never use `long`, `unsigned long`, or `int` for values with a defined bit width.
- `size_t` for object sizes; `ptrdiff_t` for pointer differences.
- Avoid POSIX-specific APIs in shared core code; wrap them behind a `vw_` abstraction.
- String functions: `strncpy` with explicit NUL termination, or `snprintf`. Never `strcpy`, `sprintf`, or `gets`.

---

## 8. Concurrency

- Each `pthread_mutex_t` or `pthread_rwlock_t` owns a specific resource; document which in the struct definition.
- Lock acquisition order must be documented when two locks are held simultaneously (to prevent deadlocks). The convention is: table-level lock before row-level lock.
- Never hold a lock across a network operation or a slow disk operation.
- Condition variables: always check the condition in a `while` loop, never `if`.

---

## 9. Security-sensitive code

- Password hashes, session tokens, and private keys must never be passed to `printf`/`fprintf`/logging functions.
- Use `vw_crypto_constant_time_eq` for all security-sensitive comparisons. Never `memcmp` for secrets.
- Validate every length field from the network against the remaining buffer before using it.
- Reject messages that would require a negative-length field or an integer overflow.

---

## 10. Comments

Write a comment only when the **why** is not obvious from the code. The what is self-evident from names.

```c
/* Correct: explains a non-obvious constraint */
/* Always run Argon2id even when user not found — timing normalisation */

/* Wrong: restates the code */
/* Check if the length is valid */
if (len > VW_MAX_MSG_BYTES) ...
```

API documentation lives in the `.h` file above the declaration, not in the `.c` file. Use plain prose; no Doxygen tags.

---

## 11. Includes

- Include the module's own header first.
- Then standard library headers in alphabetical order.
- Then third-party headers.
- Never include a `.c` file.
- Forward-declare types (`typedef struct foo foo_t;`) in the header rather than including the full definition header when only a pointer is needed.

---

## 12. C++ (GUI component only)

- Prefer plain C APIs from the core library over C++ wrappers.
- RAII for all resources; no naked `new`/`delete`.
- `nullptr` not `NULL`.
- Include guards same as C headers.
- No exceptions; compile with `-fno-exceptions` for the GUI target.

---

## 13. Things that are always wrong

- `gets`, `scanf` with `%s`  
- `strcpy`, `sprintf`  
- `memcmp` for secret comparison  
- `printf` in production non-logging code paths (use the audit/log module)  
- Signed/unsigned integer comparison without explicit casts  
- `int` where `uint32_t` is meant  
- Ignoring a `vw_err_t` return value  
- `goto` forward-jumping past a variable declaration  
- `malloc(0)` (implementation-defined behaviour)  

---

## 14. Endian helpers

Serialisation always uses the byte-shift helpers from `src/core/vw_proto.h`:

```c
static inline uint32_t vw_read_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void vw_write_u32le(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
```

Equivalent helpers exist for `u16` and `u64`. Use them everywhere integers cross a wire or disk boundary. **Never** cast a `uint8_t *` to a wider integer type, and **never** use `memcpy` into a typed integer variable for endian conversion — both violate strict-aliasing rules and produce undefined behaviour.

---

## 15. Sensitive-data zeroing and constant-time comparison

Use `secure_zero` (a volatile function pointer to `memset`) to zero password hashes, session tokens, OTP hashes, and private keys before freeing them or returning from a function:

```c
/* Define at the top of each translation unit that handles secrets: */
static void (*volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) (g_memset_fn)((p), 0, (size_t)(n))
```

Plain `memset` may be elided as a dead store by optimising compilers. The volatile indirection prevents this.

Use `vw_crypto_constant_time_eq` for **all** security-sensitive byte comparisons (session tokens, auth tokens, OTP hashes). **Never** use `memcmp` for secrets — it short-circuits on the first differing byte and leaks timing information.

Always run the Argon2id hash even when the user is not found (timing normalisation), discarding the result:

```c
/* Timing normalisation: always hash, always takes the same time. */
(void)vw_crypto_argon2id_hash(password, pw_len, dummy_salt, NULL, dummy_hash);
```

---

## 16. Test conventions

Unit tests use the hand-rolled TAP v13 harness in `tests/unit/vw_test.h`:

```c
VW_TEST_SUITE("module_name") {
    VW_TEST_CASE("what it should do") {
        /* ... */
        VW_ASSERT_OK(rc);
        VW_ASSERT_EQ(expected, actual);
    }
}
VW_TEST_SUITE_END()
```

Rules:
- **Isolation**: every test case creates its own temporary directory via `make_tmpdir(out, size, label)` and removes it at the end. No test may share state with another.
- **File-scope callbacks**: C11 has no nested functions. Callbacks passed to `vw_store_user_scan`, `vw_oplog_replay_from`, and similar APIs must be declared at file scope.
- **VW_OPLOG_SEGMENT_MAX override**: tests that exercise oplog segment rotation set `VW_OPLOG_SEGMENT_MAX=512` via CMake `target_compile_definitions` to trigger rotation with ~25 small entries instead of the production 64 MiB.
- **vw_server_lib**: server-module tests link against the `vw_server_lib` static library. Tests that need a custom `VW_OPLOG_SEGMENT_MAX` or stub symbols (e.g. `test_vw_gc`) compile server sources directly and do not link `vw_server_lib`.
- **Stub pattern for opaque types**: when a test must control an opaque context (e.g. `vw_cluster_t`) without linking the real implementation, define the struct in the test file and provide stub implementations of the two or three functions called by the module under test. Exclude the real implementation from the test binary's source list to avoid duplicate symbols.

---

## Version history

| Date       | Author  | Change                        |
|------------|---------|-------------------------------|
| 2026-06-23 | CQR.08  | Initial guide                 |
| 2026-07-13 | CQR.08  | Added §14 endian helpers, §15 sensitive-data zeroing, §16 test conventions |
