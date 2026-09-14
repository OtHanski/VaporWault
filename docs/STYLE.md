# VaporWault Style Guide

**Owner:** CQR.08
**Applies to:** All `.c`, `.h`, and `.cpp` files in the repository (§1–16); Kotlin under `android/` (§17, owned day-to-day by MOB.10) and TypeScript under `web/src/` (§18, owned day-to-day by WEB.09) as of `TASK-00276`

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
- **Borrowed pointers**: a module that needs another module's already-open handle for its whole lifetime (e.g. `vw_cluster_open`'s `store`/`file_store`/`chunks`/`share_store`/`vault_store`/`conn_registry` parameters) takes it as a plain pointer documented as *borrowed* in the header comment — "same lifetime contract as X above", or similar — never takes ownership, and never frees it. The caller opens it first and closes it after the borrower. An optional dependency (the borrower still works with reduced functionality if it's absent) is documented as "may be NULL" in the same comment rather than silently changing behavior with no signal in the API surface (`vw_vault_store_t`/`vw_share_store_t` in `vw_cluster_open`, `vw_conn_registry_t` likewise). This is the standing pattern for cross-module dependencies in this codebase — checked and confirmed still accurate as of `TASK-00285` (2026-09-14), which added a sixth borrowed parameter to `vw_cluster_open` on top of the five `TASK-172` already established.
- **In-memory-only auxiliary arrays alongside a persisted slot index**: when a module needs to track a piece of state that must NOT be persisted (a live gauge, a transient pin/lock count — never written to the module's own on-disk record format) but is naturally indexed the same way an existing on-disk-backed slot index already is, add a second array grown/freed in lockstep with the first (same capacity, same `_ensure`-style growth function, updated in the same commit that grows the first) rather than a separate side table with its own capacity to keep synchronized. Two independent instances of this same idiom: `vw_vault.c`'s `pin_counts` beside `vid_to_slot` (`TASK-00290`) and `vw_cluster.c`'s `client_conn_counts` beside `nid_to_slot` (`TASK-00285`) — the second was modeled directly on the first.

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

## 17. Kotlin (Android client)

**Owner:** MOB.10
**Applies to:** `android/app/src/main/java/com/vaporwault/client/**/*.kt`

This section documents conventions already consistently followed by the shipped code (`TASK-224`–`251`), derived by reading it rather than imposed from outside — see each rule's citation. Standardize on these for new code; flag a genuine inconsistency to MOB.10/CQR.08 rather than picking a third way.

### Naming

| Entity                          | Convention                          | Example |
|----------------------------------|--------------------------------------|---------|
| Classes                          | `PascalCase`                        | `VwClient`, `VwSecureStore`, `FileEntryAdapter` |
| Functions / properties           | `camelCase`                         | `listFiles`, `folderFileId` |
| Constants (`companion object`)   | `SCREAMING_SNAKE_CASE`               | `VwSecureStore.KEY_ALIAS`, `VwClient.ERR_AUTH_2FA_REQUIRED` |
| JNI external declarations        | `native` + `PascalCase` verb-noun    | `nativeFileList`, `nativeVaultSetup` (`VwNative.kt`) |
| Private backing field for a public getter | same name + `Field` suffix | `VwClient.handleField` backs `VwClient.handle` (`VwClient.kt`) |

No leading-underscore backing-field convention (`_foo`/`foo`) anywhere — use the `Field` suffix instead. `native*` is the one systematic prefix in this codebase: it marks "this call crosses into C," the Kotlin equivalent of the C-side `vw_` prefix rule (§2).

### Null safety

- `!!` is effectively banned by precedent: one occurrence exists in the entire tree. Use `?.let { }`, `?:`, or an explicit `if (x != null)` check instead.
- The dominant idiom at the JNI boundary is `nativeFoo(...)?.let(::decodeFoo)` — a fetch-shaped native call returns a nullable `ByteArray?`/`String?` and the Kotlin wrapper decodes only on success. An action-shaped native call instead returns a non-nullable `Int`/`Long`/`Boolean` sentinel (0/negative = failure) — never a nullable success flag. Keep this split when adding a new native declaration to `VwNative.kt`: nullable return for "fetched something," non-nullable sentinel for "did something."
- A `Long` native handle uses `0L` as its own null sentinel rather than `Long?` — see `VwClient.handle`'s getter, which throws via `error(...)` if the backing field is `0L`.
- `lateinit var` is reserved for Activity fields populated in `onCreate` that are never plausibly read before it runs. Don't reach for it as a general "avoid a nullable type" escape hatch.

### Error handling

- No exceptions and no sealed `Result` type on the native-facing API surface. A fetch-shaped method returns `null` on failure; an action-shaped method returns a nonzero/negative sentinel. Either way, the caller retrieves the actual `vw_err_t` via `VwClient.lastError()` / `VwVault.lastError()`, which read a native thread-local slot.
- **Known footgun, worth repeating for new code**: `lastError()` must be captured on the same background thread that made the failing call, *before* posting the result to `runOnUiThread` — capture it into a local (`val lastError = if (x == null) VwClient.lastError() else 0`) at the point of failure, not inside the UI-thread callback. `VwClient.kt`'s own doc comment on this function calls it out as a mistake this codebase has made more than once.
- Real exceptions are fine at a boundary where the underlying JDK/Android API's own convention already throws — don't invent a null/error-code wrapper just for consistency with the rule above. `VwSecureStore.decrypt` deliberately lets `AEADBadTagException` propagate (matches `javax.crypto`'s own idiom); `getOrCreateKey` catches `StrongBoxUnavailableException` specifically to fall back to a software key.

### Threading

- No coroutines anywhere in this codebase (no `suspend`, no `Flow`) — don't introduce them in isolation for one new feature. Use `kotlin.concurrent.thread { }` + `runOnUiThread { }` for a simple fire-and-forget background action; use `TransferManager`'s `JobScheduler`/User-Initiated-Data-Transfer path (with a foreground-service fallback below API 34) for anything that should survive the Activity going away.
- Cross-thread state uses plain `java.util.concurrent` primitives (`ConcurrentHashMap`, `AtomicBoolean`, `AtomicInteger`), not a coroutine-flavored equivalent — `TransferManager`'s cancel-flag table and work-id counter are the reference example.

### File / module structure

- One public class per file, filename matching the class name. Small, tightly-coupled supporting types (DTOs a class produces, private decode helpers it uses) live in the same file rather than being split out — `VwClient.kt` holds `VwClient` plus its seven small `data class` results and a block of file-scope `private fun ByteBuffer.readX()` extensions below the class.
- No sealed classes anywhere — the nullable-return convention above already covers what a sealed `Result` type would otherwise be for. Don't introduce one for a single new call site.
- Four flat packages under `com.vaporwault.client`: root (native bridge + wrappers), `accounts`, `transfer`, `ui`. No further nesting.

### Comments

- KDoc (`/** */`) on every public class/function, and on a private helper too if its behavior isn't obvious from its name. Plain prose only — no `@param`/`@return` tags, cross-reference other symbols with `[SquareBrackets]` instead. This matches the C-side "plain prose, no Doxygen tags" rule (§10) — kept the same across both languages deliberately, not a coincidence.
- Document a non-obvious invariant right next to the code it constrains (a `ByteBuffer` position/limit gotcha, an API-level gate's reasoning), not only in the file's header comment. Cite the task that found it when there is one — this codebase already does that consistently and it's worth keeping.

### Android-specific idioms

- `RecyclerView.Adapter`: a nested `ViewHolder` class with `findViewById` calls as `val` properties, an `update(newEntries)` method calling `notifyDataSetChanged()` (not `DiffUtil`), and constructor-injected callback lambdas for row actions rather than a listener interface.
- Activities extend `AppCompatActivity`, wire views via `findViewById` in `onCreate` (no ViewBinding/DataBinding), and use `registerForActivityResult(ActivityResultContracts.OpenDocument())` for Storage Access Framework picker flows.
- A `content://` URI from SAF is never passed to native code directly. Every native-facing path takes a real POSIX path — code holding a picked URI stages it through `filesDir`/cache first (`LoginActivity.copyCaCert` is the reference example).

### Native-bridge idioms (the JNI boundary specifically)

- A class wrapping one native handle (`VwClient`, `VwVault`) is `class ... private constructor(handle: Long) : AutoCloseable`, with a private `handleField`, a public `close()` (or a domain-named alias like `logout()`) that zeroes it and is safe to call twice, and every method reading the handle through a getter that throws `IllegalStateException` via `error(...)` once closed. This exact shape is intentionally duplicated between `VwClient` and `VwVault` rather than factored into a shared base — keep duplicating it for a third such class rather than introducing an abstraction for two examples.
- Hold exactly one native handle per wrapper object. When a C function needs two handles (e.g. a vault operation needs both the vault's own handle and the owning session's), pass the second one in explicitly as a parameter (`VwVault`'s methods take `client.rawHandle()`) rather than nesting one wrapper inside another. `rawHandle()` is `internal`, never `public` — a caller outside this module has no business touching a raw native handle.
- Decode a flat wire record via a `private fun ByteBuffer.readX()` extension reading fields in the exact C struct order, using a shared `leBuffer()` helper that sets `ByteOrder.LITTLE_ENDIAN` once rather than per call. A `count`-prefixed array decodes as `List(count) { buf.readX() }`.
- A secret crossing the JNI boundary (password, passphrase) is always `ByteArray`, never `String` — `String` interning on the JVM defeats zeroing it afterward. Build it from an `Editable` directly (`.toString().toCharArray()` is exactly the mistake this rule exists to prevent — it round-trips through an interned `String` first). Zero the buffer on both sides of the boundary independently: the native side zeroes its own copy before returning, and the Kotlin wrapper separately zeroes whatever intermediate encoding buffer it built — one side zeroing its copy is never a substitute for the other doing the same for its own.

---

## 18. TypeScript (web frontend)

**Owner:** WEB.09
**Applies to:** `web/src/*.ts`

No framework, no bundler, no linter beyond the compiler's own settings (`web/tsconfig.json`'s `"strict": true`, `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns` — the actual enforcement mechanism; there is no ESLint config in this project). `tsc` compiles straight to static `.js` served by nginx (`package.json`'s own description) — there is no bundling step to hide file-extension mismatches, so **every relative import must use the `.js` extension the compiled output will actually have**, never `.ts` and never bare (`import { login } from "./api.js"`, not `"./api"` or `"./api.ts"`) — this is a compile-time-invisible mistake (`tsc` accepts either) that only breaks at runtime in the browser, so it's worth stating explicitly rather than assuming it's obvious.

### Module structure

Three files, one job each — keep new code in the file matching its job rather than growing a fourth:
- `api.ts` — thin `fetch()` wrappers over the gateway's `/api/*` endpoints. No DOM access, no UI logic. Every exported function returns `Promise<ApiResult<T>>` (see below) or, for the chunked transfer helpers, throws on a genuinely exceptional condition (see Error handling below).
- `vault-crypto.ts` — the in-browser half of the E2EE vault. Every primitive here is documented as cross-verified byte-for-byte against its native counterpart (`src/core/vw_crypto.c`/`src/client/vw_vault.c`) in the file's own header comment — do the same cross-check before changing one of these functions, not just a "looks equivalent" read of both implementations.
- `main.ts` — DOM wiring and view orchestration. Organized internally into `// ── Section Name (TASK-NNN) ──` banner comments, one per feature view (login, browser, search, sharing, settings, ...) — add a new banner for a new view rather than interleaving its functions among an existing one's.

Naming: files are `kebab-case.ts`; functions/variables are `camelCase`; `interface`s are `PascalCase`; a true constant is `SCREAMING_SNAKE_CASE` (`CHUNK_SIZE`), mutable module-level state stays `camelCase` (`activeSlot`) — the same functions-vs-constants-vs-mutable-state split C uses (§2), just with JS's own casing.

### Error handling

- A network/API call returns a discriminated union, never throws for an ordinary failure: `ApiResult<T> = { ok: true; status; data: T } | { ok: false; status; data: StatusResponse }`. Callers branch on `.ok` and get real compile-time narrowing of `.data`'s shape in each branch — this is deliberately not `{ data: T | null }`, which would lie about the error case's actual shape. Follow this shape for any new `api.ts` endpoint wrapper.
- Reserve a thrown `Error` for a condition the caller cannot reasonably branch on and recover from inline (a malformed response, an unsupported combination the UI should never have been able to trigger) — the chunked upload/download helpers in `api.ts` throw for exactly this class of failure, not for an ordinary rejected request.
- An `async` function called from an event listener (not `await`ed by anything) is invoked as `void handleX()`, never bare — makes the deliberately-unawaited promise visible at the call site instead of looking like an oversight.
- A DOM element expected to exist because it's in the page's own HTML is looked up once through the `el<T extends HTMLElement>(id)` helper, which throws immediately if missing — a hard, loud failure at startup for a wiring bug, distinct from the `ApiResult` pattern above for genuinely-fallible runtime calls. Don't add a second "maybe this element exists" pattern next to it.

### Comments

Plain `/* ... */` or `//` prose explaining *why*, referencing the originating `TASK-NNN` where there is one — no JSDoc tags. Same rule as the C side (§10) and Kotlin (§17), kept consistent across all three languages in this repository deliberately.

---

## Version history

| Date       | Author  | Change                        |
|------------|---------|-------------------------------|
| 2026-06-23 | CQR.08  | Initial guide                 |
| 2026-07-13 | CQR.08  | Added §14 endian helpers, §15 sensitive-data zeroing, §16 test conventions |
| 2026-09-14 | CQR.08  | `TASK-00276`: added §17 Kotlin (Android client) and §18 TypeScript (web frontend) — derived from reading the actual shipped code (`TASK-224`–`251`, `TASK-136`–`141`/`164`–`166`/`198`–`222`), not written from generic best practice. §6 (Memory) gained two entries found during the same drift review: the "borrowed pointer" convention (already used ~30 times across this codebase, most recently `vw_cluster_open`'s sixth parameter, `TASK-00285`) and the in-memory-only-auxiliary-array-in-lockstep-with-a-slot-index idiom (`vw_vault.c`'s `pin_counts`, `TASK-00290`; `vw_cluster.c`'s `client_conn_counts`, `TASK-00285`). Sections 1–16 spot-checked against code shipped since 2026-07-13 (cluster replication, vault/E2EE, web gateway, Android, corruption detection/repair) and found still accurate as written — no other changes needed there. |
