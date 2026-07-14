/*
 * fuzz_path_validate.c — libFuzzer target for vw_path_validate().
 *
 * The path validator is the first line of defence against path traversal
 * attacks. This target calls it with arbitrary bytes and verifies:
 *   - Never crashes (out-of-bounds read, stack overflow, NULL deref).
 *   - Input containing ".." always returns VW_ERR_PATH_INVALID.
 *   - Input not starting with '/' always returns VW_ERR_PATH_INVALID.
 *   - Input containing '\0' or '\' always returns VW_ERR_PATH_INVALID.
 *   - Input containing "//" always returns VW_ERR_PATH_INVALID.
 *
 * These invariants are checked as postcondition assertions so the fuzzer
 * can detect logic regressions in addition to crash bugs.
 */

#include "vw_file_handlers.h"  /* pulls in vw_err_t via vw_server_core.h → vw_proto.h */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

/*
 * Returns 1 if 'haystack' (length 'hlen') contains 'needle' (length 'nlen').
 * Safe for untrusted 'haystack'.
 */
static int mem_contains(const uint8_t *haystack, size_t hlen,
                        const uint8_t *needle,   size_t nlen)
{
    if (nlen == 0) return 1;
    if (hlen < nlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/*
 * Returns 1 if the path contains a ".." COMPONENT (bounded by '/' or end).
 * "/a..b" → 0 (component is "a..b", not "..").
 * "/a/../b" → 1.
 * "/../" → 1.
 */
static int has_dotdot_component(const uint8_t *path, size_t len)
{
    for (size_t i = 0; i < len; ) {
        /* skip '/' */
        while (i < len && path[i] == '/') i++;
        /* find end of component */
        size_t start = i;
        while (i < len && path[i] != '/') i++;
        size_t comp_len = i - start;
        if (comp_len == 2 && path[start] == '.' && path[start+1] == '.') return 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > UINT32_MAX) return 0;

    vw_err_t rc = vw_path_validate((const char *)data, (uint32_t)size);

    /* ── Postcondition invariants ────────────────────────────────────────── */

    /* 1. Must not start with '/' → always invalid */
    if (size == 0 || data[0] != '/') {
        assert(rc != VW_OK && "vw_path_validate: accepted path not starting with '/'");
    }

    /* 2. Contains a ".." path component → always invalid.
     *    NB: "/a..b" is a valid component name and must NOT trigger this. */
    if (has_dotdot_component(data, size)) {
        assert(rc != VW_OK && "vw_path_validate: accepted path with '..' component");
    }

    /* 3. Contains NUL byte → always invalid */
    if (mem_contains(data, size, (const uint8_t *)"\x00", 1)) {
        assert(rc != VW_OK && "vw_path_validate: accepted path containing NUL");
    }

    /* 4. Contains backslash → always invalid */
    if (mem_contains(data, size, (const uint8_t *)"\\", 1)) {
        assert(rc != VW_OK && "vw_path_validate: accepted path containing backslash");
    }

    /* 5. Contains double slash → always invalid */
    if (mem_contains(data, size, (const uint8_t *)"//", 2)) {
        assert(rc != VW_OK && "vw_path_validate: accepted path containing '//'");
    }

    return 0;
}
