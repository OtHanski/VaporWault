/*
 * vw_test.h — minimal TAP v13 unit test framework for VaporWault.
 *
 * Single-header, no heap allocation, no dependencies beyond stdio.
 * Each test binary should contain exactly one VW_TEST_SUITE block.
 * Each VW_ASSERT* call is one TAP line (globally numbered).
 *
 * Usage:
 *   VW_TEST_SUITE("my_module") {
 *       VW_TEST_CASE("basic arithmetic") {
 *           VW_ASSERT_EQ(1 + 1, 2);
 *           VW_ASSERT_NE(1 + 1, 3);
 *       }
 *       VW_TEST_CASE("string compare") {
 *           VW_ASSERT_STR_EQ("foo", "foo");
 *       }
 *   }
 *   VW_TEST_SUITE_END()
 */

#ifndef VW_TEST_H
#define VW_TEST_H

#include <stdio.h>
#include <string.h>

/* ── Global counters (one per translation unit) ──────────────────────────── */

static int g_vw_test_count  = 0;  /* total assertions emitted */
static int g_vw_test_failed = 0;  /* failed assertions         */

/* ── Suite / case macros ─────────────────────────────────────────────────── */

#define VW_TEST_SUITE(name)                      \
    int main(void) {                             \
        printf("TAP version 13\n");              \
        (void)(name);

/* Print a comment block grouping subsequent assertions under a test name. */
#define VW_TEST_CASE(desc) \
    printf("# --- %s ---\n", (desc));

#define VW_TEST_CASE_END()  /* optional syntactic grouping only */

/* Emit the tail plan and return exit code. */
#define VW_TEST_SUITE_END()                                  \
        printf("1..%d\n", g_vw_test_count);                  \
        return (g_vw_test_failed > 0) ? 1 : 0;               \
    }

/* ── Internal helper ─────────────────────────────────────────────────────── */

#define VW__PASS(label)  \
    printf("ok %d - " label "\n", ++g_vw_test_count)

#define VW__FAIL(label)  \
    do {                                                                     \
        printf("not ok %d - " label "\n", ++g_vw_test_count);               \
        printf("  # FAILED at %s:%d\n", __FILE__, __LINE__);                 \
        g_vw_test_failed++;                                                   \
    } while (0)

/* ── Assertion macros ────────────────────────────────────────────────────── */

#define VW_ASSERT(expr)                                  \
    do {                                                 \
        if (expr) { VW__PASS(#expr); }                   \
        else      { VW__FAIL(#expr); }                   \
    } while (0)

#define VW_ASSERT_EQ(a, b)                               \
    do {                                                 \
        if ((a) == (b)) { VW__PASS(#a " == " #b); }     \
        else            { VW__FAIL(#a " == " #b); }     \
    } while (0)

#define VW_ASSERT_NE(a, b)                               \
    do {                                                 \
        if ((a) != (b)) { VW__PASS(#a " != " #b); }     \
        else            { VW__FAIL(#a " != " #b); }     \
    } while (0)

#define VW_ASSERT_STR_EQ(a, b)                                           \
    do {                                                                  \
        if (strcmp((a), (b)) == 0) { VW__PASS("strcmp(" #a ", " #b ")"); } \
        else {                                                            \
            int _n = ++g_vw_test_count;                                   \
            printf("not ok %d - strcmp(" #a ", " #b ")\n", _n);          \
            printf("  # got \"%s\", expected \"%s\"\n", (a), (b));        \
            printf("  # FAILED at %s:%d\n", __FILE__, __LINE__);          \
            g_vw_test_failed++;                                           \
        }                                                                 \
    } while (0)

#define VW_ASSERT_MEM_EQ(a, b, n)                                         \
    do {                                                                  \
        if (memcmp((a), (b), (n)) == 0)                                   \
            { VW__PASS("memcmp(" #a ", " #b ", " #n ")"); }              \
        else                                                              \
            { VW__FAIL("memcmp(" #a ", " #b ", " #n ")"); }              \
    } while (0)

/*
 * VW_ASSERT_ERR / VW_ASSERT_OK: verify a vw_err_t return value.
 * 'expr' is evaluated once; the int cast avoids -Wenum-compare.
 */
#define VW_ASSERT_ERR(expr, expected_err)                                 \
    do {                                                                  \
        int _rc = (int)(expr);                                            \
        if (_rc == (int)(expected_err)) {                                 \
            VW__PASS(#expr " == " #expected_err);                         \
        } else {                                                          \
            int _n = ++g_vw_test_count;                                   \
            printf("not ok %d - " #expr " == " #expected_err "\n", _n);  \
            printf("  # got %d, expected %d\n", _rc, (int)(expected_err)); \
            printf("  # FAILED at %s:%d\n", __FILE__, __LINE__);          \
            g_vw_test_failed++;                                           \
        }                                                                 \
    } while (0)

#define VW_ASSERT_OK(expr)  VW_ASSERT_ERR((expr), VW_OK)

#endif /* VW_TEST_H */
