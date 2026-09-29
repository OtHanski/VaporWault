/*
 * test_vw_update_daily_check_due.c — unit tests for TASK-00298's
 * vw_update_daily_check_due() (src/client/vw_update.c), the pure
 * scheduling decision behind vw_daemon.c's headless/auto-policy daily
 * background update check.
 *
 * This is the function's own acceptance criterion made concrete: "verified
 * to actually fire on a schedule in a test harness (don't just trust the
 * timer code by inspection)". The daemon's own wiring (calling this once
 * per main-loop tick, gated on update_policy=auto) is exercised indirectly
 * by the existing daemon integration tests continuing to pass with that
 * call site present.
 */

#include "vw_test.h"
#include "vw_update.h"

VW_TEST_SUITE("update_daily_check_due") {

    VW_TEST_CASE("never checked before (0) is always due, regardless of interval") {
        VW_ASSERT_EQ(vw_update_daily_check_due(0, 1000, 86400u), 1);
        VW_ASSERT_EQ(vw_update_daily_check_due(0, 0, 86400u), 1);
    }

    VW_TEST_CASE("elapsed time below the interval is not due") {
        int64_t last = 1000;
        int64_t now  = last + 86400 - 1; /* one second short of a full day */
        VW_ASSERT_EQ(vw_update_daily_check_due(last, now, 86400u), 0);
    }

    VW_TEST_CASE("elapsed time exactly at the interval is due") {
        int64_t last = 1000;
        int64_t now  = last + 86400;
        VW_ASSERT_EQ(vw_update_daily_check_due(last, now, 86400u), 1);
    }

    VW_TEST_CASE("elapsed time past the interval is due") {
        int64_t last = 1000;
        int64_t now  = last + 86400 * 3;
        VW_ASSERT_EQ(vw_update_daily_check_due(last, now, 86400u), 1);
    }

    VW_TEST_CASE("a clock that moved backward is never treated as due") {
        int64_t last = 100000;
        int64_t now  = 50000; /* before last_check — e.g. system clock reset */
        VW_ASSERT_EQ(vw_update_daily_check_due(last, now, 86400u), 0);
    }

    VW_TEST_CASE("a zero interval is due as soon as any time (even none) has passed") {
        int64_t last = 1000;
        VW_ASSERT_EQ(vw_update_daily_check_due(last, last, 0u), 1);
    }
}
VW_TEST_SUITE_END()
