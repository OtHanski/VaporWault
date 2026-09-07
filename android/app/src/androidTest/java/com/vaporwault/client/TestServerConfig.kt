package com.vaporwault.client

import androidx.test.platform.app.InstrumentationRegistry

/**
 * Test server connection details (TASK-235), overridable via `adb shell am
 * instrument -e <key> <value> ...` so this suite can point at a CI-provided
 * server instead of a developer's local one. Defaults match this project's
 * established local dev setup (WSL `vapourwaultd` + `adb reverse`, see
 * `docs/ANDROID_BUILD.md` and the Android client design plan's manual
 * verification section) — a non-2FA test account, since `TASK-00238`
 * currently makes 2FA login structurally unreachable server-side (not an
 * Android bug; login-flow tests below deliberately use the non-2FA account
 * rather than exercising a path known to be broken upstream).
 */
object TestServerConfig {
    private val args = InstrumentationRegistry.getArguments()

    private fun arg(key: String, default: String): String = args.getString(key) ?: default

    val host: String get() = arg("vw_test_host", "127.0.0.1")
    val port: Int get() = arg("vw_test_port", "4430").toInt()
    val username: String get() = arg("vw_test_user", "androidtest2")
    val password: String get() = arg("vw_test_pass", "TestPass456!")

    /**
     * A second account, distinct from [username], that must also already
     * exist server-side (TASK-243) — [com.vaporwault.client.SharingFlowTest]
     * grants a share to it. Only the username needs to be reachable from
     * this suite; nothing here ever logs into it, since `SharesActivity`
     * only lists shares/links *created by* the current account, never the
     * "shared with me" side (out of scope, matching `SharesActivity`'s own
     * doc comment).
     */
    val shareTargetUsername: String get() = arg("vw_share_target_user", "androidtest3")
}
