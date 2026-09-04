package com.vaporwault.client

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.vaporwault.client.UiTestHelpers.clearAndType
import com.vaporwault.client.UiTestHelpers.click
import com.vaporwault.client.UiTestHelpers.device
import com.vaporwault.client.UiTestHelpers.textExists
import com.vaporwault.client.UiTestHelpers.waitFor
import com.vaporwault.client.ui.LoginActivity
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TASK-244: confirms (or rules out) whether `SharesActivity`'s `shareList`
 * exhibits the same `RecyclerView`-in-`ScrollView` overflow bug
 * `TASK-00241` found and fixed in `LoginActivity`'s `profileList` — both
 * use the identical `wrap_content`-height `RecyclerView`-inside-`ScrollView`
 * layout shape, with more content declared after it in the same
 * `LinearLayout` (`linkList`'s own section, then `statusText`).
 *
 * Seeds shares directly via [VwClient.shareGrant] (real server round trips,
 * but no UI interaction needed for seeding — same efficiency reasoning as
 * `LoginProfileScaleTest`) rather than driving the share dialog 10 times.
 */
@RunWith(AndroidJUnit4::class)
class SharesScaleTest {

    private val folderPrefix = "vw-sharesscale-test-"
    private val createdFileIds = mutableListOf<Long>()
    private val createdShareIds = mutableListOf<Long>()

    private fun login(): VwClient {
        repeat(3) { device().pressBack() }
        val intent = Intent(InstrumentationRegistry.getInstrumentation().targetContext, LoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        InstrumentationRegistry.getInstrumentation().targetContext.startActivity(intent)
        waitFor("connectButton")
        clearAndType("hostField", TestServerConfig.host)
        clearAndType("portField", TestServerConfig.port.toString())
        clearAndType("userField", TestServerConfig.username)
        clearAndType("passField", TestServerConfig.password)
        click("connectButton")
        waitFor("fileList", timeoutMs = 15_000)
        return VwSession.client ?: error("no active session after login")
    }

    @After
    fun cleanup() {
        val client = VwSession.client
        // TASK-00246: shares are never hard-deleted server-side (see
        // vw_share.h's vw_share_record_t doc comment) and deleting the
        // shared *file* does not revoke the share record pointing at it —
        // this class used to only delete the folders, leaving 10 ghost
        // share entries (target-resolvable, but with an unresolvable —
        // and therefore blank — file name once the file is gone) in every
        // later test's SharesActivity listing. A real, observed cause of
        // SharingFlowTest.grantListAndRevokeShare failing to find its own
        // share's row: those 10 leaked entries pushed it out of shareList's
        // fixed-height visible window. Revoke before deleting.
        createdShareIds.forEach { client?.shareRevoke(it) }
        createdFileIds.forEach { client?.deleteFileById(it) }
        // TASK-245: login() creates a brand-new saved profile every call
        // (VwAccountRegistry.addProfile never de-dupes by username/host) —
        // left uncleaned, it's a leaked stray profile the next test class's
        // own LoginActivity launch inherits. Same reasoning as CoreFlowTest/
        // VaultFlowTest's identical cleanup.
        val registry = com.vaporwault.client.accounts.VwAccountRegistry(
            InstrumentationRegistry.getInstrumentation().targetContext,
        )
        registry.listProfiles()
            .filter { it.username == TestServerConfig.username && it.host == TestServerConfig.host }
            .forEach { registry.removeProfile(it.id) }
    }

    @Test
    fun tenSharesDoesNotHideLinksSection() {
        val client = login()

        repeat(10) { i ->
            val fileId = client.mkdir(0L, "$folderPrefix$i")
            check(fileId != 0L) { "mkdir failed for $folderPrefix$i: vw_err_t=${VwClient.lastError()}" }
            createdFileIds.add(fileId)
            val shareId = client.shareGrant(fileId, TestServerConfig.shareTargetUsername, 1)
            check(shareId != 0L) { "shareGrant failed for $folderPrefix$i: vw_err_t=${VwClient.lastError()}" }
            createdShareIds.add(shareId)
        }

        click("sharesButton")
        waitFor("shareList", timeoutMs = 15_000)
        // The real assertion: content declared *after* shareList in the
        // same LinearLayout (linkList's own section header) must still be
        // reachable with 10 shares present — matching TASK-00241's exact
        // failure shape (everything after the overflowing RecyclerView
        // silently dropped from layout, not merely scrolled off-screen).
        check(textExists("Public links you've created")) {
            "Content after shareList (linkList's own header) not reachable with 10 shares present"
        }
    }
}
