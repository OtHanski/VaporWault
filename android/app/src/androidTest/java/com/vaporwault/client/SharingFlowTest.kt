package com.vaporwault.client

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import com.vaporwault.client.UiTestHelpers.clearAndType
import com.vaporwault.client.UiTestHelpers.click
import com.vaporwault.client.UiTestHelpers.clickText
import com.vaporwault.client.UiTestHelpers.device
import com.vaporwault.client.UiTestHelpers.textExists
import com.vaporwault.client.UiTestHelpers.waitFor
import com.vaporwault.client.UiTestHelpers.waitForAll
import com.vaporwault.client.UiTestHelpers.waitUntilTextAppears
import com.vaporwault.client.ui.LoginActivity
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented sharing/link coverage (TASK-243): grant a share to a second
 * account, verify it appears in `SharesActivity`, revoke it, verify it
 * disappears; same for a public link, once without a password/expiry and
 * once with. `TASK-235`'s `CoreFlowTest` never touches `SharesActivity` or
 * the share/link dialogs added in `TASK-231` — zero instrumented coverage
 * before this.
 *
 * Requires a real `vapourwaultd` reachable at [TestServerConfig]'s
 * host/port, same as `CoreFlowTest`, **plus** a second account
 * ([TestServerConfig.shareTargetUsername]) that must already exist
 * server-side — `SHARE_GRANT` rejects an unknown target username
 * (`vw_file_handlers.c`'s `handle_share_grant`), so this suite cannot
 * create that account itself via the wire protocol; it must be seeded the
 * same way [TestServerConfig.username] is (see `docs/ANDROID_BUILD.md` /
 * the CI job in `.github/workflows/ci.yml`, `TASK-242`).
 */
@RunWith(AndroidJUnit4::class)
class SharingFlowTest {

    private val testFolderName = "vw-share-test-${System.currentTimeMillis()}"

    @Before
    fun setUp() {
        // TASK-243: see CoreFlowTest's identical call for why.
        UiTestHelpers.grantNotificationPermission()
        launchFresh()
        login()
        createTestFolder()
    }

    private fun launchFresh() {
        repeat(3) { device().pressBack() }
        val intent = Intent(InstrumentationRegistry.getInstrumentation().targetContext, LoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        InstrumentationRegistry.getInstrumentation().targetContext.startActivity(intent)
        waitFor("connectButton")
    }

    private fun login() {
        clearAndType("hostField", TestServerConfig.host)
        clearAndType("portField", TestServerConfig.port.toString())
        clearAndType("userField", TestServerConfig.username)
        clearAndType("passField", TestServerConfig.password)
        click("connectButton")
        waitFor("fileList", timeoutMs = 15_000)
        purgeStaleTestFolders()
    }

    /** Same rationale as `CoreFlowTest`'s identical helper (TASK-00241),
     * but scoped to *every* `vw-*-test-*` prefix this test suite uses
     * (`vw-share-test-`, `vw-vault-test-`), not just this file's own —
     * a stale sibling folder left by another test class (most commonly
     * `VaultFlowTest`, which crashes mid-run under `TASK-00246`'s
     * still-open bug, so its own cleanup never gets a chance to run) sorts
     * into the same root listing and can be the one
     * `openEntryMenuForTestFolder`'s `.last()` picks instead of this
     * test's own folder — a real, observed false failure ("Share row for
     * ... not found"), not a hypothetical. */
    private fun purgeStaleTestFolders() {
        val client = VwSession.client ?: return
        client.listFiles("/", recursive = false)
            ?.filter {
                it.entryType == 1 &&
                    (it.name.startsWith("vw-share-test-") || it.name.startsWith("vw-vault-test-"))
            }
            ?.forEach { client.deleteFileById(it.fileId) }
    }

    /** Same stable-id reasoning as `VaultFlowTest`'s identical helper —
     * a dialog's title/button text can collide with other on-screen text,
     * the framework positive-button id never does. */
    private fun clickDialogPositiveButton() {
        check(device().wait(Until.hasObject(By.res("android", "button1")), 5_000)) {
            "Dialog positive button not found"
        }
        device().findObject(By.res("android", "button1")).click()
    }

    private fun createTestFolder() {
        click("newFolderButton")
        check(device().wait(Until.hasObject(By.clazz("android.widget.EditText")), 5_000)) {
            "New-folder dialog EditText not found"
        }
        device().findObject(By.clazz("android.widget.EditText")).text = testFolderName
        clickDialogPositiveButton()
        waitUntilTextAppears(testFolderName)
    }

    private fun openEntryMenuForTestFolder() {
        waitForAll("entryMenuButton").last().click()
    }

    /** Both `shareList` and `linkList` rows reuse the identical
     * `item_share.xml` layout/ids (`ShareAdapter`/`LinkAdapter`) — so a
     * revoke button lookup is only unambiguous when at most one of the
     * two lists has an entry at a time. Every flow below fully revokes
     * (and confirms disappearance) before starting the next one, so this
     * always holds. */
    private fun revokeLastAndConfirmGone(expectedGoneText: String) {
        waitForAll("shareRevokeButton").last().click()
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline && textExists(expectedGoneText)) {
            Thread.sleep(300)
        }
        check(!textExists(expectedGoneText)) {
            "'$expectedGoneText' still present after revoke"
        }
    }

    @Test
    fun grantListAndRevokeShare() {
        openEntryMenuForTestFolder()
        clickText("Share")
        check(device().wait(Until.hasObject(By.res("com.vaporwault.client", "shareUsernameField")), 5_000)) {
            "Share dialog not found"
        }
        device().findObject(By.res("com.vaporwault.client", "shareUsernameField")).text =
            TestServerConfig.shareTargetUsername
        clickDialogPositiveButton()
        waitUntilTextAppears("Shared with ${TestServerConfig.shareTargetUsername}", timeoutMs = 20_000)

        click("sharesButton")
        waitUntilTextAppears(testFolderName, timeoutMs = 20_000)
        // Scoped to this test's own row, same reasoning as the link
        // tests' password-suffix checks below.
        check(textExists("$testFolderName → ${TestServerConfig.shareTargetUsername}")) {
            "Share row for ${TestServerConfig.shareTargetUsername} not found in SharesActivity"
        }

        revokeLastAndConfirmGone(testFolderName)
    }

    @Test
    fun createListAndRevokeLinkWithoutPasswordOrExpiry() {
        openEntryMenuForTestFolder()
        clickText("Get link")
        check(device().wait(Until.hasObject(By.res("com.vaporwault.client", "linkPermissionGroup")), 5_000)) {
            "Get-link dialog not found"
        }
        // Leave password/expiry fields blank — "without a password/expiry".
        clickDialogPositiveButton()
        // A second confirmation dialog shows the link token; dismiss it.
        check(device().wait(Until.hasObject(By.text("OK")), 10_000)) {
            "Link-created confirmation dialog not found"
        }
        clickText("OK")

        click("sharesButton")
        waitUntilTextAppears(testFolderName, timeoutMs = 20_000)
        // Scoped to this test's own row (LinkAdapter's exact label format)
        // rather than a bare "password-protected" substring search — the
        // bare search matches *any* password-protected row currently in
        // linkList, including a sibling test's still-present entry if it
        // happens to run interleaved with or just before this one, which
        // is a real, observed false failure this fixes, not a hypothetical.
        check(textExists("$testFolderName (view)")) {
            "Link created without a password does not show as expected (no password-protected suffix)"
        }

        revokeLastAndConfirmGone(testFolderName)
    }

    @Test
    fun createListAndRevokeLinkWithPasswordAndExpiry() {
        openEntryMenuForTestFolder()
        clickText("Get link")
        check(device().wait(Until.hasObject(By.res("com.vaporwault.client", "linkPasswordField")), 5_000)) {
            "Get-link dialog not found"
        }
        device().findObject(By.res("com.vaporwault.client", "linkPasswordField")).text = "vw-link-test-pw"
        device().findObject(By.res("com.vaporwault.client", "linkExpiryField")).text = "7"
        clickDialogPositiveButton()
        check(device().wait(Until.hasObject(By.text("OK")), 10_000)) {
            "Link-created confirmation dialog not found"
        }
        clickText("OK")

        click("sharesButton")
        waitUntilTextAppears(testFolderName, timeoutMs = 20_000)
        // Same scoping reasoning as the "without password" test above.
        check(textExists("$testFolderName (view, password-protected)")) {
            "Link created with a password does not show as password-protected"
        }

        revokeLastAndConfirmGone(testFolderName)
    }
}
