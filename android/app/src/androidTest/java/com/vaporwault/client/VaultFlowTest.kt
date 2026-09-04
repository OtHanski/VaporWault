package com.vaporwault.client

import android.content.ContentValues
import android.content.Intent
import android.os.Environment
import android.provider.MediaStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import com.vaporwault.client.UiTestHelpers.clearAndType
import com.vaporwault.client.UiTestHelpers.click
import com.vaporwault.client.UiTestHelpers.clickDesc
import com.vaporwault.client.UiTestHelpers.clickText
import com.vaporwault.client.UiTestHelpers.clickTextContains
import com.vaporwault.client.UiTestHelpers.device
import com.vaporwault.client.UiTestHelpers.shell
import com.vaporwault.client.UiTestHelpers.waitFor
import com.vaporwault.client.UiTestHelpers.waitForAll
import com.vaporwault.client.UiTestHelpers.waitUntilTextAppears
import com.vaporwault.client.ui.LoginActivity
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented vault coverage (TASK-243): create a vault, upload into it,
 * exit and re-unlock with the correct passphrase, verify the file is still
 * there byte-identical, then a negative case with a wrong passphrase.
 * `TASK-235`'s `CoreFlowTest` covers the non-vault login/browse/transfer
 * path only — vault create/unlock/browse had zero instrumented coverage
 * before this.
 *
 * Requires a real `vapourwaultd` reachable at [TestServerConfig]'s
 * host/port, same as `CoreFlowTest`.
 */
@RunWith(AndroidJUnit4::class)
class VaultFlowTest {

    private val testFileName = "vw_vault_test_upload.txt"
    private val testFileContent = "VaporWault vault instrumented test content — ${System.currentTimeMillis()}"
    private val vaultFolderName = "vw-vault-test-${System.currentTimeMillis()}"
    private val correctPassphrase = "VaultTestPass123"
    private val wrongPassphrase = "WrongPassphrase456"
    private var seededDownloadUri: android.net.Uri? = null

    @Before
    fun freshLaunch() {
        seedTestFileInDownloads()
        // TASK-243: see CoreFlowTest's identical call for why.
        UiTestHelpers.grantNotificationPermission()
        repeat(3) { device().pressBack() }
        val intent = Intent(InstrumentationRegistry.getInstrumentation().targetContext, LoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        InstrumentationRegistry.getInstrumentation().targetContext.startActivity(intent)
        waitFor("connectButton")
    }

    @After
    fun cleanup() {
        seededDownloadUri?.let {
            InstrumentationRegistry.getInstrumentation().targetContext.contentResolver.delete(it, null, null)
        }
        // Same reasoning as CoreFlowTest's cleanup: don't leave this run's
        // saved profile behind for the next run to trip over
        // (TASK-00241).
        val registry = com.vaporwault.client.accounts.VwAccountRegistry(
            InstrumentationRegistry.getInstrumentation().targetContext,
        )
        registry.listProfiles()
            .filter { it.username == TestServerConfig.username && it.host == TestServerConfig.host }
            .forEach { registry.removeProfile(it.id) }
    }

    private fun seedTestFileInDownloads() {
        val resolver = InstrumentationRegistry.getInstrumentation().targetContext.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, testFileName)
            put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: error("MediaStore insert into Downloads failed")
        resolver.openOutputStream(uri)?.use { it.write(testFileContent.toByteArray()) }
            ?: error("Could not open an output stream for the seeded test file")
        seededDownloadUri = uri
    }

    /** Same navigation CoreFlowTest uses for the SAF Downloads picker. */
    private fun navigateSafPickerToDownloadsAndSelect(fileName: String) {
        clickDesc("Show roots")
        clickText("Downloads")
        check(device().wait(Until.hasObject(By.text(fileName)), 10_000)) {
            "'$fileName' not found in the Downloads picker listing"
        }
        clickText(fileName)
    }

    /** AlertDialog's stable framework positive-button id — not `clickText`,
     * since this dialog's own title/button can share label text with
     * something else already on screen (the same pitfall CoreFlowTest's
     * new-folder dialog hit — see its own comment on this). */
    private fun clickDialogPositiveButton() {
        check(device().wait(Until.hasObject(By.res("android", "button1")), 5_000)) {
            "Dialog positive button not found"
        }
        device().findObject(By.res("android", "button1")).click()
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

    /** Same rationale as `CoreFlowTest`'s identical helper — TASK-00241:
     * enough accumulated root-level folders make a newly-created one
     * scroll out of `fileList`'s rendered window, where a text search
     * genuinely cannot find it. Vault folders from earlier runs of this
     * test file accumulate at the root the same way CoreFlowTest's own
     * `vw-test-*` folders do (observed directly while writing this file —
     * repeated local runs eventually made a brand-new vault folder
     * undiscoverable). */
    private fun purgeStaleTestFolders() {
        val client = VwSession.client ?: return
        client.listFiles("/", recursive = false)
            ?.filter { it.entryType == 1 && it.name.startsWith("vw-vault-test-") }
            ?.forEach { client.deleteFileById(it.fileId) }
    }

    private fun enterPassphraseAndSubmit(passphrase: String) {
        check(device().wait(Until.hasObject(By.clazz("android.widget.EditText")), 5_000)) {
            "Passphrase dialog EditText not found"
        }
        device().findObject(By.clazz("android.widget.EditText")).text = passphrase
        clickDialogPositiveButton()
    }

    /** There is no VAULT_DELETE wire message at all (checked
     * docs/PROTOCOL.md and src/core/vw_proto.h — genuinely absent, not
     * just unexposed in this UI), so every vault this account has ever
     * created — this test's own from earlier runs, and TASK-244's own
     * VaultsScaleTest's 10 seeded vaults, whose folders get purged above
     * but whose vault records necessarily outlive that — stays listed in
     * VaultActivity forever. `waitForAll("vaultUnlockButton").last()`
     * silently assumed the newest vault always sorts last in that list,
     * which broke for real once other vaults accumulated: clicking the
     * wrong (folder-already-deleted) vault's unlock button, then
     * submitting *this* vault's correct passphrase against *that* one,
     * fails to unlock and the rest of the test times out waiting for
     * uploadButton. Vault IDs are assigned monotonically by the server, so
     * the row whose own label is "Vault #<highest id>" is unambiguously
     * this account's most recently created vault — this test's own,
     * regardless of how many others exist or what order the list renders
     * them in. */
    private fun clickUnlockButtonForNewestVault() {
        val client = VwSession.client ?: error("no active session")
        val newestVaultId = client.listVaults()?.maxOfOrNull { it.vaultId }
            ?: error("listVaults() failed or returned no vaults: vw_err_t=${VwClient.lastError()}")
        val label = "Vault #$newestVaultId"
        check(device().wait(Until.hasObject(By.text(label)), 25_000)) {
            "'$label' not found in VaultActivity's vault list"
        }
        val row = device().findObject(By.clazz("android.widget.LinearLayout").hasDescendant(By.text(label)))
        row.findObject(UiTestHelpers.byId("vaultUnlockButton")).click()
    }

    @Test
    fun createUnlockUploadPersistAndRejectWrongPassphrase() {
        login()

        // ── Create the vault (this also uploads-in nothing yet; creating
        // navigates straight into vault-mode FileBrowserActivity) ────────
        click("vaultsButton")
        waitFor("createVaultButton")
        clearAndType("newVaultFolderField", vaultFolderName)
        clearAndType("newVaultPassphraseField", correctPassphrase)
        clearAndType("newVaultPassphraseConfirmField", correctPassphrase)
        click("createVaultButton")
        waitFor("uploadButton", timeoutMs = 15_000)

        // ── Upload into the vault ────────────────────────────────────────
        click("uploadButton")
        navigateSafPickerToDownloadsAndSelect(testFileName)
        waitUntilTextAppears(testFileName, timeoutMs = 15_000)

        // Delete the local seed copy now — the later byte-identical check
        // downloads back to this same path/name, and leaving the original
        // seed file in place would make that check trivially pass even if
        // the download itself did nothing (it would just be re-reading the
        // untouched seed file, not verifying anything came back over the
        // wire from inside the vault).
        shell("rm -f /sdcard/Download/$testFileName")

        // ── Exit the vault, then re-enter and unlock with the *correct*
        // passphrase — the file must still be there ─────────────────────
        click("exitVaultButton")
        waitFor("vaultsButton")
        click("vaultsButton")
        clickUnlockButtonForNewestVault()
        enterPassphraseAndSubmit(correctPassphrase)
        waitFor("uploadButton", timeoutMs = 15_000)
        waitUntilTextAppears(testFileName, timeoutMs = 15_000)

        // ── Download it back and verify it's byte-identical ─────────────
        waitForAll("entryMenuButton").last().click()
        clickText("Download")
        clickTextContains("SAVE")
        var downloadedContent = ""
        val deadline = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < deadline) {
            downloadedContent = shell("cat /sdcard/Download/$testFileName")
            if (downloadedContent.isNotEmpty()) break
            Thread.sleep(500)
        }
        check(downloadedContent == testFileContent) {
            "Downloaded vault file content mismatch — expected '$testFileContent', got '$downloadedContent'"
        }
        shell("rm -f /sdcard/Download/$testFileName")

        // ── Wrong passphrase: exit, re-enter, unlock with the wrong
        // passphrase — must be cleanly rejected, not silently accepted ──
        click("exitVaultButton")
        waitFor("vaultsButton")
        click("vaultsButton")
        clickUnlockButtonForNewestVault()
        enterPassphraseAndSubmit(wrongPassphrase)
        waitUntilTextAppears("Unlock failed", timeoutMs = 10_000)
        // Still on VaultActivity, not navigated into the vault — the
        // create-vault form (always present on this screen) is still
        // reachable, proving the rejected unlock didn't proceed anywhere.
        check(com.vaporwault.client.UiTestHelpers.exists("createVaultButton")) {
            "Expected to still be on VaultActivity after a rejected unlock"
        }
    }
}
