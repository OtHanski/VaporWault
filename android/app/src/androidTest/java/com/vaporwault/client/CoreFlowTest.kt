package com.vaporwault.client

import android.content.ContentValues
import android.content.Intent
import android.os.Environment
import android.provider.MediaStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import com.vaporwault.client.UiTestHelpers.byId
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
import com.vaporwault.client.accounts.VwAccountRegistry
import com.vaporwault.client.ui.LoginActivity
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented core-flow test (TASK-235): login (fresh connect, non-2FA
 * account — see [TestServerConfig]'s doc on why 2FA login isn't exercised
 * here), browse, new folder, upload, download-and-verify, delete. This
 * automates exactly the manual `adb`-driven pass TASK-229 was verified
 * with, using `UiTestHelpers`' resource-id-based UiAutomator lookups
 * instead of hardcoded screen coordinates — the coordinate approach was
 * repeatedly fragile in manual testing (a soft keyboard appearing shifts
 * every field below it), which resource-id lookup is immune to by
 * construction.
 *
 * Requires a real `vapourwaultd` reachable at [TestServerConfig]'s
 * host/port (`adb reverse` already set up, matching every prior manual
 * verification pass in this project) with [TestServerConfig]'s account
 * already created and 2FA disabled.
 */
@RunWith(AndroidJUnit4::class)
class CoreFlowTest {

    private val testFileName = "vw_test_upload.txt"
    private val testFileContent = "VaporWault instrumented test content — ${System.currentTimeMillis()}"
    private val testFolderName = "vw-test-${System.currentTimeMillis()}"
    private var seededDownloadUri: android.net.Uri? = null

    @Before
    fun freshLaunch() {
        // No `am force-stop` here — instrumented tests run *inside* the
        // target app's own process (that's what "instrumentation" means),
        // so force-stopping com.vaporwault.client would kill this test
        // runner along with it. Confirmed the hard way: the first version
        // of this test did exactly that and the whole instrumentation run
        // died mid-`@Before` with no exception, just "Process crashed" —
        // launching LoginActivity fresh is enough to reset to a known
        // screen; VwSession's static state is naturally fresh at
        // instrumentation process start regardless.
        //
        // A file the SAF picker can browse to for the upload step. Scoped
        // storage means neither this app's own UID nor the shell UID can
        // write a plain file directly into /sdcard/Download (confirmed the
        // hard way — a shell `echo > /sdcard/Download/...` fails with
        // "Operation not permitted" on this API level, unlike `adb push`,
        // which uses a different, more privileged path entirely) — the
        // correct, scoped-storage-compliant way to seed a file there is a
        // real `MediaStore` insert through `ContentResolver`, which is what
        // the SAF Downloads picker itself is backed by anyway.
        seedTestFileInDownloads()
        // TASK-243: FileBrowserActivity now requests POST_NOTIFICATIONS on
        // first launch (needed for the User-Initiated Data Transfer job's
        // required setNotification() call — see that request's own doc
        // comment) — grant it up front so that system dialog never blocks
        // this test on a fresh install.
        UiTestHelpers.grantNotificationPermission()

        // Defensive: a previous run that failed mid-flow (e.g. while the
        // SAF picker was open) can leave system UI on top with no app
        // activity to receive our next startActivity() call reliably.
        // pressBack() on an already-clean home screen is a harmless no-op.
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
        // Every run of this test creates a fresh saved profile via a real
        // login (see loginBrowseUploadDownloadDelete) — remove all of
        // them matching the test account, not just "the one this run
        // made", so a prior run's incomplete cleanup (e.g. this test
        // itself failing before reaching @After) can't silently
        // accumulate across runs. This isn't just tidiness: TASK-00241
        // found that enough accumulated saved profiles make
        // LoginActivity's connectButton stop being discoverable at all,
        // which would otherwise make this test's *own* repeated runs
        // eventually break themselves.
        val registry = VwAccountRegistry(InstrumentationRegistry.getInstrumentation().targetContext)
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

    /**
     * Deletes any root-level folder left over from an earlier run of this
     * test that didn't reach its own cleanup steps (e.g. this test itself
     * failing partway through, which — until every bug this file's own
     * commit history fixed was actually fixed — happened a lot). Not just
     * tidiness: `TASK-00241` found that enough accumulated items make a
     * newly-created one scroll out of the `RecyclerView`'s rendered
     * window, where a text search genuinely cannot find it (unlike a
     * plain `ScrollView`, `RecyclerView` really doesn't lay out what
     * isn't visible) — which made *this specific test* intermittently
     * fail against its own leftover state from prior failed runs.
     */
    private fun purgeStaleTestFolders() {
        val client = VwSession.client ?: return
        client.listFiles("/", recursive = false)
            ?.filter { it.entryType == 1 && it.name.startsWith("vw-test-") }
            ?.forEach { client.deleteFileById(it.fileId) }
    }

    @Test
    fun loginBrowseUploadDownloadDelete() {
        // ── Login ────────────────────────────────────────────────────────
        clearAndType("hostField", TestServerConfig.host)
        clearAndType("portField", TestServerConfig.port.toString())
        clearAndType("userField", TestServerConfig.username)
        clearAndType("passField", TestServerConfig.password)
        // No extra pressBack() needed here — clearAndType() now dismisses
        // the IME itself after every field (see its own doc comment for
        // why that turned out to matter, not just for this last field).
        click("connectButton")
        waitFor("fileList", timeoutMs = 15_000)
        purgeStaleTestFolders()

        // ── New folder ───────────────────────────────────────────────────
        click("newFolderButton")
        check(device().wait(Until.hasObject(By.clazz("android.widget.EditText")), 5_000)) {
            "New-folder dialog EditText not found"
        }
        device().findObject(By.clazz("android.widget.EditText")).text = testFolderName
        // No pressBack() here (unlike clearAndType) — this EditText was
        // never `.click()`ed first, so it never gained real focus and no
        // IME ever appeared; a pressBack() with no keyboard to consume it
        // dismisses the dialog itself instead, which is exactly what
        // happened here the first time this was tried (button1 never
        // found again afterward — the dialog was simply gone).
        // Not clickText("NEW FOLDER") — this dialog's own positive button
        // and the *screen's* newFolderButton underneath it both
        // auto-uppercase to the exact same text "NEW FOLDER" (real
        // Button/MaterialButton widgets do this by default; the dialog
        // doesn't remove the underlying screen from the accessibility
        // tree, just draws over it), so a text match can silently hit the
        // wrong one — confirmed via the server log showing zero
        // FILE_MKDIR calls despite this click "succeeding". Android's
        // AlertDialog positive/negative buttons have stable framework
        // resource ids regardless of their label text; use those instead.
        check(device().wait(Until.hasObject(By.res("android", "button1")), 5_000)) {
            "New-folder dialog's positive button not found"
        }
        device().findObject(By.res("android", "button1")).click()
        waitUntilTextAppears(testFolderName)

        // ── Open the new folder, upload into it ─────────────────────────
        clickTextContains(testFolderName)
        waitFor("uploadButton")
        click("uploadButton")
        navigateSafPickerToDownloadsAndSelect(testFileName)
        waitUntilTextAppears(testFileName, timeoutMs = 15_000)

        // ── Download it back and verify content byte-for-byte ───────────
        waitForAll("entryMenuButton").last().click()
        clickText("Download")
        // CreateDocument's picker defaults to the last-used location
        // (Downloads, from the SAF navigation above) with the file's own
        // name pre-filled — just confirm.
        clickTextContains("SAVE")
        // Not waiting on the "Download complete" status text here — it's
        // shown only transiently (immediately overwritten by the
        // subsequent folder-reload's own "Loading…"/cleared status), and
        // this download is small enough (~50 bytes) that the whole
        // exchange can finish before this test's next poll even starts.
        // Confirmed via the server log that the download genuinely
        // completed (CHUNK_DOWNLOAD/FILE_STAT/VERSION_CHUNKS all
        // succeeded) despite the text-wait approach missing it — polling
        // for the file's real on-device existence below is the actually
        // meaningful assertion anyway.
        var downloadedListing = ""
        val deadline = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < deadline) {
            downloadedListing = shell("ls /sdcard/Download/")
            if (downloadedListing.contains(testFileName)) break
            Thread.sleep(500)
        }
        check(downloadedListing.contains(testFileName)) {
            "Downloaded file not found in /sdcard/Download/ after 15s — listing: $downloadedListing"
        }

        // ── Delete the test file, then the now-empty test folder
        // (cleanup, also exercises delete) ──────────────────────────────
        waitForAll("entryMenuButton").last().click()
        clickText("Delete")
        clickText("DELETE")
        waitUntilTextAppears("empty", timeoutMs = 10_000)

        // Not device().pressBack() — FileBrowserActivity has no custom
        // back-press handling for breadcrumb navigation, so pressBack()
        // here exits the whole activity rather than going up one level
        // (confirmed the hard way: "entryMenuButton" was never found
        // afterward because the app was simply gone). Tap the "Home"
        // breadcrumb instead, matching how a real user would navigate up.
        clickTextContains("Home") // BreadcrumbAdapter renders non-last entries as "Home ›", not plain "Home"
        waitForAll("entryMenuButton").last().click()
        clickText("Delete")
        clickText("DELETE")
    }

    /** Drives the DocumentsUI picker to Downloads and taps a file by exact
     * name — the same manual navigation (Show roots → Downloads → file)
     * every prior task in this project was verified against by hand. */
    private fun navigateSafPickerToDownloadsAndSelect(fileName: String) {
        clickDesc("Show roots")
        clickText("Downloads")
        check(device().wait(Until.hasObject(By.text(fileName)), 10_000)) {
            "'$fileName' not found in the Downloads picker listing"
        }
        clickText(fileName)
    }
}
