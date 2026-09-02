package com.vaporwault.client

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until

private const val PKG = "com.vaporwault.client"
private const val DEFAULT_TIMEOUT_MS = 20_000L

/**
 * Thin UiAutomator wrappers (TASK-235) — chosen over Espresso alone because
 * several flows this app drives cross into system UI outside the app's own
 * process (the SAF document picker) that Espresso's in-app view matchers
 * cannot reach. These helpers exist to make test bodies read like the
 * manual `adb`-driven verification steps every prior Android task in this
 * project was actually checked against — find by resource id, tap, type,
 * wait — not to hide real assertions behind indirection.
 */
object UiTestHelpers {
    fun device(): UiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

    fun byId(resId: String) = By.res(PKG, resId)

    fun waitFor(resId: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): UiObject2 {
        val dev = device()
        check(dev.wait(Until.hasObject(byId(resId)), timeoutMs)) {
            "Timed out waiting for view with id '$resId'"
        }
        return dev.findObject(byId(resId))
    }

    fun waitForText(text: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): UiObject2 {
        val dev = device()
        check(dev.wait(Until.hasObject(By.text(text)), timeoutMs)) {
            "Timed out waiting for text '$text'"
        }
        return dev.findObject(By.text(text))
    }

    fun waitForTextContains(substring: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): UiObject2 {
        val dev = device()
        val pattern = Regex(".*${Regex.escape(substring)}.*")
        check(dev.wait(Until.hasObject(By.text(pattern.toPattern())), timeoutMs)) {
            "Timed out waiting for text containing '$substring'"
        }
        return dev.findObject(By.text(pattern.toPattern()))
    }

    fun exists(resId: String): Boolean = device().hasObject(byId(resId))

    fun textExists(substring: String): Boolean {
        val pattern = Regex(".*${Regex.escape(substring)}.*").toPattern()
        return device().hasObject(By.text(pattern))
    }

    fun click(resId: String) = waitFor(resId).click()

    /** Waits for exact text (e.g. a dialog button's label) then clicks it.
     * Every click in this test suite goes through a `wait*` helper first —
     * a plain immediate `findObject().click()` raced the UI at least once
     * during development (see `CoreFlowTest`'s history) since dialogs and
     * screen transitions aren't instantaneous. */
    fun clickText(text: String): UiObject2 {
        val dev = device()
        check(dev.wait(Until.hasObject(By.text(text)), DEFAULT_TIMEOUT_MS)) {
            "Timed out waiting for clickable text '$text'"
        }
        val obj = dev.findObject(By.text(text))
        obj.click()
        return obj
    }

    fun clickTextContains(substring: String): UiObject2 {
        val dev = device()
        val pattern = Regex(".*${Regex.escape(substring)}.*").toPattern()
        check(dev.wait(Until.hasObject(By.text(pattern)), DEFAULT_TIMEOUT_MS)) {
            "Timed out waiting for clickable text containing '$substring'"
        }
        val obj = dev.findObject(By.text(pattern))
        obj.click()
        return obj
    }

    fun clickDesc(desc: String): UiObject2 {
        val dev = device()
        check(dev.wait(Until.hasObject(By.desc(desc)), DEFAULT_TIMEOUT_MS)) {
            "Timed out waiting for clickable content-desc '$desc'"
        }
        val obj = dev.findObject(By.desc(desc))
        obj.click()
        return obj
    }

    /** Waits for at least one object with [resId] to exist, then returns
     * every current match — used for repeated per-row controls (a file
     * list's overflow-menu buttons) where the *last* match is typically
     * the most-recently-added row. */
    fun waitForAll(resId: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): List<UiObject2> {
        val dev = device()
        check(dev.wait(Until.hasObject(byId(resId)), timeoutMs)) {
            "Timed out waiting for any view with id '$resId'"
        }
        return dev.findObjects(byId(resId))
    }

    /** Focuses [resId], replaces its content with [text], then dismisses
     * the IME before returning. The dismiss matters, not just cosmetics:
     * leaving the keyboard up after a `UiObject2.text = value` set (as
     * opposed to real typed input) was repeatedly seen to make the *next*
     * `wait*` call fail to find an adjacent, perfectly-present view for a
     * full timeout window with no exception in between — reproducible
     * even on a freshly-booted emulator, so not an environment-flakiness
     * artifact. Root cause not fully pinned down (likely an IME-transition
     * window-scoping quirk in UiAutomator's search), but dismissing the
     * IME immediately after each field, rather than only once at the end
     * of a run of fields, reliably avoids it. */
    fun clearAndType(resId: String, text: String) {
        val obj = waitFor(resId)
        obj.click()
        obj.text = ""
        obj.text = text
        device().pressBack()
    }

    /** Waits until [textExists] for the given substring, polling rather
     * than a single check — used for async (background-thread) status
     * text updates where a single [waitForTextContains] call's initial
     * `hasObject` poll might race a UI update that lands a moment later. */
    fun waitUntilTextAppears(substring: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS) {
        val dev = device()
        val pattern = Regex(".*${Regex.escape(substring)}.*").toPattern()
        check(dev.wait(Until.hasObject(By.text(pattern)), timeoutMs)) {
            "Timed out (${timeoutMs}ms) waiting for text containing '$substring'"
        }
    }

    /** Runs a shell command on-device via the instrumentation's own
     * `UiAutomation` — equivalent to a plain `adb shell <cmd>` but callable
     * from inside the running test process, so test setup (writing a file
     * for the SAF picker to browse to) is self-contained and portable
     * (works the same locally or in CI) rather than depending on an
     * external `adb` invocation alongside the test run. */
    fun shell(cmd: String): String =
        InstrumentationRegistry.getInstrumentation().uiAutomation
            .executeShellCommand(cmd)
            .let { pfd -> android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd) }
            .use { it.readBytes().toString(Charsets.UTF_8) }
}
