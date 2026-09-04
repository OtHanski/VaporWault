package com.vaporwault.client

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.vaporwault.client.UiTestHelpers.device
import com.vaporwault.client.UiTestHelpers.exists
import com.vaporwault.client.UiTestHelpers.waitFor
import com.vaporwault.client.accounts.ProfileStore
import com.vaporwault.client.ui.LoginActivity
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression test for TASK-00241: with enough saved profiles,
 * `LoginActivity`'s `connectButton` (and the rest of the add-profile form
 * below it) stopped appearing in the view hierarchy at all. Seeds profile
 * metadata directly via [ProfileStore] (no live server needed — these
 * profiles are never resumed, only listed) rather than a real
 * [com.vaporwault.client.accounts.VwAccountRegistry.addProfile] round trip.
 */
@RunWith(AndroidJUnit4::class)
class LoginProfileScaleTest {

    private val labelPrefix = "vw-scale-test-"
    private val seededIds = mutableListOf<String>()

    @Before
    fun cleanupPriorRuns() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = ProfileStore(context)
        store.list().filter { it.label.startsWith(labelPrefix) }.forEach { store.remove(it.id) }
    }

    @After
    fun cleanup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = ProfileStore(context)
        seededIds.forEach { store.remove(it) }
    }

    private fun seedProfiles(count: Int) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = ProfileStore(context)
        repeat(count) { i ->
            val profile = store.create(
                label = "$labelPrefix$i",
                host = "example$i.test",
                port = 8443,
                caCertPemPath = "",
                username = "user$i",
                sessionToken = ByteArray(32),
                loginToken = ByteArray(32),
                expiresAt = Long.MAX_VALUE,
            )
            seededIds.add(profile.id)
        }
    }

    private fun launchLoginActivity() {
        repeat(3) { device().pressBack() }
        val intent = Intent(InstrumentationRegistry.getInstrumentation().targetContext, LoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        InstrumentationRegistry.getInstrumentation().targetContext.startActivity(intent)
    }

    @Test
    fun connectButtonReachableWithTenSavedProfiles() {
        seedProfiles(10)
        launchLoginActivity()
        waitFor("connectButton")
        check(exists("connectButton")) {
            "connectButton not found in the view hierarchy with 10 saved profiles"
        }
    }
}
