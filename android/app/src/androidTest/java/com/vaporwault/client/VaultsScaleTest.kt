package com.vaporwault.client

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.vaporwault.client.UiTestHelpers.clearAndType
import com.vaporwault.client.UiTestHelpers.click
import com.vaporwault.client.UiTestHelpers.device
import com.vaporwault.client.UiTestHelpers.waitFor
import com.vaporwault.client.ui.LoginActivity
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TASK-244: confirms (or rules out) whether `VaultActivity`'s `vaultList`
 * exhibits the same `RecyclerView`-in-`ScrollView` overflow bug
 * `TASK-00241` found and fixed in `LoginActivity`'s `profileList` — both
 * use the identical `wrap_content`-height `RecyclerView`-inside-`ScrollView`
 * layout shape, with the create-vault form (and `createVaultButton`)
 * declared after it in the same `LinearLayout`.
 *
 * Seeds vaults directly via [VwVault.setup] (real server round trips incl.
 * Argon2id key derivation, but no UI dialog interaction needed for
 * seeding) rather than driving the create-vault form 10 times.
 */
@RunWith(AndroidJUnit4::class)
class VaultsScaleTest {

    private val folderPrefix = "vw-vaultsscale-test-"
    private val createdFileIds = mutableListOf<Long>()

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
        createdFileIds.forEach { client?.deleteFileById(it) }
        // TASK-245: see SharesScaleTest's identical cleanup for why —
        // login() leaks a brand-new saved profile every call.
        val registry = com.vaporwault.client.accounts.VwAccountRegistry(
            InstrumentationRegistry.getInstrumentation().targetContext,
        )
        registry.listProfiles()
            .filter { it.username == TestServerConfig.username && it.host == TestServerConfig.host }
            .forEach { registry.removeProfile(it.id) }
    }

    @Test
    fun tenVaultsDoesNotHideCreateForm() {
        val client = login()

        repeat(10) { i ->
            val fileId = client.mkdir(0L, "$folderPrefix$i")
            check(fileId != 0L) { "mkdir failed for $folderPrefix$i: vw_err_t=${VwClient.lastError()}" }
            createdFileIds.add(fileId)
            val passphrase = "VaultsScaleTestPass$i".toCharArray()
            val vault = VwVault.setup(client, fileId, passphrase)
            check(vault != null) { "vault setup failed for $folderPrefix$i: vw_err_t=${VwVault.lastError()}" }
        }

        click("vaultsButton")
        // The real assertion: the create-vault form (and its button)
        // declared *after* vaultList in the same LinearLayout must still be
        // reachable with 10 vaults present — matching TASK-00241's exact
        // failure shape. waitFor() itself throws with a clear message if
        // it times out, so no separate check() wrapper is needed here.
        waitFor("createVaultButton", timeoutMs = 15_000)
    }
}
