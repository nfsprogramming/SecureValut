package com.securevault

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.securevault.security.KeystoreManager
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.AEADBadTagException

/**
 * Instrumented tests on a device/emulator. Uses a separate key WITHOUT user-authentication so the crypto
 * can be exercised without a biometric prompt; the production key (authRequired = true) is covered by manual
 * test S5 in the README.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreManagerTest {
    private val ks = KeystoreManager(alias = "securevault_test_key", authRequired = false)

    @Before fun setUp() { ks.deleteKey(); ks.createKey() }
    @After fun tearDown() { ks.deleteKey() }

    @Test fun roundTrip_F4() {
        val plain = "my secret note".toByteArray()
        assertArrayEquals(plain, ks.decrypt(ks.encrypt(plain)))
    }

    @Test fun freshIvEveryTime_S3() {
        val a = ks.encrypt("same".toByteArray())
        val b = ks.encrypt("same".toByteArray())
        assertFalse(a.copyOfRange(0, 12).contentEquals(b.copyOfRange(0, 12)))
        assertFalse(a.contentEquals(b))
    }

    @Test fun ciphertextHasNoPlaintext_S1() {
        val blob = ks.encrypt("TOP-SECRET-MARKER".toByteArray())
        assertFalse(String(blob, Charsets.ISO_8859_1).contains("TOP-SECRET-MARKER"))
    }

    @Test(expected = AEADBadTagException::class)
    fun flippedByteIsRejected_S4() {
        val blob = ks.encrypt("tamper me".toByteArray())
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        ks.decrypt(blob)
    }

    @Test fun deletedKeyMakesDataUnreadable_F10() {
        val blob = ks.encrypt("gone".toByteArray())
        ks.deleteKey()
        assertFalse(ks.hasKey())
        var failed = false
        try { ks.decrypt(blob) } catch (_: Exception) { failed = true }
        assertTrue(failed)
    }
}
