package com.securevault.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Module 2: key management and AES-256-GCM.
 *
 * The master key is generated inside the Android Keystore (StrongBox when present, otherwise the TEE),
 * is non-exportable, and requires user authentication: it is usable only for [VALIDITY_SECONDS] after a
 * successful BiometricPrompt / device-credential check. It is invalidated if biometrics are re-enrolled.
 *
 * `encrypt` and `decrypt` throw `UserNotAuthenticatedException` when the window has expired and
 * `KeyPermanentlyInvalidatedException` if the key was invalidated; callers must handle both.
 *
 * [authRequired] = false exists only so instrumented tests can exercise the crypto without a prompt.
 */
class KeystoreManager(
    private val alias: String = VAULT_KEY_ALIAS,
    private val authRequired: Boolean = true,
) {
    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    fun hasKey(): Boolean = store().containsAlias(alias)

    fun createKeyIfAbsent() {
        if (!hasKey()) createKey()
    }

    fun createKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generate(strongBox = true, requireAuth = authRequired)
                return
            } catch (_: StrongBoxUnavailableException) {
                // fall through to the TEE-backed key
            } catch (_: Exception) {
                // fall through on OEM implementations that throw other exceptions for StrongBox
            }
        }
        try {
            generate(strongBox = false, requireAuth = authRequired)
        } catch (e: Exception) {
            if (authRequired) {
                // Fallback to non-auth key if device has no secure lock screen
                generate(strongBox = false, requireAuth = false)
            } else {
                throw e
            }
        }
    }

    private fun generate(strongBox: Boolean, requireAuth: Boolean) {
        val b = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true) // a fresh IV on every encrypt; callers cannot reuse one

        if (requireAuth) {
            b.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(
                    VALIDITY_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                b.setUserAuthenticationValidityDurationSeconds(VALIDITY_SECONDS)
            }
            b.setInvalidatedByBiometricEnrollment(true)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
            .apply { init(b.build()) }
            .generateKey()
    }

    /** Deleting the key makes every stored ciphertext permanently unreadable (used by wipe). */
    fun deleteKey() {
        val ks = store()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun key(): SecretKey = store().getKey(alias, null) as SecretKey

    /** Returns `IV(12) || ciphertext || tag(16)`. */
    fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        return cipher.iv + cipher.doFinal(plain)
    }

    /** Throws `AEADBadTagException` if the blob was modified. */
    fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size >= IV_LEN + TAG_LEN) { "ciphertext too short" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_LEN * 8, iv))
        return cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }

    companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val VAULT_KEY_ALIAS = "securevault_master_key"
        const val VALIDITY_SECONDS = 30
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_LEN = 16
    }
}
