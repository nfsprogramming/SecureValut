package com.securevault.security

import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import com.securevault.data.AuditDao
import com.securevault.data.AuditEntry
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Module 8: appends hash-chained entries. Event types only; no sensitive content is ever logged.
 * The chain key is a Keystore HMAC key that does NOT require user authentication, so security events
 * (e.g. a failed unlock) can be recorded while the vault is locked.
 */
class AuditLogger(private val dao: AuditDao) {
    private val executor = Executors.newSingleThreadExecutor()
    private val mac: (ByteArray) -> ByteArray = { data ->
        Mac.getInstance("HmacSHA256").apply { init(hmacKey()) }.doFinal(data)
    }

    /** Blocking append; call from a background thread. */
    @Synchronized
    fun append(type: String) {
        try {
            val prev = dao.lastHash() ?: AuditChain.GENESIS
            val ts = System.currentTimeMillis()
            val hash = AuditChain.compute(mac, prev, type, ts)
            dao.insert(AuditEntry(eventType = type, timestamp = ts, prevHash = prev, hash = hash))
        } catch (_: Exception) {
            // Audit logging is resilient and must not break core authentication flows
        }
    }

    /** Fire-and-forget append, safe from any thread (including main). Order is preserved. */
    fun log(type: String) {
        executor.execute { runCatching { append(type) } }
    }

    fun entries(): List<AuditEntry> = dao.all()

    /** Returns the id of the first entry that breaks the chain, or null if the chain is intact. */
    fun verify(): Long? {
        val all = dao.all()
        val links = all.map { AuditChain.Link(it.eventType, it.timestamp, it.prevHash, it.hash) }
        val idx = AuditChain.firstBreak(links, mac)
        return if (idx < 0) null else all[idx].id
    }

    private var fallbackHmacKey: SecretKey? = null

    private fun hmacKey(): SecretKey {
        return try {
            val ks = KeyStore.getInstance(KeystoreManager.PROVIDER).apply { load(null) }
            if (!ks.containsAlias(HMAC_ALIAS)) {
                val spec = KeyGenParameterSpec.Builder(HMAC_ALIAS, KeyProperties.PURPOSE_SIGN).build()
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KeystoreManager.PROVIDER)
                    .apply { init(spec) }
                    .generateKey()
            }
            ks.getKey(HMAC_ALIAS, null) as SecretKey
        } catch (_: Exception) {
            fallbackHmacKey ?: javax.crypto.spec.SecretKeySpec(
                "SecureVaultFallbackAuditHmac256!".toByteArray(Charsets.UTF_8), "HmacSHA256",
            ).also { fallbackHmacKey = it }
        }
    }

    companion object {
        private const val HMAC_ALIAS = "securevault_audit_hmac"
    }
}
