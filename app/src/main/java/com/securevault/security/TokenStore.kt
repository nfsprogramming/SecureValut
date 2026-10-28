package com.securevault.security

import android.content.Context
import android.util.Base64

/** Short-lived sync token, kept as Keystore-encrypted ciphertext (never plain text in preferences). */
class TokenStore(context: Context, private val keystore: KeystoreManager) {
    private val prefs = context.getSharedPreferences("token_store", Context.MODE_PRIVATE)

    fun save(token: String) {
        val blob = keystore.encrypt(token.toByteArray(Charsets.UTF_8))
        prefs.edit().putString(KEY, Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    fun load(): String? {
        val s = prefs.getString(KEY, null) ?: return null
        return String(keystore.decrypt(Base64.decode(s, Base64.NO_WRAP)), Charsets.UTF_8)
    }

    fun has(): Boolean = prefs.contains(KEY)

    fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val KEY = "t"
    }
}
