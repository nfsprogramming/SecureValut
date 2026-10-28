package com.securevault.security

import android.content.Context
import com.securevault.data.AppDatabase
import com.securevault.vault.SecureSharer
import java.io.File

/**
 * Module 8: the single wipe path used by remote wipe, auto-wipe and key-invalidation reset.
 * The key is deleted FIRST, so even an interrupted wipe leaves only unreadable ciphertext.
 * The audit log is kept (event types only) so the wipe itself is on record.
 * Blocking: call from a background thread.
 */
class WipeManager(
    private val context: Context,
    private val db: AppDatabase,
    private val keystore: KeystoreManager,
    private val tokens: TokenStore,
    private val audit: AuditLogger,
) {
    fun wipe(reason: String) {
        Session.lock()
        keystore.deleteKey()
        db.users().clear()
        db.items().clear()
        db.files().clear()
        File(context.filesDir, "vault").deleteRecursively()
        SecureSharer.purgeAll(context)
        tokens.clear()
        audit.append("WIPE_$reason")
    }
}
