package com.securevault.vault

import android.content.Context
import android.net.Uri
import com.securevault.data.AppDatabase
import com.securevault.data.FileMeta
import com.securevault.data.VaultItem
import com.securevault.security.AccessController
import com.securevault.security.Action
import com.securevault.security.AuditLogger
import com.securevault.security.KeystoreManager
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.UUID

enum class ItemType { NOTE, CREDENTIAL, FILE }
data class ItemSummary(val id: Long, val type: ItemType, val title: String, val updatedAt: Long)
data class ItemDetail(val id: Long, val type: ItemType, val title: String, val body: String)

/**
 * Modules 2 + 3: the only path to vault data. Every call is access-checked, everything stored is ciphertext,
 * and plaintext exists only in the returned objects. All methods block (call from Dispatchers.IO) and may throw
 * UserNotAuthenticatedException / KeyPermanentlyInvalidatedException from the Keystore.
 */
class VaultRepository(
    private val context: Context,
    private val db: AppDatabase,
    private val keystore: KeystoreManager,
    private val audit: AuditLogger,
) {
    private val vaultDir: File get() = File(context.filesDir, "vault").apply { mkdirs() }

    private fun enc(s: String) = keystore.encrypt(s.toByteArray(Charsets.UTF_8))
    private fun dec(b: ByteArray) = String(keystore.decrypt(b), Charsets.UTF_8)

    fun list(): List<ItemSummary> {
        AccessController.check(Action.READ)
        return db.items().all().map {
            ItemSummary(it.id, ItemType.valueOf(it.type), dec(it.titleEnc), it.updatedAt)
        }
    }

    fun get(id: Long): ItemDetail {
        AccessController.check(Action.READ)
        val i = db.items().byId(id) ?: throw NoSuchElementException("item $id")
        return ItemDetail(i.id, ItemType.valueOf(i.type), dec(i.titleEnc), dec(i.bodyEnc))
    }

    fun save(id: Long?, type: ItemType, title: String, body: String): Long {
        AccessController.check(Action.WRITE)
        val now = System.currentTimeMillis()
        val t = enc(title)
        val b = enc(body)
        return if (id == null) {
            val newId = db.items().insert(VaultItem(type = type.name, titleEnc = t, bodyEnc = b, createdAt = now, updatedAt = now))
            audit.log("ITEM_CREATE")
            newId
        } else {
            val old = db.items().byId(id) ?: throw NoSuchElementException("item $id")
            db.items().update(VaultItem(id, old.type, t, b, old.createdAt, now))
            audit.log("ITEM_UPDATE")
            id
        }
    }

    fun delete(id: Long) {
        AccessController.check(Action.WRITE)
        db.files().byItem(id)?.let { File(vaultDir, it.randomName).delete() }
        db.files().deleteByItem(id)
        db.items().delete(id)
        audit.log("ITEM_DELETE")
    }

    /** Encrypts an imported file (picked via the Storage Access Framework) into app-private storage. */
    fun importFile(uri: Uri, displayName: String): Long {
        AccessController.check(Action.WRITE)
        val plain = context.contentResolver.openInputStream(uri)?.use { readLimited(it) }
            ?: throw IOException("Cannot open file")
        val blob = keystore.encrypt(plain) // encrypt first: fail before anything touches disk
        val randomName = UUID.randomUUID().toString() + ".bin"
        File(vaultDir, randomName).writeBytes(blob)
        val now = System.currentTimeMillis()
        val itemId = db.items().insert(
            VaultItem(type = ItemType.FILE.name, titleEnc = enc(displayName), bodyEnc = enc(""), createdAt = now, updatedAt = now),
        )
        db.files().insert(FileMeta(itemId = itemId, randomName = randomName, size = plain.size.toLong()))
        audit.log("FILE_IMPORT")
        return itemId
    }

    /** Returns (original name, decrypted bytes). Callers must not persist the bytes. */
    fun readFile(itemId: Long): Pair<String, ByteArray> {
        AccessController.check(Action.READ)
        val item = db.items().byId(itemId) ?: throw NoSuchElementException("item $itemId")
        val meta = db.files().byItem(itemId) ?: throw NoSuchElementException("file $itemId")
        val bytes = keystore.decrypt(File(vaultDir, meta.randomName).readBytes())
        return dec(item.titleEnc) to bytes
    }

    /** Ciphertext-only export for sync (Module 5 sends only ciphertext). */
    fun ciphertextForSync(): List<VaultItem> {
        AccessController.check(Action.READ)
        return db.items().all().filter { it.type != ItemType.FILE.name }
    }

    private fun readLimited(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > MAX_FILE_BYTES) throw IOException("File too large (prototype limit 10 MB)")
        }
        return out.toByteArray()
    }

    companion object {
        const val MAX_FILE_BYTES = 10 * 1024 * 1024
    }
}
