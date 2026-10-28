package com.securevault.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.FileProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securevault.BuildConfig
import com.securevault.R
import com.securevault.app
import com.securevault.security.Role
import com.securevault.security.Session
import com.securevault.vault.ItemSummary
import com.securevault.vault.ItemType
import com.securevault.vault.SecureSharer
import java.io.File

/** Main screen: decrypted titles live only in this activity's memory and are cleared on stop/lock. */
class VaultActivity : BaseSecureActivity() {
    private val adapter = ItemAdapter { onItemClick(it) }

    private var cameraTempFile: File? = null
    private var cameraTempUri: Uri? = null

    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) importFile(uri)
    }

    private val takePicture = registerForActivityResult(ActivityResultContracts.TakePicture()) { success ->
        val uri = cameraTempUri
        val file = cameraTempFile
        if (success && uri != null) {
            importCapturedPhoto(uri, file)
        } else {
            file?.delete()
            cameraTempFile = null
            cameraTempUri = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vault)
        findViewById<RecyclerView>(R.id.list).apply {
            layoutManager = LinearLayoutManager(this@VaultActivity)
            adapter = this@VaultActivity.adapter
        }
        val readOnly = Session.role == Role.VIEW_ONLY && BuildConfig.ENFORCE_INTEGRITY
        findViewById<TextView>(R.id.statusText).text =
            if (readOnly) "READ-ONLY · Device state untrusted" else "VAULT UNLOCKED · 100% Offline · Hardware AES-256-GCM"
        if (readOnly) {
            findViewById<android.view.View>(R.id.vaultStatusDot)?.setBackgroundResource(R.drawable.bg_status_dot_amber)
        }
        findViewById<Button>(R.id.newNoteBtn).apply {
            isEnabled = !readOnly
            setOnClickListener { openEditor(null, ItemType.NOTE) }
        }
        findViewById<Button>(R.id.newCredBtn).apply {
            isEnabled = !readOnly
            setOnClickListener { openEditor(null, ItemType.CREDENTIAL) }
        }

        // Wire top navigation bar action buttons
        findViewById<android.view.View>(R.id.btnImport)?.setOnClickListener {
            if (readOnly) toast("Read-only mode") else {
                AlertDialog.Builder(this)
                    .setTitle("Import Document")
                    .setItems(arrayOf("Choose File from Storage", "Scan Document with Camera")) { _, which ->
                        when (which) {
                            0 -> {
                                Session.suppressLock = true
                                pickFile.launch(arrayOf("*/*"))
                            }
                            1 -> {
                                val cameraDir = File(cacheDir, "camera").apply { mkdirs() }
                                val tempFile = File(cameraDir, "scan_${System.currentTimeMillis()}.jpg")
                                val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", tempFile)
                                cameraTempFile = tempFile
                                cameraTempUri = uri
                                Session.suppressLock = true
                                takePicture.launch(uri)
                            }
                        }
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }
        }
        findViewById<android.view.View>(R.id.btnAudit)?.setOnClickListener {
            Session.suppressLock = true
            startActivity(Intent(this, AuditActivity::class.java))
        }
        findViewById<android.view.View>(R.id.btnLock)?.setOnClickListener { lockNow("MANUAL") }
        findViewById<android.view.View>(R.id.btnWipe)?.setOnClickListener { confirmWipe() }
    }

    override fun onResume() {
        super.onResume()
        Session.suppressLock = false
        if (Session.unlocked) authed({ app.repo.list() }) { items ->
            adapter.submit(items)
            findViewById<TextView>(R.id.countNotes)?.text = items.count { it.type == ItemType.NOTE }.toString()
            findViewById<TextView>(R.id.countCreds)?.text = items.count { it.type == ItemType.CREDENTIAL }.toString()
            findViewById<TextView>(R.id.countFiles)?.text = items.count { it.type == ItemType.FILE }.toString()
        }
    }

    override fun onStop() {
        adapter.submit(emptyList()) // drop decrypted titles from memory
        super.onStop()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_vault, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        R.id.action_add_file -> {
            if (Session.role == Role.VIEW_ONLY && BuildConfig.ENFORCE_INTEGRITY) toast("Read-only mode") else {
                Session.suppressLock = true
                pickFile.launch(arrayOf("*/*"))
            }
            true
        }
        R.id.action_audit -> {
            Session.suppressLock = true
            startActivity(Intent(this, AuditActivity::class.java))
            true
        }
        R.id.action_lock -> { lockNow("MANUAL"); true }
        R.id.action_wipe -> { confirmWipe(); true }
        else -> super.onOptionsItemSelected(item)
    }

    private fun openEditor(id: Long?, type: ItemType) {
        Session.suppressLock = true
        startActivity(
            Intent(this, EditorActivity::class.java)
                .putExtra(EditorActivity.EXTRA_ID, id ?: -1L)
                .putExtra(EditorActivity.EXTRA_TYPE, type.name),
        )
    }

    private fun onItemClick(item: ItemSummary) {
        if (item.type != ItemType.FILE) { openEditor(item.id, item.type); return }
        AlertDialog.Builder(this)
            .setTitle(item.title)
            .setItems(arrayOf("Share (temporary grant)", "Delete")) { _, which ->
                if (which == 0) {
                    authed({ app.repo.readFile(item.id) }) { (name, bytes) ->
                        SecureSharer.share(this, name, bytes)
                        app.audit.log("SHARE_FILE")
                    }
                } else {
                    authed({ app.repo.delete(item.id) }) { onResume() }
                }
            }
            .show()
    }

    private fun importFile(uri: Uri) {
        authed({
            val name = contentResolver.query(uri, null, null, null, null)?.use { c ->
                val col = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (c.moveToFirst() && col >= 0) c.getString(col) else null
            } ?: "file"
            app.repo.importFile(uri, name)
        }) {
            toast("File encrypted and stored")
            onResume()
        }
    }

    private fun importCapturedPhoto(uri: Uri, tempFile: File?) {
        val fileName = "scan_${System.currentTimeMillis()}.jpg"
        authed({
            app.repo.importFile(uri, fileName)
            tempFile?.let { file ->
                try {
                    if (file.exists()) {
                        val len = file.length().toInt().coerceAtMost(8 * 1024 * 1024)
                        if (len > 0) file.writeBytes(ByteArray(len))
                        file.delete()
                    }
                } catch (_: Exception) {}
            }
            cameraTempFile = null
            cameraTempUri = null
        }) {
            toast("Document scanned & encrypted into vault")
            onResume()
        }
    }

    private fun confirmWipe() {
        AlertDialog.Builder(this)
            .setTitle("Wipe vault?")
            .setMessage("This deletes the encryption key and all data. It cannot be undone.")
            .setPositiveButton("Wipe") { _, _ -> wipeAndRestart("MANUAL") }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
