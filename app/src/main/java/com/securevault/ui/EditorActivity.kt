package com.securevault.ui

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import com.securevault.BuildConfig
import com.securevault.R
import com.securevault.app
import com.securevault.security.Role
import com.securevault.security.Session
import com.securevault.vault.ItemType
import com.securevault.vault.SecureClipboard
import com.securevault.vault.SecureSharer

/** Create / view / edit / delete one encrypted note or credential. Sensitive fields disable autofill and keyboard learning. */
class EditorActivity : BaseSecureActivity() {
    private var itemId: Long? = null
    private lateinit var type: ItemType
    private lateinit var titleInput: EditText
    private lateinit var bodyInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_editor)
        titleInput = findViewById(R.id.titleInput)
        bodyInput = findViewById(R.id.bodyInput)
        itemId = intent.getLongExtra(EXTRA_ID, -1L).takeIf { it >= 0 }
        type = ItemType.valueOf(intent.getStringExtra(EXTRA_TYPE) ?: ItemType.NOTE.name)

        findViewById<View>(R.id.btnBack)?.setOnClickListener { finish() }
        findViewById<TextView>(R.id.editorTitle)?.text = if (itemId != null) {
            if (type == ItemType.CREDENTIAL) "Edit Credential" else "Edit Record"
        } else {
            if (type == ItemType.CREDENTIAL) "New Credential" else "New Note"
        }

        val readOnly = Session.role == Role.VIEW_ONLY && BuildConfig.ENFORCE_INTEGRITY
        val saveBtn = findViewById<Button>(R.id.saveBtn).apply { isEnabled = !readOnly }
        val deleteBtn = findViewById<Button>(R.id.deleteBtn).apply { isEnabled = !readOnly && itemId != null }
        val shareBtn = findViewById<Button>(R.id.shareBtn).apply { isEnabled = itemId != null }
        val copyBtn = findViewById<Button>(R.id.copyBtn)
        titleInput.isEnabled = !readOnly
        bodyInput.isEnabled = !readOnly
        titleInput.isFocusable = true
        titleInput.isFocusableInTouchMode = true
        bodyInput.isFocusable = true
        bodyInput.isFocusableInTouchMode = true

        itemId?.let { id ->
            authed({ app.repo.get(id) }) { d ->
                titleInput.setText(d.title)
                bodyInput.setText(d.body)
            }
        }

        saveBtn.setOnClickListener {
            val title = titleInput.text.toString().ifBlank { "Untitled" }
            val body = bodyInput.text.toString()
            authed({ app.repo.save(itemId, type, title, body) }) { finish() }
        }
        deleteBtn.setOnClickListener {
            itemId?.let { id -> authed({ app.repo.delete(id) }) { finish() } }
        }
        shareBtn.setOnClickListener {
            val title = titleInput.text.toString().ifBlank { "note" }
            val body = bodyInput.text.toString()
            SecureSharer.share(this, "$title.txt", body.toByteArray(Charsets.UTF_8))
            app.audit.log("SHARE_ITEM")
        }
        copyBtn.setOnClickListener {
            SecureClipboard.copy(this, bodyInput.text.toString())
            toast("Copied; clipboard clears in 30 s")
        }
    }

    override fun onResume() {
        super.onResume()
        Session.suppressLock = false
    }

    override fun onStop() {
        // Drop plaintext from the views when leaving the foreground.
        if (!isChangingConfigurations) { titleInput.text.clear(); bodyInput.text.clear() }
        super.onStop()
    }

    companion object {
        const val EXTRA_ID = "id"
        const val EXTRA_TYPE = "type"
    }
}
