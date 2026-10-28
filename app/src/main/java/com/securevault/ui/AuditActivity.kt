package com.securevault.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.securevault.R
import com.securevault.app
import com.securevault.data.AuditEntry
import com.securevault.security.Session
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Module 8: shows the audit log and verifies the hash chain (test S12). */
class AuditActivity : BaseSecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_audit)

        findViewById<View>(R.id.btnBack)?.setOnClickListener { finish() }

        val list = findViewById<ListView>(R.id.auditList)
        val result = findViewById<TextView>(R.id.resultText)
        val fmt = SimpleDateFormat("MMM d, HH:mm:ss", Locale.US)

        authed({ app.audit.entries() }) { entries ->
            list.adapter = object : BaseAdapter() {
                override fun getCount(): Int = entries.size
                override fun getItem(position: Int): AuditEntry = entries[position]
                override fun getItemId(position: Int): Long = entries[position].id
                override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
                    val view = convertView ?: LayoutInflater.from(this@AuditActivity)
                        .inflate(R.layout.item_audit_timeline, parent, false)
                    val item = getItem(position)
                    view.findViewById<TextView>(R.id.auditEventTag).text = item.eventType
                    view.findViewById<TextView>(R.id.auditEntryId).text = "#${item.id}"
                    view.findViewById<TextView>(R.id.auditTimestamp).text = fmt.format(Date(item.timestamp))
                    return view
                }
            }
        }
        findViewById<Button>(R.id.verifyBtn).setOnClickListener {
            authed({ app.audit.verify() }) { brokenId ->
                if (brokenId == null) {
                    result.text = "✓ Chain intact. Zero tampering detected."
                    result.setBackgroundResource(R.drawable.bg_audit_result_success)
                    result.setTextColor(ContextCompat.getColor(this, R.color.vault_signal_green))
                } else {
                    result.text = "✗ CHAIN BROKEN at entry #$brokenId — log modified!"
                    result.setBackgroundResource(R.drawable.bg_audit_result_broken)
                    result.setTextColor(ContextCompat.getColor(this, R.color.vault_signal_danger))
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        Session.suppressLock = false
    }
}
