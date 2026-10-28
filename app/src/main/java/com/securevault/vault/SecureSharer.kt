package com.securevault.vault

import android.app.Activity
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import com.securevault.security.Session
import java.io.File
import java.util.UUID

/**
 * Module 4: share ONE item through a FileProvider URI with a temporary read grant.
 *  1. decrypt to a short-lived file in cache/share/ (the only folder the provider exposes)
 *  2. share with FLAG_GRANT_READ_URI_PERMISSION via the system chooser (explicit user choice, no implicit broadcast)
 *  3. overwrite + delete after [TTL_MS], and whenever the vault locks or is wiped
 */
object SecureSharer {
    private const val DIR = "share"
    private const val TTL_MS = 60_000L
    private val handler = Handler(Looper.getMainLooper())

    fun share(activity: Activity, displayName: String, bytes: ByteArray) {
        val dir = File(activity.cacheDir, DIR).apply { mkdirs() }
        val ext = displayName.substringAfterLast('.', "").filter { it.isLetterOrDigit() }.take(8)
        val file = File(dir, UUID.randomUUID().toString() + if (ext.isNotEmpty()) ".$ext" else "")
        file.writeBytes(bytes)

        val uri = FileProvider.getUriForFile(activity, "${activity.packageName}.fileprovider", file)
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.lowercase()) ?: "application/octet-stream"
        val send = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newRawUri("", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        Session.suppressLock = true // the chooser backgrounds us; do not auto-lock mid-share
        activity.startActivity(Intent.createChooser(send, "Share securely"))
        handler.postDelayed({ shred(file) }, TTL_MS)
    }

    fun purgeAll(context: Context) {
        File(context.cacheDir, DIR).listFiles()?.forEach { shred(it) }
        File(context.cacheDir, "camera").listFiles()?.forEach { shred(it) }
    }

    private fun shred(file: File) {
        try {
            if (file.exists()) {
                file.outputStream().use { it.write(ByteArray(file.length().toInt().coerceAtMost(8 * 1024 * 1024))) }
            }
        } catch (_: Exception) {
            // best effort; delete below regardless
        }
        file.delete()
    }
}
