package com.securevault.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import com.securevault.BuildConfig
import java.io.File
import java.security.MessageDigest

/**
 * Module 6: gathers local integrity signals and (optionally) a server-verified Play Integrity verdict.
 * Local checks can be bypassed by a determined attacker; they are one signal next to the server verdict.
 */
class IntegrityChecker(
    private val context: Context,
    private val play: PlayIntegrityClient,
) {
    suspend fun evaluate(): IntegritySignals = IntegritySignals(
        rooted = isRooted(),
        debuggerAttached = isDebuggerAttached(),
        signatureValid = signatureValid(),
        play = play.verdict(),
    )

    fun isRooted(): Boolean {
        if (SU_PATHS.any { File(it).exists() }) return true
        if (Build.TAGS?.contains("test-keys") == true) return true
        return File("/system").canWrite()
    }

    fun isDebuggerAttached(): Boolean {
        val debuggableFlag = (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        return Debug.isDebuggerConnected() || (!BuildConfig.DEBUG && debuggableFlag)
    }

    /** null = no expected hash configured. */
    fun signatureValid(): Boolean? {
        val expected = BuildConfig.EXPECTED_CERT_SHA256
        if (expected.isBlank()) return null
        val actual = signingCertSha256() ?: return false
        return actual.equals(expected.replace(":", ""), ignoreCase = true)
    }

    @Suppress("DEPRECATION")
    fun signingCertSha256(): String? = try {
        val pm = context.packageManager
        val sig = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners?.firstOrNull()
        } else {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures?.firstOrNull()
        }
        sig?.let {
            MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { b -> "%02x".format(b) }
        }
    } catch (_: Exception) {
        null
    }

    companion object {
        private val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/system/bin/failsafe/su", "/system/app/Superuser.apk",
        )
    }
}
