package com.securevault.net

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.securevault.BuildConfig
import com.securevault.SecureVaultApp
import com.securevault.security.WipeCommand
import com.securevault.security.WipeCommandVerifier

/**
 * Module 8: polls the command channel (WorkManager runs it when the network is available, so an offline
 * device executes the command at its next connection). Swap the poll for an FCM message if preferred;
 * the verification and wipe path are identical.
 */
class WipeWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result {
        val app = applicationContext as SecureVaultApp
        val key = WipeCommandVerifier.keyFromBase64(BuildConfig.WIPE_PUBLIC_KEY_B64) ?: return Result.success()

        val (payload, signature) = try {
            app.api.pollWipeCommand() ?: return Result.success()
        } catch (_: Exception) {
            return Result.retry()
        }

        val cmd = WipeCommand.parse(payload)
        val prefs = applicationContext.getSharedPreferences("wipe_state", Context.MODE_PRIVATE)
        val last = prefs.getLong("last_ts", 0L)
        if (cmd == null || !WipeCommandVerifier(key).verify(payload, signature) || cmd.timestamp <= last) {
            app.audit.append("WIPE_CMD_REJECTED")
            return Result.success()
        }
        prefs.edit().putLong("last_ts", cmd.timestamp).apply()
        app.wipeManager.wipe("REMOTE")
        return Result.success()
    }
}
