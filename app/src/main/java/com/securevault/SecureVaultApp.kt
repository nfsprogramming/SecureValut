package com.securevault

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.securevault.data.AppDatabase
import com.securevault.net.ApiClient
import com.securevault.net.WipeWorker
import com.securevault.security.AuditLogger
import com.securevault.security.AuthManager
import com.securevault.security.IntegrityChecker
import com.securevault.security.KeystoreManager
import com.securevault.security.PlayIntegrityClient
import com.securevault.security.Session
import com.securevault.security.TokenStore
import com.securevault.security.WipeManager
import com.securevault.vault.SecureSharer
import com.securevault.vault.VaultRepository
import java.util.concurrent.TimeUnit

/** Simple manual wiring of the security core (no DI framework, to keep the prototype readable). */
class SecureVaultApp : Application() {
    lateinit var db: AppDatabase
    lateinit var keystore: KeystoreManager
    lateinit var audit: AuditLogger
    lateinit var auth: AuthManager
    lateinit var repo: VaultRepository
    lateinit var tokens: TokenStore
    lateinit var api: ApiClient
    lateinit var integrity: IntegrityChecker
    lateinit var wipeManager: WipeManager

    override fun onCreate() {
        super.onCreate()
        db = AppDatabase.build(this)
        val canAuth = try {
            val bm = androidx.biometric.BiometricManager.from(this)
            val authenticators = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
            } else {
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
            }
            bm.canAuthenticate(authenticators) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
        } catch (_: Exception) {
            false
        }
        keystore = KeystoreManager(authRequired = canAuth && BuildConfig.ENFORCE_INTEGRITY)
        audit = AuditLogger(db.audit())
        auth = AuthManager(db.users(), audit)
        repo = VaultRepository(this, db, keystore, audit)
        tokens = TokenStore(this, keystore)
        api = ApiClient(audit)
        integrity = IntegrityChecker(this, PlayIntegrityClient(this, api))
        wipeManager = WipeManager(this, db, keystore, tokens, audit)

        if (BuildConfig.WIPE_PUBLIC_KEY_B64.isNotBlank()) scheduleWipePolling()

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            private var startedCount = 0
            private val mainHandler = Handler(Looper.getMainLooper())
            private val lockRunnable = Runnable {
                if (startedCount <= 0 && !Session.suppressLock) {
                    if (Session.unlocked) {
                        Session.lock()
                        audit.log("LOCK_BACKGROUND")
                    }
                }
            }

            override fun onActivityStarted(activity: Activity) {
                startedCount++
                mainHandler.removeCallbacks(lockRunnable)
            }

            override fun onActivityStopped(activity: Activity) {
                val isChangingConfig = activity.isChangingConfigurations
                startedCount--
                if (startedCount <= 0 && !isChangingConfig && !Session.suppressLock) {
                    mainHandler.removeCallbacks(lockRunnable)
                    mainHandler.postDelayed(lockRunnable, 1000L)
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun scheduleWipePolling() {
        val req = PeriodicWorkRequestBuilder<WipeWorker>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(this)
            .enqueueUniquePeriodicWork("wipe-poll", ExistingPeriodicWorkPolicy.KEEP, req)
    }
}

val Context.app: SecureVaultApp get() = applicationContext as SecureVaultApp
