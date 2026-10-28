package com.securevault.ui

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.view.MotionEvent
import android.view.WindowManager
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securevault.BuildConfig
import com.securevault.app
import com.securevault.security.Session
import com.securevault.vault.SecureSharer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Module 7: runtime protection shared by every screen.
 *  - FLAG_SECURE: no screenshots, screen recording or recents thumbnail
 *  - filterTouchesWhenObscured: touches are dropped when another window overlays the app (tap-jacking)
 *  - auto-lock when the app leaves the foreground, and after [IDLE_MS] without touches
 *  - re-authentication when the Keystore key's 30 s window has expired (see [authed])
 */
abstract class BaseSecureActivity : AppCompatActivity() {
    /** False for Setup and Unlock, which must be reachable while locked. */
    protected open val requiresUnlock: Boolean = true

    private val handler = Handler(Looper.getMainLooper())
    private val idleLock = Runnable { lockNow("IDLE") }
    private val onSessionLocked: () -> Unit = { handler.post { goToUnlock() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        if (!BuildConfig.DEBUG) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        super.onCreate(savedInstanceState)
    }

    override fun onStart() {
        super.onStart()
        if (requiresUnlock) {
            if (!Session.unlocked) {
                goToUnlock()
                return
            }
            Session.addLockListener(onSessionLocked)
        }
    }

    override fun onResume() {
        super.onResume()
        resetIdleTimer()
    }

    override fun onStop() {
        if (requiresUnlock) {
            Session.removeLockListener(onSessionLocked)
        }
        handler.removeCallbacks(idleLock)
        super.onStop()
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        resetIdleTimer()
        return super.dispatchTouchEvent(ev)
    }

    private fun resetIdleTimer() {
        handler.removeCallbacks(idleLock)
        if (requiresUnlock) handler.postDelayed(idleLock, IDLE_MS)
    }

    protected fun lockNow(reason: String) {
        if (Session.unlocked) {
            Session.removeLockListener(onSessionLocked) // we navigate ourselves below
            Session.lock()
            app.audit.log("LOCK_$reason")
            SecureSharer.purgeAll(this)
        }
        if (reason == "IDLE" || reason == "MANUAL") goToUnlock()
    }

    protected fun goToUnlock() {
        startActivity(
            Intent(this, UnlockActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }

    protected fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    /**
     * Runs [block] (blocking vault work) on a background thread and delivers the result on the main thread.
     * If the Keystore key's 30 s use window has expired, asks the user to authenticate and retries.
     */
    protected fun <T> authed(block: () -> T, onOk: (T) -> Unit) {
        lifecycleScope.launch {
            try {
                onOk(withContext(Dispatchers.IO) { block() })
            } catch (e: CancellationException) {
                throw e
            } catch (e: UserNotAuthenticatedException) {
                Authenticator.prompt(
                    this@BaseSecureActivity, "Confirm it's you",
                    onSuccess = { authed(block, onOk) },
                    onError = { toast(it) },
                )
            } catch (e: KeyPermanentlyInvalidatedException) {
                showKeyInvalidated()
            } catch (e: SecurityException) {
                toast(e.message ?: "Not allowed")
            } catch (e: Exception) {
                toast("Operation failed: ${e.javaClass.simpleName}")
            }
        }
    }

    private fun showKeyInvalidated() {
        AlertDialog.Builder(this)
            .setTitle("Vault key invalidated")
            .setMessage("Biometric enrolment changed, so the vault key was permanently invalidated. The stored data can no longer be decrypted. Reset the vault to start over.")
            .setCancelable(false)
            .setPositiveButton("Reset vault") { _, _ -> wipeAndRestart("KEY_INVALIDATED") }
            .show()
    }

    protected fun wipeAndRestart(reason: String) {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) { app.wipeManager.wipe(reason) }
            startActivity(
                Intent(this@BaseSecureActivity, SetupActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
            )
            finish()
        }
    }

    companion object {
        const val IDLE_MS = 60_000L
    }
}
