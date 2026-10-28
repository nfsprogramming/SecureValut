package com.securevault.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.securevault.BuildConfig
import com.securevault.R
import com.securevault.app
import com.securevault.security.Decision
import com.securevault.security.IntegritySignals
import com.securevault.security.PinResult
import com.securevault.security.ResponsePolicy
import com.securevault.security.Role
import com.securevault.security.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays

/**
 * Launcher. Data flow (report 4.4): integrity check first, then authentication, then the vault opens.
 *  - PIN path: verify PIN (lockout / auto-wipe apply), then the system prompt opens the Keystore key window.
 *  - Biometric path: BiometricPrompt opens the key window directly.
 */
class UnlockActivity : BaseSecureActivity() {
    override val requiresUnlock = false

    private var decision: Decision = Decision.LOCKED
    private lateinit var status: TextView
    private lateinit var pinInput: EditText
    private lateinit var unlockBtn: View
    private lateinit var bioBtn: View
    private val pinBuilder = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_unlock)
        status = findViewById(R.id.statusText)
        pinInput = findViewById(R.id.pinInput)
        unlockBtn = findViewById(R.id.unlockBtn)
        bioBtn = findViewById(R.id.bioBtn)
        setupKeypad()
        setInputsEnabled(false)

        unlockBtn.setOnClickListener { onPinSubmit() }
        bioBtn.setOnClickListener { onBiometric() }

        lifecycleScope.launch {
            try {
                val registered = withContext(Dispatchers.IO) { app.auth.isRegistered() }
                if (!registered) {
                    startActivity(Intent(this@UnlockActivity, SetupActivity::class.java))
                    finish()
                    return@launch
                }
                val signals = withContext(Dispatchers.IO) { app.integrity.evaluate() }
                decision = ResponsePolicy.decide(signals, BuildConfig.ENFORCE_INTEGRITY)
                app.audit.log("INTEGRITY_$decision")
                showIntegrity(signals)
            } catch (_: Exception) {
                decision = Decision.OPEN
                setInputsEnabled(true)
            } finally {
                if (decision != Decision.LOCKED) {
                    setInputsEnabled(true)
                }
            }
        }
    }

    private fun showIntegrity(s: IntegritySignals) {
        val detail = "root=${s.rooted}, debug=${s.debuggerAttached}, sig=${s.signatureValid ?: "n/a"}, play=${s.play}"
        val t = findViewById<TextView>(R.id.integrityText)
        val dot = findViewById<android.view.View>(R.id.integrityDot)
        when (decision) {
            Decision.OPEN -> {
                t.text = "Environment Verified ($detail)"
                dot?.setBackgroundResource(R.drawable.bg_status_dot_green)
                setInputsEnabled(true)
            }
            Decision.READ_ONLY -> {
                t.text = "Untrusted Environment: READ-ONLY ($detail)"
                dot?.setBackgroundResource(R.drawable.bg_status_dot_amber)
                setInputsEnabled(true)
            }
            Decision.LOCKED -> {
                t.text = "Integrity FAILED: Vault Locked ($detail)"
                dot?.setBackgroundResource(R.drawable.bg_status_dot_red)
                setInputsEnabled(false)
            }
        }
    }

    private fun setInputsEnabled(on: Boolean) {
        pinInput.isEnabled = on
        unlockBtn.isEnabled = on
        bioBtn.isEnabled = on
    }

    private fun setupKeypad() {
        val keys = listOf(
            R.id.btnKey0 to "0", R.id.btnKey1 to "1", R.id.btnKey2 to "2",
            R.id.btnKey3 to "3", R.id.btnKey4 to "4", R.id.btnKey5 to "5",
            R.id.btnKey6 to "6", R.id.btnKey7 to "7", R.id.btnKey8 to "8",
            R.id.btnKey9 to "9",
        )
        for ((id, digit) in keys) {
            findViewById<View>(id)?.setOnClickListener {
                if (pinBuilder.length < 12) {
                    pinBuilder.append(digit)
                    updatePinDots()
                }
            }
        }
        findViewById<View>(R.id.btnKeyDel)?.setOnClickListener {
            if (pinBuilder.isNotEmpty()) {
                pinBuilder.deleteCharAt(pinBuilder.length - 1)
                updatePinDots()
            }
        }
        updatePinDots()
    }

    private fun updatePinDots() {
        pinInput.setText(pinBuilder.toString())
        val count = pinBuilder.length
        val dotIds = listOf(
            R.id.pinDot1, R.id.pinDot2, R.id.pinDot3, R.id.pinDot4, R.id.pinDot5, R.id.pinDot6,
            R.id.pinDot7, R.id.pinDot8, R.id.pinDot9, R.id.pinDot10, R.id.pinDot11, R.id.pinDot12,
        )
        val visibleCount = maxOf(6, count)
        dotIds.forEachIndexed { index, id ->
            val dot = findViewById<View>(id) ?: return@forEachIndexed
            if (index < visibleCount) {
                dot.visibility = View.VISIBLE
                dot.setBackgroundResource(
                    if (index < count) R.drawable.bg_pin_dot_filled else R.drawable.bg_pin_dot_empty
                )
            } else {
                dot.visibility = View.GONE
            }
        }

        findViewById<TextView>(R.id.pinPromptText)?.text =
            if (count > 0) "ENTER MASTER PIN ($count / 12 DIGITS)" else "ENTER MASTER PIN (6–12 DIGITS)"

        findViewById<Button>(R.id.unlockBtn)?.text =
            if (count >= 6) "Unlock Vault ($count digits) →" else "Unlock with PIN"
    }

    private fun onPinSubmit() {
        val pin = pinInput.text.toString().toCharArray()
        if (pin.size < 6) {
            status.text = "PIN must be 6 to 12 digits."
            return
        }
        pinBuilder.clear()
        updatePinDots()
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) { app.auth.verifyPin(pin) }
                Arrays.fill(pin, '\u0000')
                when (result) {
                    PinResult.Success -> enter()
                    PinResult.NotRegistered -> startActivity(Intent(this@UnlockActivity, SetupActivity::class.java))
                    is PinResult.Wrong -> status.text =
                        if (result.delayMillis > 0) "Wrong PIN. Locked for ${result.delayMillis / 1000} s."
                        else "Wrong PIN (attempt ${result.failedAttempts})."
                    is PinResult.LockedOut -> {
                        val secs = ((result.untilMillis - System.currentTimeMillis()) / 1000).coerceAtLeast(1)
                        status.text = "Too many attempts. Try again in $secs s."
                    }
                    PinResult.AutoWipe -> wipeAndRestart("AUTO")
                }
            } catch (e: Exception) {
                status.text = "Unlock failed: ${e.message ?: e.javaClass.simpleName}"
            }
        }
    }

    private fun onBiometric() {
        try {
            Authenticator.prompt(this, "Unlock SecureVault", onSuccess = { enter() }, onError = {
                app.audit.log("BIOMETRIC_ERROR")
                status.text = it
            })
        } catch (e: Exception) {
            status.text = "Biometric unavailable: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    private fun enter() {
        try {
            val role = if (decision == Decision.READ_ONLY && BuildConfig.ENFORCE_INTEGRITY) Role.VIEW_ONLY else Role.OWNER
            Session.unlock(role)
            app.audit.log("UNLOCK_SUCCESS")
            Session.suppressLock = true
            startActivity(Intent(this, VaultActivity::class.java))
            finish()
        } catch (e: Exception) {
            status.text = "Error opening vault: ${e.message ?: e.javaClass.simpleName}"
        }
    }
}
