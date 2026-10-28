package com.securevault.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.securevault.BuildConfig
import com.securevault.R
import com.securevault.app
import com.securevault.security.PinHasher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays

/** Module 1, first launch: create the PIN and the Keystore master key. */
class SetupActivity : BaseSecureActivity() {
    override val requiresUnlock = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        val pinInput = findViewById<EditText>(R.id.pinInput)
        val confirmInput = findViewById<EditText>(R.id.confirmInput)
        val status = findViewById<TextView>(R.id.statusText)
        val chipDigits = findViewById<TextView>(R.id.chipDigits)
        val chipMatch = findViewById<TextView>(R.id.chipMatch)

        fun updateChips() {
            val p = pinInput.text.toString()
            val c = confirmInput.text.toString()
            val validLen = p.length in 6..12
            chipDigits?.text = if (validLen) "✓ 6–12 Digits" else "• 6–12 Digits"
            chipDigits?.setTextColor(androidx.core.content.ContextCompat.getColor(this, if (validLen) R.color.vault_signal_green else R.color.vault_ink_muted))

            val matches = validLen && p == c
            chipMatch?.text = if (matches) "✓ Digits Match" else "• Digits Match"
            chipMatch?.setTextColor(androidx.core.content.ContextCompat.getColor(this, if (matches) R.color.vault_signal_green else R.color.vault_ink_muted))
        }

        val watcher = object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) = updateChips()
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        }
        pinInput.addTextChangedListener(watcher)
        confirmInput.addTextChangedListener(watcher)
        updateChips()

        findViewById<Button>(R.id.createBtn).setOnClickListener {
            val pin = pinInput.text.toString().toCharArray()
            val confirm = confirmInput.text.toString().toCharArray()
            pinInput.text.clear()
            confirmInput.text.clear()

            when {
                !PinHasher.isValidPin(pin) -> status.text = "PIN must be 6 to 12 digits."
                !pin.contentEquals(confirm) -> status.text = "PINs do not match."
                else -> lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            if (!app.auth.isRegistered()) {
                                app.keystore.deleteKey()
                            }
                            app.keystore.createKeyIfAbsent()
                            app.auth.register(pin)
                        }
                        startActivity(
                            Intent(this@SetupActivity, UnlockActivity::class.java)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                        )
                        finish()
                    } catch (e: Exception) {
                        status.text = "Setup failed: ${e.message ?: e.javaClass.simpleName}"
                    }
                }
            }
            Arrays.fill(confirm, '\u0000')
        }
    }
}
