package com.securevault.security

import com.securevault.data.UserDao
import com.securevault.data.UserEntity

sealed class PinResult {
    object Success : PinResult()
    object NotRegistered : PinResult()
    data class Wrong(val failedAttempts: Int, val delayMillis: Long) : PinResult()
    data class LockedOut(val untilMillis: Long) : PinResult()

    /** Consecutive-failure limit reached; the caller must run the wipe path. */
    object AutoWipe : PinResult()
}

/** Module 1: PIN registration and verification, with persisted lockout state. All calls block (use IO). */
class AuthManager(private val users: UserDao, private val audit: AuditLogger) {

    fun isRegistered(): Boolean = users.get() != null

    fun register(pin: CharArray) {
        require(PinHasher.isValidPin(pin)) { "PIN must be 6 to 12 digits" }
        val salt = PinHasher.newSalt()
        users.upsert(UserEntity(pinSalt = salt, pinHash = PinHasher.hash(pin, salt)))
        audit.append("REGISTERED")
    }

    fun verifyPin(pin: CharArray, now: Long = System.currentTimeMillis()): PinResult {
        val user = users.get() ?: return PinResult.NotRegistered
        if (now < user.lockedUntil) return PinResult.LockedOut(user.lockedUntil)

        if (PinHasher.verify(pin, user.pinSalt, user.pinHash)) {
            users.setAttempts(0, 0L)
            audit.append("PIN_OK")
            return PinResult.Success
        }

        val failed = user.failedAttempts + 1
        audit.append("PIN_FAILURE")
        if (LockoutPolicy.shouldWipe(failed)) return PinResult.AutoWipe

        val delay = LockoutPolicy.delayMillis(failed)
        users.setAttempts(failed, if (delay > 0) now + delay else 0L)
        if (delay > 0) audit.append("LOCKOUT")
        return PinResult.Wrong(failed, delay)
    }
}
