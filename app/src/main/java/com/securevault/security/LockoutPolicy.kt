package com.securevault.security

/**
 * Module 1 / 8: lockout with increasing delay, then auto-wipe.
 *
 * Failures 1-4: no delay. From the 5th failure the delay doubles each time (30 s, 60 s, 120 s, ...),
 * capped at 15 minutes. At [WIPE_THRESHOLD] consecutive failures the vault is wiped.
 */
object LockoutPolicy {
    const val LOCKOUT_THRESHOLD = 5
    const val WIPE_THRESHOLD = 10
    private const val BASE_DELAY_MS = 30_000L
    private const val MAX_DELAY_MS = 15 * 60_000L

    fun delayMillis(failedAttempts: Int): Long {
        if (failedAttempts < LOCKOUT_THRESHOLD) return 0L
        val shift = (failedAttempts - LOCKOUT_THRESHOLD).coerceAtMost(20)
        return (BASE_DELAY_MS shl shift).coerceAtMost(MAX_DELAY_MS)
    }

    fun shouldWipe(failedAttempts: Int): Boolean = failedAttempts >= WIPE_THRESHOLD
}
