package com.securevault.security

enum class PlayVerdict { PASS, FAIL, UNAVAILABLE, SKIPPED }

/** [signatureValid] is null when no expected certificate hash is configured (check skipped). */
data class IntegritySignals(
    val rooted: Boolean,
    val debuggerAttached: Boolean,
    val signatureValid: Boolean?,
    val play: PlayVerdict,
)

enum class Decision { OPEN, READ_ONLY, LOCKED }

/**
 * Module 6 response policy (report 7.1, step 4).
 *  - clean            -> OPEN
 *  - doubtful         -> READ_ONLY (root/debugger signal, or Play Integrity unreachable)
 *  - failed           -> LOCKED   (signature mismatch, or Play Integrity verdict failed)
 *
 * Root/debugger/unavailable signals are weak (a determined attacker can hide them) so they only downgrade;
 * hard failures always lock. With [enforce] = false (debug builds) weak signals are shown but ignored,
 * so the prototype runs on emulators.
 */
object ResponsePolicy {
    fun decide(s: IntegritySignals, enforce: Boolean): Decision {
        if (s.signatureValid == false || s.play == PlayVerdict.FAIL) return Decision.LOCKED
        val doubtful = s.rooted || s.debuggerAttached || s.play == PlayVerdict.UNAVAILABLE
        return if (doubtful && enforce) Decision.READ_ONLY else Decision.OPEN
    }
}
