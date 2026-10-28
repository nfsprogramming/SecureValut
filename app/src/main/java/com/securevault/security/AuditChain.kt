package com.securevault.security

/**
 * Module 8: tamper-evident hash chain. Pure logic so it can be unit-tested on the JVM.
 *
 * hash(n) = HMAC(key, prev_hash | event_type | timestamp). Because the HMAC key lives in the Keystore,
 * an attacker who edits the database cannot recompute a valid chain.
 *
 * Known limit: removing the newest entries (truncation) leaves a valid chain; periodically anchoring
 * the latest hash on the server would close that gap.
 */
object AuditChain {
    const val GENESIS = "GENESIS"

    class Link(val type: String, val timestamp: Long, val prevHash: String, val hash: String)

    fun compute(mac: (ByteArray) -> ByteArray, prevHash: String, type: String, timestamp: Long): String =
        mac("$prevHash|$type|$timestamp".toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    /** Index of the first broken link, or -1 if the whole chain is intact. */
    fun firstBreak(links: List<Link>, mac: (ByteArray) -> ByteArray): Int {
        var expectedPrev = GENESIS
        links.forEachIndexed { i, l ->
            if (l.prevHash != expectedPrev) return i
            if (compute(mac, l.prevHash, l.type, l.timestamp) != l.hash) return i
            expectedPrev = l.hash
        }
        return -1
    }
}
