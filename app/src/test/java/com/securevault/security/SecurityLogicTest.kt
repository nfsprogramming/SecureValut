package com.securevault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** JVM unit tests for the platform-independent security logic (no Android classes needed). */
class SecurityLogicTest {

    // ---- M1: PIN hashing and lockout (F1, F3) ----
    @Test fun pinHash_verifiesAndRejects() {
        val salt = PinHasher.newSalt()
        val h = PinHasher.hash("123456".toCharArray(), salt, 1000)
        assertTrue(PinHasher.verify("123456".toCharArray(), salt, h, 1000))
        assertFalse(PinHasher.verify("123457".toCharArray(), salt, h, 1000))
    }

    @Test fun pinHash_isSalted() {
        val a = PinHasher.hash("123456".toCharArray(), PinHasher.newSalt(), 1000)
        val b = PinHasher.hash("123456".toCharArray(), PinHasher.newSalt(), 1000)
        assertFalse(a.contentEquals(b))
    }

    @Test fun pinValidation() {
        assertTrue(PinHasher.isValidPin("123456".toCharArray()))
        assertFalse(PinHasher.isValidPin("12345".toCharArray()))
        assertFalse(PinHasher.isValidPin("12345a".toCharArray()))
        assertFalse(PinHasher.isValidPin("1234567890123".toCharArray()))
    }

    @Test fun lockoutDelaysIncrease() {
        assertEquals(0L, LockoutPolicy.delayMillis(4))
        assertEquals(30_000L, LockoutPolicy.delayMillis(5))
        assertEquals(60_000L, LockoutPolicy.delayMillis(6))
        assertEquals(480_000L, LockoutPolicy.delayMillis(9))
        assertEquals(15 * 60_000L, LockoutPolicy.delayMillis(100))
        assertFalse(LockoutPolicy.shouldWipe(9))
        assertTrue(LockoutPolicy.shouldWipe(10))
    }

    // ---- M3: access control ----
    @Test fun accessControl() {
        assertFalse(AccessController.isAllowed(false, Role.OWNER, Action.READ))
        assertTrue(AccessController.isAllowed(true, Role.VIEW_ONLY, Action.READ))
        assertFalse(AccessController.isAllowed(true, Role.VIEW_ONLY, Action.WRITE))
        assertTrue(AccessController.isAllowed(true, Role.OWNER, Action.WRITE))
    }

    // ---- M6: response policy (F8, S9, S10) ----
    @Test fun responsePolicy() {
        val clean = IntegritySignals(false, false, true, PlayVerdict.PASS)
        assertEquals(Decision.OPEN, ResponsePolicy.decide(clean, true))
        assertEquals(Decision.READ_ONLY, ResponsePolicy.decide(clean.copy(rooted = true), true))
        assertEquals(Decision.READ_ONLY, ResponsePolicy.decide(clean.copy(debuggerAttached = true), true))
        assertEquals(Decision.OPEN, ResponsePolicy.decide(clean.copy(rooted = true), false)) // debug build
        assertEquals(Decision.LOCKED, ResponsePolicy.decide(clean.copy(signatureValid = false), true))
        assertEquals(Decision.LOCKED, ResponsePolicy.decide(clean.copy(play = PlayVerdict.FAIL), false))
        assertEquals(Decision.OPEN, ResponsePolicy.decide(clean.copy(signatureValid = null, play = PlayVerdict.SKIPPED), true))
    }

    // ---- M8: audit hash chain (S12) ----
    private val mac: (ByteArray) -> ByteArray = {
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(ByteArray(32) { 7 }, "HmacSHA256")) }.doFinal(it)
    }

    private fun chain(vararg types: String): MutableList<AuditChain.Link> {
        val out = mutableListOf<AuditChain.Link>()
        var prev = AuditChain.GENESIS
        types.forEachIndexed { i, t ->
            val h = AuditChain.compute(mac, prev, t, 1000L + i)
            out += AuditChain.Link(t, 1000L + i, prev, h)
            prev = h
        }
        return out
    }

    @Test fun auditChain_intact() = assertEquals(-1, AuditChain.firstBreak(chain("A", "B", "C"), mac))

    @Test fun auditChain_deletedMiddleEntryDetected() {
        val c = chain("A", "B", "C", "D")
        c.removeAt(1)
        assertEquals(1, AuditChain.firstBreak(c, mac))
    }

    @Test fun auditChain_deletedFirstEntryDetected() {
        val c = chain("A", "B", "C")
        c.removeAt(0)
        assertEquals(0, AuditChain.firstBreak(c, mac))
    }

    @Test fun auditChain_editedEntryDetected() {
        val c = chain("A", "B", "C")
        val b = c[1]
        c[1] = AuditChain.Link("EVIL", b.timestamp, b.prevHash, b.hash)
        assertEquals(1, AuditChain.firstBreak(c, mac))
    }

    @Test fun auditChain_wrongKeyCannotForge() {
        val c = chain("A", "B")
        val otherMac: (ByteArray) -> ByteArray = {
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(ByteArray(32) { 9 }, "HmacSHA256")) }.doFinal(it)
        }
        assertEquals(0, AuditChain.firstBreak(c, otherMac))
    }

    // ---- M8: signed wipe command (F10) ----
    @Test fun wipeCommand_verifyAndReject() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val payload = "WIPE|1700000000000|abc123"
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private); update(payload.toByteArray()); Base64.getEncoder().encodeToString(sign())
        }
        val v = WipeCommandVerifier(kp.public)
        assertTrue(v.verify(payload, sig))
        assertFalse(v.verify("WIPE|1700000000001|abc123", sig)) // tampered payload
        assertFalse(v.verify(payload, "not-base64!!"))

        val b64 = Base64.getEncoder().encodeToString(kp.public.encoded)
        assertNotNull(WipeCommandVerifier.keyFromBase64(b64))
        assertNull(WipeCommandVerifier.keyFromBase64(""))
    }

    @Test fun wipeCommand_parse() {
        assertEquals(5L, WipeCommand.parse("WIPE|5|n")?.timestamp)
        assertNull(WipeCommand.parse("DELETE|5|n"))
        assertNull(WipeCommand.parse("WIPE|x|n"))
        assertNull(WipeCommand.parse("WIPE|5"))
    }
}
