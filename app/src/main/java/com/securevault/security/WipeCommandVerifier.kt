package com.securevault.security

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** A signed remote-wipe command: `WIPE|<epochMillis>|<nonce>`. The timestamp must strictly increase (replay guard). */
class WipeCommand(val timestamp: Long, val nonce: String) {
    companion object {
        fun parse(payload: String): WipeCommand? {
            val p = payload.split("|")
            if (p.size != 3 || p[0] != "WIPE") return null
            val ts = p[1].toLongOrNull() ?: return null
            if (p[2].isBlank()) return null
            return WipeCommand(ts, p[2])
        }
    }
}

/** Module 8: verifies the ECDSA (P-256, SHA-256, DER) signature on a wipe command. */
class WipeCommandVerifier(private val publicKey: PublicKey) {
    fun verify(payload: String, signatureB64: String): Boolean = try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(payload.toByteArray(Charsets.UTF_8))
            verify(Base64.getDecoder().decode(signatureB64))
        }
    } catch (_: Exception) {
        false
    }

    companion object {
        /** Returns null for a blank or malformed key, which disables remote wipe. */
        fun keyFromBase64(b64: String): PublicKey? = try {
            if (b64.isBlank()) null
            else KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(b64)))
        } catch (_: Exception) {
            null
        }
    }
}
