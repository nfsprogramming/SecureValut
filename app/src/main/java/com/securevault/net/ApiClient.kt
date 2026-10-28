package com.securevault.net

import com.securevault.BuildConfig
import com.securevault.security.AuditLogger
import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Module 5: TLS 1.2+ only (ConnectionSpec.RESTRICTED_TLS, so cleartext is refused by OkHttp as well as by the
 * Network Security Config), with public-key pinning on top of the platform's pin-set. A failed pin check
 * stops the request and writes PIN_FAILURE to the audit log. All methods block (call from Dispatchers.IO).
 */
class ApiClient(private val audit: AuditLogger) {
    private val client: OkHttpClient = OkHttpClient.Builder()
        .certificatePinner(
            CertificatePinner.Builder()
                .add(BuildConfig.SYNC_HOST, "sha256/${BuildConfig.PIN_PRIMARY}")
                .add(BuildConfig.SYNC_HOST, "sha256/${BuildConfig.PIN_BACKUP}")
                .build(),
        )
        .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    /** Returns the body, or null for HTTP 204. */
    private fun execute(request: Request): String? {
        try {
            client.newCall(request).execute().use { r ->
                if (r.code == 204) return null
                if (!r.isSuccessful) throw IOException("HTTP ${r.code}")
                return r.body?.string()
            }
        } catch (e: SSLPeerUnverifiedException) {
            audit.append("PIN_FAILURE")
            throw e
        }
    }

    private fun get(path: String) = Request.Builder().url(BuildConfig.SYNC_BASE_URL + path).get().build()

    private fun post(path: String, json: String, bearer: String? = null): Request =
        Request.Builder()
            .url(BuildConfig.SYNC_BASE_URL + path)
            .apply { if (bearer != null) header("Authorization", "Bearer $bearer") }
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()

    fun integrityNonce(): String =
        JSONObject(execute(get("/integrity/nonce")) ?: throw IOException("empty")).getString("nonce")

    fun verifyIntegrity(token: String): Boolean {
        val body = execute(post("/integrity/verify", JSONObject().put("token", token).toString())) ?: return false
        return JSONObject(body).optString("verdict") == "PASS"
    }

    /** Returns (payload, signature) or null if no command is pending. */
    fun pollWipeCommand(): Pair<String, String>? {
        val body = execute(get("/wipe-command")) ?: return null
        val o = JSONObject(body)
        return o.getString("payload") to o.getString("signature")
    }

    /** Uploads ciphertext only. */
    fun sync(json: String, bearer: String?) {
        execute(post("/sync", json, bearer))
    }
}
