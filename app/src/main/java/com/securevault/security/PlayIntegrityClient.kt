package com.securevault.security

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.securevault.BuildConfig
import com.securevault.net.ApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * Module 6, steps 1-2: request an integrity token bound to a fresh server nonce, send it to the server for
 * decryption and checking, and read back the decision. The app never decides from the raw token itself.
 * Skipped while BuildConfig.CLOUD_PROJECT_NUMBER == 0 (no backend configured).
 */
class PlayIntegrityClient(private val context: Context, private val api: ApiClient) {
    suspend fun verdict(): PlayVerdict {
        if (BuildConfig.CLOUD_PROJECT_NUMBER == 0L) return PlayVerdict.SKIPPED
        return try {
            val nonce = withContext(Dispatchers.IO) { api.integrityNonce() }
            val token = IntegrityManagerFactory.create(context)
                .requestIntegrityToken(
                    IntegrityTokenRequest.builder()
                        .setNonce(nonce)
                        .setCloudProjectNumber(BuildConfig.CLOUD_PROJECT_NUMBER)
                        .build(),
                )
                .await()
                .token()
            val ok = withContext(Dispatchers.IO) { api.verifyIntegrity(token) }
            if (ok) PlayVerdict.PASS else PlayVerdict.FAIL
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            PlayVerdict.UNAVAILABLE
        }
    }
}
