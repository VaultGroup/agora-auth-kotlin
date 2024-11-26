package com.mrisoftware.agoraauth

import android.content.Intent
import android.net.Uri
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.json.JSONObject
import java.io.BufferedReader
import java.io.Serializable
import java.lang.ref.WeakReference
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder
import java.util.UUID


object AgoraAuth {
    private var _delegate: WeakReference<AgoraAuthDelegate>? = null
    private val delegate: AgoraAuthDelegate? get() = _delegate?.get()

    private var clientConfig: AgoraClientConfig? = null
    private var oauthConfig: AgoraOauthConfig? = null

    /// Begin the sign in flow. AgoraAuth will ask the delegate for the required information before opening a
    /// web view for the user to sign in.
    fun signIn(delegate: AgoraAuthDelegate) {
        this._delegate = WeakReference(delegate)

        // Ask the delegate for the client config
        delegate.agoraAuthClientConfig a@{ clientConfig ->
            if (clientConfig == null) {
                AgoraAuth.delegate?.agoraAuthError(AgoraAuthError("Missing client config"))
                return@a
            }

            // Store the client config
            AgoraAuth.clientConfig = clientConfig

            // Fetch the open ID config
            fetchOpenidConfiguration(clientConfig) b@{ oauthConfig ->
                if (oauthConfig == null) {
                    AgoraAuth.delegate?.agoraAuthError(AgoraAuthError("Missing Oauth config"))
                    return@b
                }

                // Store the oauth config
                AgoraAuth.oauthConfig = oauthConfig

                // Get users auth state and make the auth code request
                AgoraAuth.delegate?.agoraAuthState(clientConfig, oauthConfig) { authState ->
                    requestAuthCode(clientConfig, oauthConfig, authState as Map<String, Any?>)
                }
            }
        }
    }

    // Requires a valid OAuth config, and that it contains a user info URL
    private fun fetchOpenidConfiguration(config: AgoraClientConfig, result: (AgoraOauthConfig?) -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL(config.issuer + "/" + (config.authorityId ?: "default") + "/.well-known/openid-configuration")
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "GET"
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode !in 200..299) {
                    connection.disconnect()
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("Server request failed with code $responseCode"))
                        result(null)
                    }
                    return@launch
                }

                val data = connection.inputStream.bufferedReader().use(BufferedReader::readText)
                connection.disconnect()

                val json = try {
                    Json.decodeFromString<Map<String, JsonElement>>(data)
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("JSON parse error"))
                        result(null)
                    }
                    return@launch
                }

                val issuer = json["issuer"]?.jsonPrimitive?.content
                val userInfoUrl = json["userinfo_endpoint"]?.jsonPrimitive?.content
                val authUrl = json["authorization_endpoint"]?.jsonPrimitive?.content
                val tokenUrl = json["token_endpoint"]?.jsonPrimitive?.content

                if (listOf(issuer, authUrl, tokenUrl, userInfoUrl).contains(null)) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("Missing required oauth config properties"))
                        result(null)
                    }
                    return@launch
                }

                val oauthConfig = AgoraOauthConfig(
                    issuer!!, authUrl!!,  tokenUrl!!, userInfoUrl!!)

                // SUCCESS: Call the result callback with the JSON data
                withContext(Dispatchers.Main) {
                    result(oauthConfig)
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    delegate?.agoraAuthError(AgoraAuthError("Request error ${e.localizedMessage}"))
                    result(null)
                }
            }
        }
    }

    @Suppress("NAME_SHADOWING")
    private fun requestAuthCode(clientConfig: AgoraClientConfig, oauthConfig: AgoraOauthConfig, authState: Map<String, Any?>) {
        val context = delegate?.agoraAuthContext() ?: run {
            delegate?.agoraAuthError(AgoraAuthError("Context has gone away"))
            return@requestAuthCode
        }

        val authState = authState.toMutableMap()
        if (!authState.keys.contains("source_redirect_url")) {
            authState.put("source_redirect_url", clientConfig.redirectUri)
        }

        val stateJson = JSONObject(authState).toString()

        val builder = Uri.parse(oauthConfig.authUrl).buildUpon()
        builder.appendQueryParameter("nonce", UUID.randomUUID().toString())
        builder.appendQueryParameter("response_type", "code")
        builder.appendQueryParameter("response_mode", "query")
        builder.appendQueryParameter("state", stateJson)
        builder.appendQueryParameter("scope", clientConfig.scope)
        builder.appendQueryParameter("client_id", clientConfig.clientId)
        builder.appendQueryParameter("code_challenge", clientConfig.codeChallenge)
        builder.appendQueryParameter("code_challenge_method", "S256")
        builder.appendQueryParameter("login_hint", clientConfig.loginHint ?: "")
        builder.appendQueryParameter("\$interstitial_email_federation", "true")

        // ==
        // Even though these are included in the query string of the oauth config authorization endpoint,
        // we must provide them again. Why? I do not know. But the user will be prompted to enter a client
        // ID without them.
        builder.appendQueryParameter("\$interstitial_prompt_mri_client_id", "true")
        builder.appendQueryParameter("\$interstitial_tryGetClientIdFromCookie", "true")
        // ==

        val authUrl = builder.build().toString()
        Log.i("AgoraAuth", "Auth URL => $authUrl")
        val intent = AgoraAuthWebViewActivity.newInstance(context, authUrl)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent)
    }

    internal fun canHandleRedirect(redirectUri: Uri): Boolean {
        val clientRedirectUriString = clientConfig?.redirectUri ?: return false
        val clientRedirectUri = Uri.parse(clientRedirectUriString)
        return redirectUri.scheme == clientRedirectUri.scheme
    }

    internal fun handleRedirect(redirectUri: Uri): Boolean {
        val clientConfig = this.clientConfig ?: return false
        val clientRedirectUri = Uri.parse(clientConfig.redirectUri)

        // Not our redirect
        if (redirectUri.scheme != clientRedirectUri.scheme) {
            return false
        }

        // Call the delegate and short circuit if theres an error
        val error: String? = redirectUri.getQueryParameter("error")
        if (error != null) {
            val errorDescription: String? = redirectUri.getQueryParameter("error_description")
            if (errorDescription != null) {
                delegate?.agoraAuthError(AgoraAuthError("$error $errorDescription"))
            } else {
                delegate?.agoraAuthError(AgoraAuthError("$error"))
            }
            return true
        }

        val code: String? = redirectUri.getQueryParameter("code")
        if (code == null) {
            delegate?.agoraAuthError(AgoraAuthError("auth code not found in redirect url"))
            return true
        }

        val stateEncoded: String? = redirectUri.getQueryParameter("state")
        if (stateEncoded == null) {
            delegate?.agoraAuthError(AgoraAuthError("auth code not found in redirect url"))
            return true
        }

        val stateJson = URLDecoder.decode(stateEncoded, "UTF-8")
        val state = Json.decodeFromString<Map<String, JsonElement>>(stateJson)
        delegate?.agoraAuthSuccess(code, clientConfig, state)

        return true
    }

    /** Exchange an auth code for a scoped access token that can be used for future requests */
    fun exchangeAuthCode(code: String, result: (String?) -> Unit) {
        val clientConfig = this.clientConfig ?: run {
            delegate?.agoraAuthError(AgoraAuthError("Missing client config"))
            return@exchangeAuthCode
        }

        val oauthConfig = this.oauthConfig ?: run {
            delegate?.agoraAuthError(AgoraAuthError("Missing oauth config"))
            return@exchangeAuthCode
        }

        val clientSecret = clientConfig.clientSecret ?: run {
            delegate?.agoraAuthError(AgoraAuthError("Unknown client secret, cannot exchange auth code"))
            return@exchangeAuthCode
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val authString = "%s:%s".format(clientConfig.clientId, clientSecret).trimIndent()
                val authBytes = authString.toByteArray(Charsets.UTF_8)
                val auth64 = Base64.encodeToString(authBytes, Base64.NO_WRAP).trimIndent()

                val uri = Uri.parse(oauthConfig.tokenUrl).buildUpon()
                uri.appendQueryParameter("grant_type", "authorization_code")
                uri.appendQueryParameter("code", code)
                uri.appendQueryParameter("redirect_uri", clientConfig.redirectUri)
                uri.appendQueryParameter("code_verifier", clientConfig.codeVerifier)

                val url = URL(uri.build().toString())
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Authorization", "Basic $auth64")
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode !in 200..299) {
                    connection.disconnect()
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("Server request failed with code $responseCode"))
                        result(null)
                    }
                    return@launch
                }

                val data = connection.inputStream.bufferedReader().use(BufferedReader::readText)
                connection.disconnect()

                val json = try {
                    Json.decodeFromString<Map<String, JsonElement>>(data)
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("JSON parse error"))
                        result(null)
                    }
                    return@launch
                }

                val accessToken = json["access_token"]?.jsonPrimitive?.content
                if (accessToken == null) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("Access token not found"))
                        result(null)
                    }
                    return@launch
                }
                
                // SUCCESS: Call the result callback with the JSON data
                withContext(Dispatchers.Main) {
                    result(accessToken)
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    delegate?.agoraAuthError(AgoraAuthError("Request error ${e.localizedMessage}"))
                    result(null)
                }
            }
        }
    }

    /** Exchange an auth code for a scoped access token that can be used for future requests */
    fun fetchUserInfo(accessToken: String, result: (Map<String, JsonElement>?) -> Unit) {
        val oauthConfig = this.oauthConfig ?: run {
            delegate?.agoraAuthError(AgoraAuthError("Missing oauth config"))
            return@fetchUserInfo
        }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL(oauthConfig.userInfoUrl)
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Authorization", "Bearer $accessToken")
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode !in 200..299) {
                    connection.disconnect()
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("Server request failed with code $responseCode"))
                        result(null)
                    }
                    return@launch
                }

                val data = connection.inputStream.bufferedReader().use(BufferedReader::readText)
                connection.disconnect()

                val json = try {
                    Json.decodeFromString<Map<String, JsonElement>>(data)
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError(AgoraAuthError("JSON parse error"))
                        result(null)
                    }
                    return@launch
                }

                // SUCCESS: Call the result callback with the JSON data
                withContext(Dispatchers.Main) {
                    result(json)
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    delegate?.agoraAuthError(AgoraAuthError("Request error ${e.localizedMessage}"))
                    result(null)
                }
            }
        }
    }
}