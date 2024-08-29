package com.mrisoftware.agoraauth

import android.net.Uri
import android.net.UrlQuerySanitizer
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedReader
import java.lang.ref.WeakReference
import java.net.HttpURLConnection
import java.net.URL
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
                AgoraAuth.delegate?.agoraAuthError("Missing client config")
                return@a
            }

            // Store the client config
            AgoraAuth.clientConfig = clientConfig

            // Fetch the open ID config
            fetchOpenidConfiguration(clientConfig) b@{ oauthConfig ->
                if (oauthConfig == null) {
                    AgoraAuth.delegate?.agoraAuthError("Missing Oauth config")
                    return@b
                }

                // Store the oauth config
                AgoraAuth.oauthConfig = oauthConfig

                // Get users auth state and make the auth code request
                AgoraAuth.delegate?.agoraAuthState(clientConfig, oauthConfig) { authState ->
                    requestAuthCode(clientConfig, oauthConfig, authState)
                }
            }
        }
    }

    // Requires a valid OAuth config, and that it contains a user info URL
    private fun fetchOpenidConfiguration(config: AgoraClientConfig, result: (AgoraOauthConfig?) -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val url = URL(config.issuer + "/.well-known/openid-configuration")
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "GET"
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode !in 200..299) {
                    connection.disconnect()
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError("Server request failed with code $responseCode")
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
                        delegate?.agoraAuthError("JSON parse error")
                        result(null)
                    }
                    return@launch
                }

                val issuer = json["issuer"]?.jsonPrimitive?.content
                val authUrl = json["authorization_endpoint"]?.jsonPrimitive?.content
                val tokenUrl = json["token_endpoint"]?.jsonPrimitive?.content
                val userInfoUrl = json["userinfo_endpoint"]?.jsonPrimitive?.content

                if (listOf(issuer, authUrl, tokenUrl, userInfoUrl).contains(null)) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError("Missing required oauth config properties")
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
                    delegate?.agoraAuthError("Request error ${e.localizedMessage}")
                    result(null)
                }
            }
        }
    }

    @Suppress("NAME_SHADOWING")
    private fun requestAuthCode(clientConfig: AgoraClientConfig, oauthConfig: AgoraOauthConfig, authState: AgoraAuthState) {
        val context = delegate?.agoraAuthContext() ?: run {
            delegate?.agoraAuthError("Context has gone away")
            return@requestAuthCode
        }

        val stateJson = Json.encodeToString(authState)
        val state64 = Base64.encodeToString(stateJson.toByteArray(Charsets.UTF_8), Base64.DEFAULT).trimIndent()

        val builder = Uri.parse(oauthConfig.authUrl).buildUpon()
        builder.appendQueryParameter("nonce", UUID.randomUUID().toString())
        builder.appendQueryParameter("response_type", "code")
        builder.appendQueryParameter("response_mode", "query")
        builder.appendQueryParameter("\$interstitial_email_federation", "true")
        builder.appendQueryParameter("state", state64)
        builder.appendQueryParameter("scope", clientConfig.scope)
        builder.appendQueryParameter("redirect_uri", clientConfig.redirectUri)
        builder.appendQueryParameter("client_id", clientConfig.clientId)

        val intent = AgoraAuthWebViewActivity.newInstance(context, builder.build().toString())
        context.startActivity(intent)
    }

    internal fun handleRedirect(redirectUri: Uri): Boolean {
        val clientRedirectUriString = clientConfig?.redirectUri ?: return false
        val clientRedirectUri = Uri.parse(clientRedirectUriString)

        // Not our redirect
        if (redirectUri.scheme != clientRedirectUri.scheme) {
            return false
        }

        val sani = UrlQuerySanitizer(redirectUri.toString())
        sani.allowUnregisteredParamaters = true
        sani.parseQuery(redirectUri.query)

        // Call the delegate and short circuit if theres an error
        val error: String? = sani.getValue("error")
        if (error != null) {
            val errorDescription: String? = sani.getValue("error_description")
            if (errorDescription != null) {
                delegate?.agoraAuthError("$error $errorDescription")
            } else {
                delegate?.agoraAuthError("$error")
            }
            return true
        }

        val code: String? = sani.getValue("code")
        if (code == null) {
            delegate?.agoraAuthError("auth code not found in redirect url")
            return true
        }

        val state64: String? = sani.getValue("state")
        if (state64 == null) {
            delegate?.agoraAuthError("auth code not found in redirect url")
            return true
        }

        val state64Bytes = Base64.decode(state64, Base64.NO_WRAP)
        val stateJson = String(state64Bytes, Charsets.UTF_8)
        val state = Json.decodeFromString<Map<String, JsonElement>>(stateJson)
        delegate?.agoraAuthSuccess(code, state)

        return true
    }

    /** Exchange an auth code for a scoped access token that can be used for future requests */
    fun exchangeAuthCode(code: String, result: (String?) -> Unit) {
        val clientConfig = this.clientConfig ?: run {
            delegate?.agoraAuthError("Missing client config")
            return@exchangeAuthCode
        }

        val oauthConfig = this.oauthConfig ?: run {
            delegate?.agoraAuthError("Missing oauth config")
            return@exchangeAuthCode
        }

        val clientSecret = clientConfig.clientSecret ?: run {
            delegate?.agoraAuthError("Unknown client secret, cannot exchange auth code")
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
                        delegate?.agoraAuthError("Server request failed with code $responseCode")
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
                        delegate?.agoraAuthError("JSON parse error")
                        result(null)
                    }
                    return@launch
                }

                val accessToken = json["access_token"]?.jsonPrimitive?.content
                if (accessToken == null) {
                    withContext(Dispatchers.Main) {
                        delegate?.agoraAuthError("Access token not found")
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
                    delegate?.agoraAuthError("Request error ${e.localizedMessage}")
                    result(null)
                }
            }
        }
    }

    /** Exchange an auth code for a scoped access token that can be used for future requests */
    fun fetchUserInfo(accessToken: String, result: (Map<String, JsonElement>?) -> Unit) {
        val oauthConfig = this.oauthConfig ?: run {
            delegate?.agoraAuthError("Missing oauth config")
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
                        delegate?.agoraAuthError("Server request failed with code $responseCode")
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
                        delegate?.agoraAuthError("JSON parse error")
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
                    delegate?.agoraAuthError("Request error ${e.localizedMessage}")
                    result(null)
                }
            }
        }
    }
}