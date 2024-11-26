package com.mrisoftware.agoraauth

import android.content.Context


interface AgoraAuthDelegate {
    /** The auth flow completed successfully */
    fun agoraAuthSuccess(code: String, config: AgoraClientConfig, state: Map<String, Any>)

    /** The auth flow completed with an error */
    fun agoraAuthError(error: AgoraAuthError)

    /** Asks the delegate to return a client config */
    fun agoraAuthClientConfig(result: (AgoraClientConfig?) -> Unit)

    /**
     * You can return any values in the handler and it will be included in the `state` argument of the oauth request. For Agora Authentication,
     * you can optionally include `source_redirect_url` and `authorize_url` and they will override any default values this library assigns.
     * The default value for `source_redirect_url` will be `AgoraClientConfig.redirectUri`. Note that the sign in web view redirects will
     * only be intercepted for schemes matching `AgoraClientConfig.redirectUri`.
     */
    fun agoraAuthState(clientConfig: AgoraClientConfig, oauthConfig: AgoraOauthConfig, result: (Map<String, Any?>) -> Unit)

    /**
     * The context will never be stored but may be requested at any time
     */
    fun agoraAuthContext(): Context?
}