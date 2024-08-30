package com.mrisoftware.agoraauth

import android.content.Context


interface AgoraAuthDelegate {
    fun agoraAuthSuccess(code: String, state: Map<String, Any>)
    fun agoraAuthError(error: String)

    /** Asks the delegate to return a client config */
    fun agoraAuthClientConfig(result: (AgoraClientConfig?) -> Unit)

    /**
     * You can return any values in the handler and it will be included in the `state` argument of the oauth request. For Agora Authentication,
     * you must include `source_redirect_url` and `authorize_url`
     */
    fun agoraAuthState(clientConfig: AgoraClientConfig, oauthConfig: AgoraOauthConfig, result: (AgoraAuthState) -> Unit)

    /**
     * The context will never be stored but may be requested at any time
     */
    fun agoraAuthContext(): Context?
}