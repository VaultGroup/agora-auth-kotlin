package com.mrisoftware.agoraauth

data class AgoraClientConfig (
     val clientId : String,
     val redirectUri : String,
     val issuer : String,
     val authorityId: String?,
    /// A space delimited list of scopes being requested
     var scope: String = "openid offline_access email profile",
    /// The client secret that can be used to make requests to the IDP. Not all implementations
    /// require this secure key, consider whether you need to expose this secret client side.
     var clientSecret: String? = null,
     var loginHint: String?
) {

     val codeVerifier: String = AgoraPkce.generateCodeVerifier()
     val codeChallenge: String = AgoraPkce.generateCodeChallenge(this.codeVerifier)
}


