package com.mrisoftware.agoraauth

data class AgoraClientConfig (
     val clientId : String,
     val redirectUri : String,
     val issuer : String,
    /// A space delimited list of scopes being requested
     var scope: String = "openid offline_access device_sso email profile",
    /// The client secret that can be used to make requests to the IDP. Not all implementations
    /// require this secure key, consider whether you need to expose this secret client side.
     var clientSecret: String? = null
)