package com.mrisoftware.agoraauth

data class AgoraOauthConfig(
    val issuer: String,
    val authUrl: String,
    val tokenUrl: String,
    val userInfoUrl: String,
)