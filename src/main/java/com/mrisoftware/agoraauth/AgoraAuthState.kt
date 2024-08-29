package com.mrisoftware.agoraauth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class AgoraAuthState (
     val source_redirect_url: String,
     val authorize_url: String,
     var other: Map<String, JsonElement> = emptyMap()
)