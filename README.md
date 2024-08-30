# Agora Auth for Android

This package simplifies Agora Authentication for Android projects. This package is dependent
on Android, AndroidX and Kotlin libraries.

## Example

Implement `AgoraAuthDelegate` in your Agora Auth event handler.

```kotlin

    /**
    * Agora auth success handler
    */
    override fun agoraAuthSuccess(code: String, state: Map<String, Any>) {
        // handle successfull login
    }

    /**
    * Agora error message handler
    */
    override fun agoraAuthError(error: String) {
        // handle agora error messages
    }

    /**
    * Respond with a client config.
    */
    override fun agoraAuthClientConfig(result: (AgoraClientConfig?) -> Unit) {
        val config = AgoraClientConfig(
            issuer = this.issuer,
            clientId = this.clientId,
            redirectUri = this.redirectUri
        )
        result(config)
    }

    /**
    * Respond with an `AgoraAuthState` instance. This data class ensures that required auth state arguments are included
    * in authentication requests
    */
    override fun agoraAuthState(clientConfig: AgoraClientConfig, oauthConfig: AgoraOauthConfig, result: (AgoraAuthState) -> Unit) {
        val state = AgoraAuthState(source_redirect_url = clientConfig.redirectUri, authorize_url = oauthConfig.authUrl)
        result(state)
    }

    /**
    * Provide a context `AgoraAuth` can operate within. This context will never be stored but may be requested at any time.
    * If the context is unavailable, `AgoraAuth` may fail silently.
    */
    override fun agoraAuthContext(): Context {
        return context
    }

```

Then call the `AgoraAuth.signIn(:)` method

```kotlin
AgoraAuth.signIn(this)
```