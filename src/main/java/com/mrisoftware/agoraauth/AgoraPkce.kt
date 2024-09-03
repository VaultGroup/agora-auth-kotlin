/*
 * Copyright (c) 2024.
 */

package com.mrisoftware.agoraauth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom


object AgoraPkce {

     // Define valid characters as per the PKCE specification
     private const val validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

     // Function to generate a random code verifier of a specified length
     fun generateCodeVerifier(length: Int = 64): String {
          val secureRandom = SecureRandom()
          val verifier = StringBuilder(length)

          repeat(length) {
               val index = secureRandom.nextInt(validChars.length)
               verifier.append(validChars[index])
          }

          return verifier.toString()
     }

     // Function to generate a code challenge using SHA-256
     fun generateCodeChallenge(codeVerifier: String): String {
          val bytes = codeVerifier.toByteArray(Charsets.US_ASCII)
          val messageDigest = MessageDigest.getInstance("SHA-256")
          val digest = messageDigest.digest(bytes)

          // Encode using Base64 URL-safe encoding without padding
          return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
     }


}