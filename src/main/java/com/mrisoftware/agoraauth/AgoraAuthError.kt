/*
 * Copyright (c) 2024.
 */

package com.mrisoftware.agoraauth


// Define a custom exception class extending Exception
class AgoraAuthError(override val message: String) : Exception(message)