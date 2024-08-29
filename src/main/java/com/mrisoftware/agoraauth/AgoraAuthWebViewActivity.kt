package com.mrisoftware.agoraauth

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar

class AgoraAuthWebViewActivity: AppCompatActivity() {
    companion object {
        private const val AUTH_URL = "AUTH_URL"
        fun newInstance(context: Context, authUrl: String): Intent {
            return Intent(context, AgoraAuthWebViewActivity::class.java).apply {
                putExtra(AUTH_URL, authUrl)
            }
        }
    }

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize the WebView
        webView = WebView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
            webViewClient = CustomWebViewClient()
            settings.javaScriptEnabled = true
        }

        val toolbar = Toolbar(this).apply {
            title = "Authorization"
            setNavigationIcon(android.R.drawable.ic_menu_close_clear_cancel)
            setNavigationOnClickListener {
                finish()
            }
        }

        // Create a LinearLayout to hold the WebView and Toolbar
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(toolbar)
            addView(webView)
        }

        setContentView(layout)

        // Load the URL passed to this Activity
        val authUrl = intent.getStringExtra(AUTH_URL) ?: ""
        webView.loadUrl(authUrl)
    }

    // Handle our custom redirect url
    inner class CustomWebViewClient : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            if (AgoraAuth.handleRedirect(request.url)) {
                this@AgoraAuthWebViewActivity.finish()
                return true
            }
            return false
        }
    }
}