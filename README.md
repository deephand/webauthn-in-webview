# WebAuthn in Android WebView Demo
A client-side demonstration of WebAuthn (Passkeys) in an Android WebView, focusing on secure integration with a native Android application.

## Key Features
* **Full Flow Simulation:** Demonstrates passkey creation and login, including a detailed simulation of the server-side verification steps (challenge, origin, signature) directly in the client's console log.

* **Native App Integration:** Correctly validates WebAuthn requests originating from a native Android app using the android:apk-key-hash origin, which is enabled via Digital Asset Links.

## Quick Setup Guide
1. **Host Web Content:** Serve the index.html and script.js files over https:// or localhost. WebAuthn requires a secure context.

2. **Configure Android WebView:** In your native Android app's code, enable WebAuthn support for your WebView.

```
// In your Activity or Fragment
WebView myWebView = findViewById(R.id.my_webview);
WebSettings settings = myWebView.getSettings();
WebSettingsCompat.setWebAuthenticationSupport(settings, WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_APP);
```

3. **Link Your App & Website (Digital Asset Links):**

   1. **Get your app's signing fingerprint:**
   Your app must be signed. Use keytool to get its SHA256 fingerprint.

   ```
   keytool -printcert -jarfile path/to/your/app.apk
   ```

   2. **Add the fingerprint to script.js:**
   Open script.js and paste your fingerprint into the ALLOWED_ANDROID_HASHES array so the demo knows which app to trust.

   ```
   const ALLOWED_ANDROID_HASHES = ["YOUR_SHA256_FINGERPRINT_HERE"];
   ```

   3. **Host assetlinks.json:**
   To prove your website trusts your app, create an assetlinks.json file and host it at https://your-domain.com/.well-known/assetlinks.json.

   ```
   [
     {
       "relation": [
         "delegate_permission/common.handle_all_urls",
         "delegate_permission/common.get_login_creds"
       ],
       "target": {
         "namespace": "web",
         "site": "YOUR_WEBSITE_HERE"
       }
     }
     {
       "relation": ["delegate_permission/common.get_login_creds"],
       "target": {
         "namespace": "android_app",
         "package_name": "com.your.app.package_name",
         "sha256_cert_fingerprints": ["YOUR_SHA256_FINGERPRINT_HERE"]
       }
     }
   ]
   ```