# Vulnerability Report: Video Translator - Translate Video & Voice online

## Metadata
- **Extension ID**: ofhkcffhkdhjpnpplihikdpkcpailpnc
- **Extension Name**: Video Translator - Translate Video & Voice online
- **Version**: 4.8.10
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Video Translator is a legitimate extension that provides AI-based video and voice translation services for YouTube and other video platforms. The extension requests `identity` and `identity.email` permissions to authenticate users with Google accounts, which is used to manage subscription status and usage limits on the third-party service livepolls.app. While the extension collects user profile data (email, Google UID) and sends it to remote servers, this behavior is consistent with the extension's stated purpose of providing a subscription-based translation service. The extension does not exhibit malicious behavior, but users should be aware that their Google profile information is shared with the livepolls.app service for authentication and billing purposes.

The static analyzer flagged several exfiltration flows involving chrome.storage.sync data and tab information being sent to remote endpoints. Upon manual review, these flows are legitimate: user preferences (language, voice settings) are synced with the backend service, and tab information is only collected when users explicitly request video translation. The extension uses standard OAuth-style authentication patterns with passport tokens.

## Vulnerability Details

### 1. LOW: User Profile Data Collection and Third-Party Sharing
**Severity**: LOW
**Files**: assets/background.js-D_eCqAr1.js (lines 388-398, 478-489)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects Google user profile information (email, user ID) via the `chrome.identity.getProfileUserInfo()` API and transmits this data to the third-party service at livepolls.app. The extension creates a "passport" token based on the user's Google UID and uses it for subsequent API authentication.

**Evidence**:
```javascript
function p() {
  return new Promise(async (e, t) => {
    let n = await chrome.storage.sync.get(["g_user_info"]);
    n.g_user_info ? e(n.g_user_info) : chrome.identity.getProfileUserInfo({
      accountStatus: "ANY"
    }, o => {
      console.log("userInfo", o), e(o), chrome.storage.sync.set({
        g_user_info: o
      })
    })
  })
}

function f(e) {
  return A({
    url: "https://www.livepolls.app/video_translator/api/user/passport",
    data: {
      google_uid: e
    },
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  })
}
```

The extension also sends user status updates to livepolls.app:
```javascript
const n = await A({
  url: "https://www.livepolls.app/video_translator/api/user/status",
  method: "POST",
  headers: e,
  data: {
    app_type: t ? "edge_addon" : "chrome_addon",
    uuid: g
  }
});
```

**Verdict**: While this data collection is disclosed through the `identity.email` permission, users should be aware that their Google profile data is being shared with a third-party service (livepolls.app). This is standard for subscription-based services but represents a privacy consideration. The extension properly requests the necessary permissions and the data flow is consistent with providing authentication for a paid service.

## False Positives Analysis

The static analyzer identified several patterns that initially appear suspicious but are legitimate for this extension type:

1. **chrome.storage.sync.get → fetch()**: The extension syncs user preferences (voice settings, target language, subscription status) with the backend service. This is expected behavior for a cloud-based translation service that needs to maintain user settings across devices.

2. **chrome.tabs.query → fetch()**: This flow only occurs when users explicitly click the translation button in the popup. The extension queries the active tab to get the current YouTube video URL and sends it to the translation service. This is the core functionality of the extension.

3. **navigator.userAgent → fetch()**: The extension includes browser type (Chrome vs Edge) in API requests to differentiate between Chrome Web Store and Edge Add-ons installations. This is used for analytics and uninstall URL tracking, which is standard practice.

4. **Obfuscation flag**: The static analyzer flagged the code as obfuscated. However, this is webpack-bundled Vue.js code (Logger-CTEDOe59.js contains Element Plus UI library), not malicious obfuscation. The deobfuscation process successfully produced readable code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.imgkits.com/site/get | Retrieve remote configuration | Key (storage key) | Low - standard KV storage |
| www.imgkits.com/site/save | Save remote configuration | JSON data (user settings) | Low - user preferences only |
| ai.imgkits.com/tts | Text-to-speech API | Text, voice, language, JWT token | Low - legitimate TTS service |
| ai.imgkits.com/api/generate-presigned-url | S3-style upload URL generation | File metadata | Low - video upload for translation |
| ai.imgkits.com/upload/* | Multipart video upload | Video chunks | Low - core functionality |
| uploadr2byfileurl.409198933.workers.dev | Cloudflare R2 upload helper | Video URL, key | Low - video hosting for translation |
| www.livepolls.app/video_translator/api/user/passport | Authentication | Google UID | Medium - sends user identifier |
| www.livepolls.app/video_translator/api/user/status | User status check | Google UID, browser type | Medium - user tracking |
| www.livepolls.app/video_translator/api/order/download | Usage tracking | Count, passport token | Low - subscription management |
| livepolls.app (uninstall URL) | Uninstall tracking | Browser type | Low - standard analytics |
| word.maiyizhi.cn/api/video/preview | Video metadata extraction | Video URL | Low - preview generation |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This extension is a legitimate video translation service with no evidence of malicious behavior. The key privacy consideration is that it collects and transmits Google user profile information (email, user ID) to the third-party service livepolls.app for authentication and subscription management. This data collection is:

1. **Disclosed**: The extension requests `identity` and `identity.email` permissions, which Chrome surfaces to users during installation.
2. **Purposeful**: The data is used to authenticate users and manage subscriptions for a paid translation service.
3. **Consistent**: The data flows align with the extension's stated purpose of providing AI-powered video translation.

The extension does not:
- Collect browsing history beyond the current YouTube video when translation is requested
- Inject ads or affiliate codes
- Modify page content maliciously
- Exfiltrate data without user action
- Use dynamic code execution (no eval, Function constructor)
- Have weak CSP or insecure message handlers

The "LOW" risk rating reflects the legitimate data collection for a subscription service, rather than any malicious intent. Users who are comfortable sharing their Google profile information with the livepolls.app service for authentication purposes can safely use this extension. Users who prefer not to share their Google identity should avoid installing it.

The only flag category is `remote_config` because the extension fetches user settings from www.imgkits.com/site/get, which is standard for cloud-synced preferences.
