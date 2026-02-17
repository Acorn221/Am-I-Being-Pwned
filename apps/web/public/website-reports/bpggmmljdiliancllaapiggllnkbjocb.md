# Vulnerability Report: Ddict: AI Translation & Writing Assistant

## Metadata
- **Extension ID**: bpggmmljdiliancllaapiggllnkbjocb
- **Extension Name**: Ddict: AI Translation & Writing Assistant
- **Version**: 6.2.19
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Ddict is a legitimate AI-powered translation and writing assistant extension that integrates with Google Translate and provides additional features through its own backend API (api.ddict.me). The extension implements standard functionality for a translation tool, including text selection translation, AI-powered explanations, word saving, and text-to-speech capabilities. The extension uses proper authentication flows with token refresh mechanisms and communicates with disclosed endpoints for legitimate purposes.

The static analyzer flagged two "exfiltration" flows to www.w3.org, but these are false positives related to Vue.js framework code in the content script - there is no actual network communication to W3C domains. All actual network requests go to expected translation services and the extension's own backend.

## Vulnerability Details

### 1. LOW: Remote Configuration and Dynamic Behavior
**Severity**: LOW
**Files**: background.js, assets/api-D2qCrf-w.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension retrieves configuration and user data from a remote API (api.ddict.me) including authentication tokens, saved words, and flashcard statistics. While this is expected behavior for a cloud-synced translation tool, it does create a dependency on the remote service.

**Evidence**:
```javascript
// API endpoints defined in api-D2qCrf-w.js
const x = b.create({
  baseURL: U.URL_API,  // "https://api.ddict.me"
  withCredentials: !0
});

// Authentication refresh mechanism
async function Gn() {
  ge = !0;
  try {
    await x.post("/auth/refresh"), Ke()
  } catch (e) {
    throw Ke(e), e
  } finally {
    ge = !1
  }
}

// API calls for translation saving, AI features
async function tr(e) {
  const n = await x.post("/ai/translate", {
    src: e.src,
    target: e.target,
    text: t
  });
}
```

**Verdict**: This is standard behavior for a translation service that offers cloud sync and AI features. The extension properly handles authentication errors and redirects users to sign-in pages when needed. The remote configuration is disclosed through the extension's functionality (account features, saved words, premium AI features).

## False Positives Analysis

The static analyzer reported two "exfiltration" flows involving www.w3.org:
- `document.querySelectorAll → fetch(www.w3.org)` in content/content.js
- `document.getElementById → fetch(www.w3.org)` in content/content.js

**Analysis**: These are false positives. After examining the deobfuscated code:
1. The content script contains Vue.js framework code (6,420 lines)
2. The only actual `fetch` call found fetches audio data for text-to-speech playback (line 4826): `const b = await (await fetch(n.value)).arrayBuffer()`
3. This fetch uses a dynamic URL stored in `n.value` which is set from the background script's TTS API response
4. The TTS URL comes from Google Translate's TTS endpoint, not www.w3.org
5. No actual network requests to W3C or www.w3.org domains exist in the code

The static analyzer likely flagged Vue.js DOM manipulation patterns as potential data flows, but these don't represent actual exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.ddict.me | Backend API for user accounts, word saving, AI features | User authentication tokens, selected text for translation/AI processing, saved words | LOW - Disclosed functionality |
| app.ddict.me | Web application for account management | N/A (redirect only) | MINIMAL |
| learn.ddict.me | Flashcard learning feature | N/A (redirect only) | MINIMAL |
| translate.google.com | Google Translate API | Text to translate, language codes | MINIMAL - Public API |
| translate.googleapis.com | Google Translate API (alternative endpoint) | Text to translate, language codes | MINIMAL - Public API |

## Network Request Modifications

The extension uses declarativeNetRequest to modify headers for Google Translate requests:
```json
{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [{
      "header": "user-agent",
      "operation": "set",
      "value": "GoogleTranslate/ddict.me"
    }]
  },
  "condition": {
    "urlFilter": "translate.google.com/translate_",
    "resourceTypes": ["xmlhttprequest", "media"]
  }
}
```

This sets a custom User-Agent header for Google Translate API requests, likely for service identification purposes. This is a standard practice and poses no security risk.

## Privacy Considerations

**Data Collection**:
- Selected text for translation (disclosed - core functionality)
- User authentication and session tokens
- Saved vocabulary words (optional feature)
- Flashcard statistics (optional feature)
- Text sent to AI features (optional premium features)

**User Control**: Users can choose whether to sign in and use cloud features. Translation works without an account using only Google Translate.

**Data Storage**: Extension uses chrome.storage.sync for settings and last word (max 6KB), which syncs across user's devices.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate translation extension with appropriate permissions and disclosed functionality. The extension:
- Only requests host permissions for its own domains and Google Translate
- Uses proper MV3 patterns (service worker, declarativeNetRequest)
- Implements standard authentication with token refresh
- Has no hidden data collection or malicious behavior
- The static analyzer's "exfiltration" findings are false positives from Vue.js framework code

The single LOW-severity issue relates to the inherent dependency on remote services (api.ddict.me), which is expected and disclosed for a cloud-synced translation tool with AI features. Users who want offline-only usage can avoid signing in and use only the Google Translate integration.

**Recommendation**: Safe for general use. Users concerned about sending text to third-party services should be aware that text is sent to both Google Translate (for translation) and api.ddict.me (if using AI features).
