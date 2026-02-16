# Vulnerability Analysis Report

## Extension Metadata
- **Name**: Instant Multilingual PDF/HTML/TXT Translator
- **Extension ID**: fcbnhmalionocfajdkpnlhmekghnmbii
- **Version**: 4.8.1
- **User Count**: ~40,000
- **Manifest Version**: 3

## Executive Summary

This extension provides translation services using Microsoft Translator, Google Translate, and ChatGPT APIs. The extension operates as intended with **no critical malicious behavior detected**. However, it uses embedded API keys for third-party services and integrates ChatGPT functionality including authentication token handling. The extension requires broad permissions (`<all_urls>`, content scripts on all pages) which are necessary for its legitimate translation functionality. While the permission model is invasive, it serves the documented purpose and no data exfiltration or malicious activity was found.

**Overall Risk: CLEAN**

The extension is feature-rich and invasive by design, but serves its intended translation purpose without malicious behavior.

## Vulnerability Details

### 1. Embedded Third-Party API Keys
**Severity**: LOW
**File**: `PHT/background.js`
**Code**:
```javascript
// Line 208: Microsoft API keys (12 rotating keys)
this.m = "f122028fc68f468cb0f247f0224c5bd9 d689236971d547d1af7290eba5f31909 cd1000838f1f447fbac42c39a0a6bb03 ddea3270e79c4e2eb6f800053b516807 c45bd509cca34d78bd660740705bdd9f e88478dcd27a41aaa27cba21fd77c150 a1bf90476b444ce39f101a0fd79995d6 6627d5ca631e489aa06ee77066248e58 a31df1f51942432fbed27783ea6cd3aa 88d0ea0917564aa6a802732207b5723c fb7b7cbcc8cc440abcb3caaa1a8ab79c 3dc6c5b5f4e64cb8ba18e7d44dff6caf".split(" ");

// Line 262: Google API key
return `https://${"translate-pa"}.googleapis.com/${"v1"}/${a}?key=${"AIzaSyDLEeFI5OtFBwYBIoK_jj5m32rZK5CkCXA"}&${b}`

// Line 1162-1163: Dictionary API keys
let eb = new B("content-dictionaryextension-pa", "v1/dictionaryExtensionData", "AIzaSyA6EEtrDCfBkHV8uU2lgGY-N383ZgAOo7Y", "mgijmajocgfcbeboacabfgobmjgjcoja")
```

**Verdict**: While embedding API keys in client-side code is poor practice (keys can be extracted and abused by third parties), this is common in free translation extensions. The developer uses key rotation for Microsoft APIs to manage quota. No user data is sent to developer-controlled servers - all requests go directly to official translation APIs.

### 2. ChatGPT Integration with Authentication
**Severity**: MEDIUM
**File**: `PHT/background.js` (lines 646-910)
**Code**:
```javascript
// Session token retrieval
async function Ia() {
  const a = await fetch("https://chatgpt.com/api/auth/session");
  if (a.status === 403) throw Error(F.g);
  return (await a.json())?.accessToken
}

// Proof-of-work generation (lines 806-823)
async function Ka(a, b, c) {
  return async function(d, f, e) {
    const g = performance.now();
    for (let h = 0; h < 5E5; h++) {  // CPU-intensive computation
      e[3] = h;
      e[9] = Math.round(performance.now() - g);
      var k = JSON.stringify(e);
      k = btoa(String.fromCharCode(...(new TextEncoder).encode(k)));
      if (sha3_512(d + k).slice(0, f.length) <= f) return k
    }
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4De"
  }(b, c, [navigator.hardwareConcurrency + a.l?.w || 1920 + a.l?.h || 1080, (new Date).toString(), a.l?.hsl || 4294705152, 0, navigator.userAgent, "", "", navigator.language, navigator.languages.join(","), 0])
}
```

**Verdict**: The extension can use ChatGPT for translations if the user is logged into ChatGPT. It retrieves session tokens and generates proof-of-work challenges (anti-bot measures). While this could be concerning, it:
- Only activates if user selects ChatGPT as translation API
- Requires user to be logged into ChatGPT already
- Does not steal credentials or send data to third-party servers
- Uses standard ChatGPT API authentication flows

This is **legitimate functionality** for ChatGPT integration, not credential theft.

### 3. Arkose CAPTCHA Handling via Offscreen Document
**Severity**: LOW
**File**: `PHT/offscreen/offscreen.js`, `PHT/offscreen/api.min.js`
**Code**:
```javascript
// Offscreen document for Arkose challenge solving
chrome.offscreen.createDocument({
  url: "PHT/offscreen/offscreen.html",
  reasons: [chrome.offscreen.Reason.IFRAME_SCRIPTING],
  justification: "generating token using offscreen script"
})

// api.min.js contains Arkose Labs CAPTCHA solver (2683 lines)
// Lines 2388-2526 reference https://chat.openai.com and https://tcr9i.chat.openai.com
```

**Verdict**: The extension uses an offscreen document to solve Arkose CAPTCHA challenges when accessing ChatGPT API. This is a **standard anti-bot bypass** for automated API access. While Arkose Labs might consider this a ToS violation, it's not malicious from a user security perspective. The extension loads a minified Arkose solver library.

### 4. Broad Permissions
**Severity**: MEDIUM
**File**: `manifest.json`
**Permissions**:
```json
"host_permissions": ["<all_urls>"],
"permissions": [
  "activeTab",
  "contextMenus",
  "fontSettings",
  "notifications",
  "offscreen",
  "scripting",
  "storage",
  "webNavigation"
],
"content_scripts": [{
  "all_frames": true,
  "matches": ["<all_urls>"],
  "match_about_blank": true,
  "match_origin_as_fallback": true
}]
```

**Verdict**: The extension requires `<all_urls>` and injects content scripts on every page (including iframes and about:blank). These permissions are **necessary for translation functionality** - the extension needs to:
- Access text selection on any webpage
- Display translation tooltips/popups
- Handle PDF translation
- Support iframe content translation

**No evidence of data collection or exfiltration** was found. All content script code focuses on text selection, UI rendering (qTip tooltips), and translation display.

## False Positives

| Finding | Reason | Actual Behavior |
|---------|--------|-----------------|
| ChatGPT token handling | Could be credential theft | Legitimate ChatGPT API integration - only retrieves session tokens for users already logged in, uses standard OpenAI authentication |
| Proof-of-work computation | CPU mining / cryptojacking | Anti-bot challenge for ChatGPT API access (Cloudflare-style PoW) |
| Offscreen document with IFRAME_SCRIPTING | Suspicious hidden iframe | Required for Arkose CAPTCHA solving in isolated context |
| `<all_urls>` host permissions | Overly broad access | Necessary for translation on any website |
| Embedded API keys | Security vulnerability | Standard practice for free translation extensions - keys for official APIs (Microsoft/Google) |
| postMessage to iframe | XSS risk | PDF text selection communication (line 1 of webar.js) |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `api.cognitive.microsofttranslator.com` | Microsoft Translator API | Text to translate, language codes | LOW - Official API |
| `www.bing.com/translator` | Bing token generation | None (scraping for auth tokens) | LOW - Official service |
| `translate-pa.googleapis.com` | Google Translate API | Text to translate, language codes | LOW - Official API |
| `chatgpt.com/api/auth/session` | ChatGPT session token | None (reads existing session) | LOW - User already logged in |
| `chatgpt.com/backend-api/conversation` | ChatGPT translation | Translation prompt | LOW - Official API |
| `content-dictionaryextension-pa.googleapis.com` | Google Dictionary API | Word lookups | LOW - Official API |
| `api.dictionaryapi.dev` | Free Dictionary API | Word lookups | LOW - Public API |

## Data Flow Summary

1. **User Selection**: User selects text on webpage or uses context menu
2. **Local Processing**: Content script captures selection and sends to background script
3. **Translation Request**: Background script sends text to selected translation API:
   - **Microsoft**: Uses rotating embedded API keys, sends text + language pair
   - **Google**: Uses embedded API key, sends text + language pair
   - **ChatGPT**: If user logged in, retrieves session token, generates PoW, sends translation prompt
4. **Response Handling**: Translation returned to content script
5. **Display**: qTip tooltip displayed on page with translation

**No data sent to developer-controlled servers.** All API calls go directly to official translation services (Microsoft, Google, OpenAI).

**Storage**: Only stores user preferences (translation API choice, language preferences, UI settings) in `chrome.storage.sync`.

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification

This extension requires extensive permissions and has invasive functionality (content scripts on all pages, ChatGPT integration), but it operates **exactly as advertised**:

1. **No Malicious Behavior**: No data exfiltration, no credential theft, no hidden network requests
2. **Legitimate Functionality**: All code serves the documented translation purpose
3. **Standard APIs**: Uses official Microsoft, Google, and OpenAI translation services
4. **No Third-Party Servers**: All requests go directly to official APIs, not developer infrastructure
5. **Transparent Operation**: User controls which translation service to use via options

### Why CLEAN vs. MEDIUM:

While the extension:
- Has broad permissions (`<all_urls>`)
- Handles ChatGPT authentication tokens
- Uses embedded API keys
- Includes Arkose CAPTCHA bypass

**All of these serve the legitimate, documented purpose** of providing translation services. The extension does not abuse its permissions for data collection, tracking, or other malicious purposes. The invasive permission model is **necessary and appropriate** for a translation tool that must work on any webpage.

The ChatGPT integration is opt-in (user selects it as translation provider) and only works if the user is already logged into ChatGPT - the extension does not steal credentials or access ChatGPT without user intent.

### Recommendations for Users

- **Safe to use** for translation purposes
- Be aware that ChatGPT option will use your existing ChatGPT session
- Embedded API keys mean others could extract and abuse them (quota exhaustion), but this doesn't affect user security
- Extension has access to all webpage content (needed for translation) - standard for this type of tool

### Developer Best Practices Violations (Non-Security)

- Embedding API keys in client-side code (can be extracted and abused by third parties)
- Using Arkose CAPTCHA bypass may violate OpenAI ToS
- Minified third-party libraries (api.min.js) make auditing difficult

These are **not security vulnerabilities** affecting users, but developer practices that could lead to service disruption if API providers detect and block the keys.
