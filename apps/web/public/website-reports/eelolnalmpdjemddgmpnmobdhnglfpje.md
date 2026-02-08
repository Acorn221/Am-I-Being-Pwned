# Security Analysis Report

## Extension Metadata
- **Name**: YouTube Transcript & Summary Generator with ChatGPT & Gemini
- **Extension ID**: eelolnalmpdjemddgmpnmobdhnglfpje
- **User Count**: ~60,000 users
- **Version**: 1.1.0.0
- **Manifest Version**: 3
- **Author**: extension@notegpt.io

## Executive Summary

This extension is a legitimate YouTube transcript and AI-powered summary tool by NoteGPT/VideoTranscriber. The extension fetches YouTube transcripts and provides AI-powered summaries and chat functionality. While the core functionality appears legitimate, there are **moderate privacy concerns** related to data collection and third-party API communication patterns.

**Overall Risk Level**: **LOW**

The extension does not exhibit malicious behavior such as credential theft, malware distribution, or ad injection. However, it collects extensive user data and sends it to third-party servers for AI processing, which raises privacy considerations that users should be aware of.

---

## Vulnerability Analysis

### 1. YouTube Transcript Interception (LOW SEVERITY)

**File**: `assets/index.js-fUVzhTSs.js:2283-2291`

**Description**: The extension intercepts YouTube transcript API requests using webRequest API.

**Code Evidence**:
```javascript
chrome.webRequest.onBeforeRequest.addListener(t => {
  const e = t.url;
  e.includes("timedtext") && e.includes("fmt=json3") && !e.includes("f_orm=ng") && chrome.storage.local.set({
    [y.YOUTUBE_TRANSCRIPT_LINK]: e
  })
}, {
  urls: ["*://www.youtube.com/api/timedtext*"],
  types: ["xmlhttprequest"]
});
```

**Verdict**: **LEGITIMATE** - This is core functionality to capture YouTube's transcript URLs for processing. The extension needs this to provide transcript summaries. The data is stored locally and used for the extension's stated purpose.

---

### 2. Extensive Third-Party Data Transmission (MEDIUM SEVERITY)

**Files**: `assets/index.js-fUVzhTSs.js` (multiple functions), `assets/_commonjsHelpers-OLu-LHfR.js`

**Description**: The extension sends extensive data to `videotranscriber.ai` and `notegpt.io` servers, including video transcripts, user notes, and AI chat conversations.

**API Endpoints Identified**:
- `https://videotranscriber.ai/api/v2/video-transcript` - Fetch/store transcripts
- `https://videotranscriber.ai/api/v1/transcriptions/start` - Start transcription
- `https://videotranscriber.ai/api/v1/transcriptions` - Get transcription status
- `https://videotranscriber.ai/api/v2/plan-quota` - Check user quota
- `https://videotranscriber.ai/api/v2/notes/add-video` - Add video notes
- `https://videotranscriber.ai/api/v2/notes/add-video-notes` - Add user notes
- `https://videotranscriber.ai/api/v2/notes/ai-chat` - AI chat interactions
- `https://videotranscriber.ai/api/v2/notes/ai-chat/batch` - Batch chat
- `https://videotranscriber.ai/api/v2/share-link` - Create share links
- `https://videotranscriber.ai/api/v2/notes/delete-note` - Delete notes
- `https://videotranscriber.ai/api/v1/transcriptions/export` - Export transcriptions
- `https://notegpt.io/api/v2/user/prompt` - User prompts (CRUD)
- `https://notegpt.io/api/v2/user/prompts` - List prompts
- `https://notegpt.io/api/v2/add-quota-record` - Usage tracking
- `https://notegpt.io/api/v2/add-quota-content-v2` - Content quota tracking
- `https://videotranscriber.ai/user/platform-communication/sync-user-status` - User sync

**Code Evidence** (function `sr` for video transcript):
```javascript
async function sr(t) {
  var r;
  const n = (await chrome.storage.local.get(y.X_TOKEN))[y.X_TOKEN];
  return w({
    url: N + "/api/v2/video-transcript",
    method: "get",
    headers: {
      "X-Token": n
    },
    params: {
      platform: "youtube",
      video_id: t.videoId
    },
    signal: (r = t.controller) == null ? void 0 : r.signal
  })
}
```

**Verdict**: **PRIVACY CONCERN** - While this data transmission is necessary for the extension's AI features (transcript summaries, AI chat), users should be aware that:
- All YouTube video transcripts they view are sent to third-party servers
- AI chat conversations are transmitted and stored externally
- User notes and annotations are synced to external servers
- Usage is tracked via quota APIs

This is disclosed functionality but represents significant data exposure to third parties.

---

### 3. Authentication Token Storage (LOW SEVERITY)

**File**: `assets/_commonjsHelpers-OLu-LHfR.js:14`

**Description**: The extension stores authentication tokens in `chrome.storage.local` under the key `x_token`.

**Code Evidence**:
```javascript
c = {
  APP_LANG: "app_lang",
  NOTE_LANG: "note_lang",
  REMEMBER_USER: "remember_user",
  USER_INFO: "user_info",
  X_TOKEN: "x_token",
  ANONYMOUS_USER_ID: "anonymous_user_id",
  YOUTUBE_TRANSCRIPT_LINK: "youtube_transcript_link",
  // ...
}
```

All API requests use this token:
```javascript
const n = (await chrome.storage.local.get(y.X_TOKEN))[y.X_TOKEN];
return w({
  url: N + "/api/v2/video-transcript",
  method: "get",
  headers: {
    "X-Token": n
  },
  // ...
})
```

**Verdict**: **ACCEPTABLE** - Using chrome.storage.local for auth tokens is standard practice for extensions. The storage is isolated per-extension and reasonably secure. No evidence of token exfiltration or misuse.

---

### 4. User Behavior Tracking (LOW SEVERITY)

**File**: `assets/index.js-fUVzhTSs.js`

**Description**: The extension tracks user quotas, usage patterns, and platform communication sync.

**Code Evidence**:
```javascript
async function Pr(t) {
  const n = (await chrome.storage.local.get(y.X_TOKEN))[y.X_TOKEN];
  return w({
    url: we + "/api/v2/add-quota-record",
    method: "post",
    headers: {
      "X-Token": n
    },
    data: t
  })
}

async function cr(t) {
  const e = or(N + "/user/platform-communication/sync-user-status", {
      token: t
    }),
    n = await chrome.storage.local.get(y.X_TOKEN),
    r = await fetch(e, {
      headers: {
        "X-Token": n[y.X_TOKEN]
      },
      method: "GET"
    });
  if (!r.ok) throw new Error(`HTTP error! status: ${r.status}`);
  return await r.json()
}
```

**Verdict**: **EXPECTED BEHAVIOR** - Usage tracking is typical for freemium services with quota limits. The extension needs to track usage to enforce plan limits. No evidence of excessive or hidden tracking.

---

### 5. Login Flow and User Data (LOW SEVERITY)

**File**: `assets/index.js-fUVzhTSs.js:1852-1866`

**Description**: The extension handles user login and forwards authentication to backend services.

**Code Evidence**:
```javascript
async function lr(t) {
  const n = await fetch(N + "/api/v1/login-forwarding", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    mode: "cors",
    body: JSON.stringify(t),
    redirect: "follow"
  });
  if (!n.ok) throw new Error(`HTTP error! status: ${n.status}`);
  const o = n.headers.get("X-Token");
  return {
    ...await n.json(),
    token: o
  }
}
```

Login URL from constants:
```javascript
i = "https://notegpt.io/extension/login/?ext_id=baecjmoceaobpnffgnlkloccenkoibbb"
```

**Verdict**: **LEGITIMATE** - Standard OAuth-style login flow. Credentials are sent via HTTPS to the vendor's servers. No evidence of credential harvesting or man-in-the-middle attacks.

---

### 6. Install/Update Behavior (LOW SEVERITY)

**File**: `assets/index.js-fUVzhTSs.js:2209-2214`

**Description**: Extension opens YouTube video on installation.

**Code Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(async t => {
  if (console.log("VideoTranscriber onInstalled"), t.reason === "install") {
    chrome.tabs.create({
      active: !0,
      url: "https://www.youtube.com/watch?v=o_XVt5rdpFY"
    });
  }
})
```

**Verdict**: **BENIGN** - Opening a specific YouTube video on install is likely a tutorial or demo. This is a minor UX choice but not malicious. The video ID `o_XVt5rdpFY` could be a product demo.

---

## False Positives

| Pattern | File | Reason |
|---------|------|--------|
| `innerHTML` usage | `vendor/webcomponents-custom-elements.js` | Web Components polyfill - standard library code for custom elements |
| `document.cookie` | `assets/index.js-fUVzhTSs.js:934-942` | Axios library cookie utilities for XSRF protection (standard security feature) |
| `eval`/`Function()` | Multiple vendor files | Found 135 instances, all in bundled libraries (Vue, Element Plus, JSZip, XML parser) - not dynamically executed |
| `postMessage` | `assets/index.js-fUVzhTSs.js:241` | Axios async scheduling mechanism - internal use only, not cross-frame communication |
| `addEventListener("message")` | `assets/index.js-fUVzhTSs.js:235` | Part of Axios setImmediate polyfill - controlled internal messaging |
| Navigator/User-Agent access | `assets/index.js-fUVzhTSs.js` | Axios library checking browser capabilities - standard HTTP client behavior |

---

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/api/v2/video-transcript` | GET | Fetch YouTube transcript | Video ID, platform |
| `/api/v1/transcriptions/start` | POST | Start AI transcription | Transcript data, video metadata |
| `/api/v1/transcriptions` | GET | Get transcription status | Record ID |
| `/api/v2/plan-quota` | GET | Check user quota | Auth token |
| `/api/v2/notes/add-video` | POST | Save video to notes | Video data |
| `/api/v2/notes/add-video-notes` | POST | Add user notes | Note content, video ID |
| `/api/v2/notes/ai-chat` | GET/POST/PUT | AI chat interactions | Messages, context |
| `/api/v2/notes/ai-chat/batch` | POST | Batch chat requests | Multiple messages |
| `/api/v2/share-link` | POST | Create share link | Note/video ID |
| `/api/v2/notes/delete-note` | DELETE | Delete note | Note ID |
| `/api/v1/transcriptions/export` | POST | Export transcript | Transcript ID, format |
| `/api/v2/user/prompt` | GET/POST/PUT/DELETE | Manage user prompts | Custom prompt text |
| `/api/v2/add-quota-record` | POST | Track usage | Usage metrics |
| `/api/v2/add-quota-content-v2` | POST | Track content quota | Content metrics |
| `/user/platform-communication/sync-user-status` | GET | Sync user status | Auth token |
| `/api/v1/login-forwarding` | POST | User login | Credentials |

---

## Data Flow Summary

### Data Collection
1. **YouTube Transcripts**: Intercepted via `webRequest` API from YouTube's timedtext API
2. **User Notes**: Created by user interactions with the extension UI
3. **AI Chat Messages**: User queries and AI responses
4. **Video Metadata**: YouTube video IDs, titles, timestamps
5. **Usage Metrics**: Quota usage, feature interactions

### Data Storage
- **Local Storage**: Auth tokens (`x_token`), user preferences, cached transcripts
- **Remote Storage**: All transcripts, notes, chat history synced to `videotranscriber.ai`/`notegpt.io`

### Data Transmission
- **All API calls use HTTPS** - encrypted in transit
- **Authentication via X-Token header** - requests are authenticated
- **Axios HTTP client** - reputable library, standard configuration
- **No third-party analytics** - no evidence of Google Analytics, Mixpanel, or similar

### Third-Party Dependencies
- **Axios** - HTTP client library (legitimate)
- **Vue 3** - UI framework (legitimate)
- **Element Plus** - Vue component library (legitimate)
- **CryptoJS** - Encryption utilities (legitimate)
- **JSZip** - Zip file handling for exports (legitimate)
- **Web Components polyfills** - Browser compatibility (legitimate)

---

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "storage",
  "webRequest",
  "http://dev.notegpt.io/*",
  "https://dev.videotranscriber.ai/*",
  "http://dev.videotranscriber.ai/*"
]
```

### Host Permissions
```json
"host_permissions": [
  "https://*.youtube.com/*",
  "https://*.openai.com/*",
  "https://notegpt.io/*",
  "http://dev.notegpt.io/*",
  "https://dev.videotranscriber.ai/*",
  "http://dev.videotranscriber.ai/*"
]
```

### Analysis
- **`storage`**: Required for auth tokens and preferences - appropriate
- **`webRequest`**: Required to intercept YouTube transcript requests - necessary for core functionality
- **YouTube host permissions**: Required to inject UI and capture transcripts - appropriate
- **OpenAI host permissions**: Potentially for future ChatGPT integration - not currently used in analyzed code
- **NoteGPT/VideoTranscriber hosts**: Required for backend API communication - appropriate
- **Dev domains**: Development/staging environments - acceptable but should be removed in production

### CSP Analysis
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'; frame-src https://notegpt.io/;"
}
```
- Restrictive CSP prevents inline scripts and external script loading
- Allows framing notegpt.io (likely for OAuth/login flows)
- **Good security posture**

---

## Suspicious Patterns - NONE FOUND

❌ **No credential harvesting**
❌ **No keylogging**
❌ **No ad injection**
❌ **No coupon hijacking**
❌ **No extension fingerprinting**
❌ **No clipboard hijacking**
❌ **No cryptocurrency mining**
❌ **No residential proxy infrastructure**
❌ **No obfuscated malicious payloads**
❌ **No remote code execution**
❌ **No market intelligence SDKs** (Sensor Tower, Pathmatics, etc.)
❌ **No AI conversation scraping** (beyond stated functionality)
❌ **No cookie theft**
❌ **No XHR/fetch hooking** (except Axios internals)

---

## Privacy Considerations

While not vulnerabilities, users should be aware:

1. **All YouTube transcripts are sent to third-party servers** for AI processing
2. **AI chat conversations are stored remotely** on vendor servers
3. **User notes are synced externally** for cross-device access
4. **Usage is tracked** for quota enforcement
5. **No evidence of E2E encryption** - vendor can access all user data
6. **Data retention policy unknown** - unclear how long data is stored

---

## Recommendations

### For Users
- Be aware that transcript and chat data is sent to third-party servers
- Review NoteGPT/VideoTranscriber privacy policy before extensive use
- Consider data sensitivity before using for confidential/proprietary videos
- Extension is safe for general YouTube transcript summarization

### For Developers
- Remove dev domain permissions from production builds
- Implement E2E encryption for sensitive user data
- Add clear privacy disclosures in extension description
- Consider data minimization - only send necessary data to backend
- Add user controls for data retention/deletion

---

## Overall Risk Assessment

**Risk Level**: **LOW**

### Justification
- Extension performs its stated functionality (YouTube transcript summaries with AI)
- No evidence of malicious behavior, credential theft, or hidden functionality
- All network communication is with legitimate vendor domains over HTTPS
- Uses standard libraries and frameworks (Vue, Axios, Element Plus)
- Reasonable permission set for stated functionality
- Privacy concerns are related to legitimate feature requirements, not malicious intent

### Risk Breakdown
- **Malware Risk**: ✅ CLEAN
- **Data Theft Risk**: ✅ CLEAN
- **Privacy Risk**: ⚠️ MEDIUM (extensive data collection for AI features)
- **Ad Fraud Risk**: ✅ CLEAN
- **Supply Chain Risk**: ✅ CLEAN (uses reputable libraries)

---

## Conclusion

This extension is a **legitimate productivity tool** for YouTube transcript summarization with AI-powered features. It does not exhibit malicious behavior patterns such as credential theft, ad injection, or data exfiltration beyond its stated purpose.

The primary concern is **privacy**: the extension collects and transmits significant amounts of user data (transcripts, notes, AI chats) to third-party servers operated by NoteGPT/VideoTranscriber. This is necessary for the AI features to function but represents a privacy trade-off users should understand.

**Recommended for general use** with awareness of data sharing implications.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Analysis Depth**: Comprehensive (manifest, background scripts, content scripts, API patterns, permissions)
