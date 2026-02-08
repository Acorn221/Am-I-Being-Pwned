# Vulnerability Report: Dictation for Gmail

## Extension Metadata
- **Extension ID**: eggdmhdpffgikgakkfojgiledkekfdce
- **Extension Name**: Dictation for Gmail
- **Version**: 1.0.14
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Author**: Greg Sadetsky

## Executive Summary

Dictation for Gmail is a legitimate speech-to-text extension that provides dictation functionality for composing Gmail emails. The extension uses Web Speech API (webkitSpeechRecognition) for voice recognition and sends minimal analytics data to a first-party analytics endpoint. The extension demonstrates **good privacy practices** with limited data collection, appropriate permissions, and no malicious behavior detected.

**Overall Risk Level: CLEAN**

## Vulnerability Analysis

### 1. Analytics Data Collection - LOW SEVERITY

**Location**: `extension.js` lines 5335-5353

**Code**:
```javascript
async fireEvent(e, t = {}) {
  try {
    this.clientId || (this.clientId = await this.getOrCreateClientId()),
    t.session_id || (t.session_id = this._sessionId),
    !t.email_id && this._emailId && (t.email_id = this._emailId),
    await fetch("https://analytics.dictation.tools/collect", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: this.clientId,
        events: [{
          name: e,
          params: t
        }]
      })
    })
  } catch (e) {
    console.error("Failed to send GAnalytics Event", e)
  }
}
```

**Events Tracked**:
- `dictation_started` - When user starts dictation
- `dictation_ended` - When user stops dictation (includes `engagement_time_msec`)
- `language` - When user changes language (includes `langId`)

**Data Sent**:
- `client_id`: Random UUID stored in chrome.storage.sync
- `session_id`: Timestamp when session started
- `email_id`: Gmail draft/thread ID (NOT email addresses or content)
- Event name and parameters (timing, language selection)

**Analysis**:
The extension sends minimal usage analytics to a first-party endpoint (`analytics.dictation.tools`). The `email_id` field is a Gmail internal draft/thread identifier (e.g., from `data-message-id` attribute), NOT user email addresses or message content. This is standard analytics for understanding feature usage.

**Verdict**: ACCEPTABLE - Minimal first-party analytics with no PII collection. The email_id is an internal Gmail identifier, not sensitive user data.

---

### 2. Microphone Access - INFORMATIONAL

**Location**: `extension.js` lines 5303-5315

**Code**:
```javascript
navigator.getUserMedia = navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia,
navigator.mediaDevices.getUserMedia({
  audio: !0
}).then((e => {
  const t = this.audioContext.createMediaStreamSource(e),
    n = new AudioWorkletNode(this.audioContext, "volume-processor");
  // ... volume processing for UI visualization
  t.connect(n).connect(this.audioContext.destination)
}))
```

**Analysis**:
The extension requests microphone access to enable dictation functionality. Audio is processed using:
1. **Web Speech API** (`webkitSpeechRecognition`) - Browser-native speech recognition (line 4922)
2. **Audio Worklet** (`volume-processor.js`) - Only for visualizing microphone volume levels in UI

**Verdict**: EXPECTED - Microphone access is required and appropriate for a dictation extension. No audio is recorded or exfiltrated.

---

### 3. Gmail Integration Library (gmail-js) - INFORMATIONAL

**Location**: `extension.js` lines 2979-4905

**Analysis**:
The extension uses the open-source `gmail-js` library to interact with Gmail's DOM. This library provides:
- Compose window detection
- Draft ID extraction (for analytics session tracking)
- DOM element location for button injection
- No email content access or manipulation beyond the compose window

**Verdict**: ACCEPTABLE - Legitimate use of well-known open-source library for Gmail DOM integration.

---

### 4. Speech Recognition Implementation - INFORMATIONAL

**Location**: `extension.js` lines 4922-4988

**Code**:
```javascript
c = new window.webkitSpeechRecognition,
c.continuous = !0,
c.interimResults = !0,
c.lang = n,
c.onerror = r;

c.onresult = e => {
  // ...
  const r = Array.from(e.results),
  let s = r.map((e => e[0].transcript)).join("");
  // ... text processing and insertion into compose body
}
```

**Analysis**:
Uses browser-native Web Speech API. Transcribed text is:
- Inserted directly into Gmail compose window
- Processed for punctuation commands (e.g., "comma" → ", ")
- Capitalization of sentences
- NO external transmission of transcripts

**Verdict**: CLEAN - All speech processing happens locally in the browser.

---

## Manifest Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "scripting",
  "storage"
],
"host_permissions": [
  "*://mail.google.com/*"
]
```

**Analysis**:
- ✅ **scripting**: Used for re-injecting content scripts on extension update (service_worker.js)
- ✅ **storage**: Used for storing user language preference and analytics client ID
- ✅ **mail.google.com**: Appropriately scoped to Gmail only
- ✅ **No broad permissions**: No cookies, webRequest, tabs, history, or overly broad host permissions

**Verdict**: MINIMAL - Permissions are appropriate and scoped to necessary functionality.

---

## Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self';"
}
```

**Verdict**: SECURE - Prevents inline scripts and remote code execution.

---

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `innerHTML` usage | jQuery library (lines 1432, 1825, 1829, 3032) | Part of bundled jQuery 4.0.0-beta, used with TrustedTypes policy |
| `getAttribute` calls | jQuery & gmail-js library | Standard DOM manipulation for library functionality |
| `XMLHttpRequest` | gmail-js XHR patching (lines 3940-3999) | Library feature for monitoring Gmail's internal API calls (not used for external requests) |
| `fetch` calls | Analytics only (line 5337) | Single first-party analytics endpoint |
| `eval`/`Function()` | None found | ✅ No dynamic code execution |

---

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://analytics.dictation.tools/collect` | Usage analytics | client_id (UUID), session_id (timestamp), email_id (Gmail draft ID), event names, engagement time, language preference | LOW - First-party analytics with minimal data |

**No third-party trackers detected.**

---

## Data Flow Summary

### Data Collection
1. **Microphone Audio** → Processed locally by Web Speech API → Transcribed text inserted into compose window → Never transmitted
2. **Usage Events** → Timestamped events with minimal metadata → Sent to first-party analytics endpoint
3. **User Preferences** → Language setting → Stored in chrome.storage.sync

### Data Storage
- **chrome.storage.sync**:
  - `clientId`: Random UUID for analytics
  - `GMDE_options`: User language preference
- **No localStorage, cookies, or external storage used**

### External Communication
- **Single endpoint**: `analytics.dictation.tools/collect` (first-party)
- **No third-party services, SDKs, or trackers**

---

## Security Strengths

1. ✅ **TrustedTypes policies** implemented for HTML sanitization (lines 2969-2975, 4911-4913)
2. ✅ **No remote code loading** - All scripts are local
3. ✅ **Minimal permissions** - Scoped to Gmail only
4. ✅ **No content exfiltration** - Dictated text stays in Gmail
5. ✅ **Browser-native speech recognition** - No third-party speech services
6. ✅ **Manifest V3** - Modern, secure extension architecture
7. ✅ **Error handling** - Analytics failures are caught and don't break functionality

---

## Recommendations

**For Users:**
- ✅ Safe to use - Extension demonstrates good privacy practices
- Microphone permission required (expected for dictation)
- Minimal analytics collection (can be reviewed in network tab)

**For Developer:**
- Consider adding opt-out for analytics
- Document data collection in privacy policy
- Consider open-sourcing the extension for transparency

---

## Overall Risk Assessment

**Risk Level: CLEAN**

**Rationale:**
- Legitimate dictation functionality using browser-native APIs
- Minimal, first-party analytics with no PII collection
- No malicious behavior, code obfuscation, or suspicious patterns
- Appropriate permissions scoped to necessary functionality
- No third-party trackers or data exfiltration
- Good security practices (TrustedTypes, CSP, MV3)

**Confidence: HIGH** - Complete code review performed across all JavaScript files. Extension behavior matches stated functionality with transparent, minimal data collection.
