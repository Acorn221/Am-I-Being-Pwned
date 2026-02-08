# Vulnerability Report: Bluedot AI Notetaker & Meeting Recorder

## Metadata
- **Extension ID**: aeeninnnlhgaojlolnbpljadhbionlal
- **Extension Name**: Bluedot: AI notetaker & Meeting Recorder
- **Version**: 0.1.18
- **User Count**: ~60,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

Bluedot is a legitimate meeting recording and transcription extension with a **CLEAN** security posture. The extension uses appropriate permissions for its functionality (recording meetings, capturing audio/video, generating AI transcriptions). All network communications are restricted to the vendor's domain (bluedothq.com), and the extension implements standard telemetry (Amplitude, Sentry) without suspicious data collection. No malware, obfuscation, or malicious patterns were detected.

**Overall Risk Level**: CLEAN

## Vulnerability Details

### 1. INFORMATIONAL: Broad Host Permissions
**Severity**: INFORMATIONAL
**Files**: `manifest.json`
**Lines**: 31

**Description**:
The extension requests `*://*/*` (all URLs) host permissions, which is broader than necessary for its stated functionality.

**Evidence**:
```json
"host_permissions": ["*://*/*"]
```

**Analysis**:
While broad, this permission is justified for the extension's core functionality:
- Injecting content scripts into Google Meet (`meet.google.com`)
- Injecting content scripts into Microsoft Teams (`teams.microsoft.com`)
- Supporting Zoom meetings
- The extension only actively injects scripts into specific meeting platforms

**Verdict**: **FALSE POSITIVE** - Necessary for multi-platform meeting support. The extension does not abuse this permission for tracking or content manipulation on arbitrary sites.

---

### 2. INFORMATIONAL: Sensitive Permissions Usage
**Severity**: INFORMATIONAL
**Files**: `manifest.json`, `scripts/recorder.js`, `scripts/background.js`
**Lines**: manifest.json:32-39, recorder.js:652-689

**Description**:
The extension uses several sensitive permissions including `desktopCapture`, `tabCapture`, `activeTab`, `scripting`, and `tabs`.

**Evidence**:
```json
"permissions": [
  "activeTab",
  "scripting",
  "storage",
  "tabs",
  "desktopCapture",
  "tabCapture",
  "alarms"
]
```

```javascript
chrome.tabCapture.getMediaStreamId({
  consumerTabId: e
}, function(e) { ... })

chrome.desktopCapture.chooseDesktopMedia(["screen", "window", "tab", "audio"], function(t) { ... })
```

**Analysis**:
These permissions are **core requirements** for a meeting recorder:
- `desktopCapture` / `tabCapture`: Required to capture meeting audio/video
- `tabs`: Required to manage recording tabs and inject UI elements
- `scripting`: Required to inject meeting controls into web pages
- `storage`: Required to store recording metadata, settings, and local recordings
- `alarms`: Used for periodic cleanup tasks

All permissions are used legitimately for their stated purpose.

**Verdict**: **FALSE POSITIVE** - All permissions are necessary and properly used for meeting recording functionality.

---

### 3. INFORMATIONAL: Third-Party Analytics Integration
**Severity**: INFORMATIONAL
**Files**: `scripts/background.js`, `scripts/installed_identifier.js`
**Lines**: background.js:1-12, background.js:1810-2100

**Description**:
The extension integrates Sentry (error tracking) and Amplitude (analytics) for telemetry.

**Evidence**:
```javascript
// Sentry integration
SENTRY_RELEASE = { id: "0.1.18" }
_sentryDebugIds = { ... }

// Amplitude analytics
var x = "https://api2.amplitude.com/2/httpapi"
api_key: this.config.apiKey,
serverUrl: "https://api.eu.amplitude.com/2/httpapi"
```

**Analysis**:
Both services are legitimate and commonly used:
- **Sentry**: Error reporting and crash analytics (standard practice)
- **Amplitude**: User analytics and event tracking
- No evidence of sensitive data (meeting content, transcripts) being sent to analytics
- Standard implementation with API key authentication
- Events appear limited to UI interactions (recording started, paused, etc.)

**Verdict**: **FALSE POSITIVE** - Standard telemetry for a commercial extension. No sensitive meeting data is transmitted.

---

### 4. INFORMATIONAL: WebRTC Hooking for Audio Capture
**Severity**: INFORMATIONAL
**Files**: `scripts/google_meet_web_rtc.js`
**Lines**: 248-282

**Description**:
The extension hooks into `window.RTCPeerConnection` to intercept and record audio from Google Meet.

**Evidence**:
```javascript
var e = window.RTCPeerConnection,
window.RTCPeerConnection = function() {
  for (var n = [], i = 0; i < arguments.length; i++) n[i] = arguments[i];
  var r = Reflect.construct(e, n);
  t.onPeerConnectionCreate(r);
  var o = r.createDataChannel.bind(r);
  return r.createDataChannel = function(e, n) {
    var i = o(e, n);
    if (t.onDataChannelCreate(i, r), "meet_messages" === e) {
      t.onMeetingStarted();
      // Capture tracks from WebRTC connection
```

**Analysis**:
This is the **core functionality** of the extension - capturing meeting audio:
- The extension needs to intercept WebRTC connections to record audio
- This is done only on Google Meet pages (via content script injection)
- The captured audio is processed locally and uploaded to `bluedothq.com` for transcription
- No malicious intent - this is how meeting recorders work
- The extension informs meeting participants about recording (via in-meeting message)

**Evidence of user notification**:
```javascript
// google_meet.js:423-441
"This meeting is being transcribed and summarized by Bluedot (https://www.bluedot.com/)"
```

**Verdict**: **FALSE POSITIVE** - Legitimate meeting recording implementation. Users are notified of recording.

---

## False Positive Summary

| Pattern | Detected As | Actual Purpose | Verdict |
|---------|-------------|----------------|---------|
| `*://*/*` host permissions | Potential tracking | Multi-platform meeting support | FALSE POSITIVE |
| `desktopCapture`, `tabCapture` | Screen recording malware | Core meeting recorder functionality | FALSE POSITIVE |
| Sentry/Amplitude SDKs | Data exfiltration | Standard error tracking & analytics | FALSE POSITIVE |
| RTCPeerConnection hooking | WebRTC interception | Audio capture for transcription | FALSE POSITIVE |
| `innerHTML` usage | XSS risk | UI rendering in isolated contexts | FALSE POSITIVE |
| Amplitude API key | Hardcoded credentials | Public analytics API key (not a secret) | FALSE POSITIVE |

## API Endpoints Table

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://app.bluedothq.com/api/v1/upload-video` | Initialize recording upload | POST | Meeting metadata, title, participants, language code |
| `https://app.bluedothq.com/api/v1/videos/{id}/report-recording-stats` | Report recording completion | POST | Duration, speaker count, comment count, template |
| `https://app.bluedothq.com/api/v1/videos/refresh-upload-credentials` | Refresh S3 credentials | POST | Workspace ID, video ID |
| `https://app.bluedothq.com/api/v1/videos/{id}/recover` | Recover interrupted recording | POST | Video ID, recovery flag |
| `https://app.bluedothq.com/api/v1/workspaces/default` | Get user workspace | GET | None |
| `https://app.bluedothq.com/api/v1/workspaces/{id}/subscription/current` | Check subscription status | GET | None |
| `https://app.bluedothq.com/api/v1/workspaces/{id}/settings/transcript` | Get transcript settings | GET | None |
| `https://app.bluedothq.com/api/v1/workspaces/{id}/ai-templates` | Fetch AI note templates | GET | None |
| `https://app.bluedothq.com/api/v1/videos/start-bot-recording` | Start bot-based recording | POST | Meeting URL, bot configuration |
| `https://app.bluedothq.com/api/v1/videos/bots/{id}` | Delete bot recording | DELETE | Bot ID |
| `https://app.bluedothq.com/api/v1/user/current/experiments` | Get feature flags | GET | None |
| `https://api2.amplitude.com/2/httpapi` | Analytics events | POST | Event type, timestamp, user ID (hashed) |
| `https://api.eu.amplitude.com/2/httpapi` | Analytics events (EU) | POST | Event type, timestamp, user ID (hashed) |

## Data Flow Summary

### Recording Flow
1. User initiates recording via extension popup or keyboard shortcut (Ctrl+Shift+S)
2. Extension captures audio via `tabCapture` (for tab audio) or `getUserMedia` (for microphone)
3. Audio is encoded using `MediaRecorder` API (WebM format)
4. Chunks are base64-encoded and stored in IndexedDB locally
5. Recording metadata (title, participants, language) is sent to `bluedothq.com/api/v1/upload-video`
6. S3 credentials are obtained from Bluedot backend
7. Recording chunks are uploaded directly to AWS S3 (via temporary credentials)
8. Completion stats sent to `bluedothq.com/api/v1/videos/{id}/report-recording-stats`
9. Backend processes recording for AI transcription/summarization

### Authentication Flow
1. User authenticates via `app.bluedothq.com/auth` (opened in new tab)
2. Session stored in `chrome.storage.sync`
3. All API requests include session credentials in headers
4. Extension identifier injected via content script: `window.twisoExtensionInstalled = true`

### Data Storage
- **Local (IndexedDB)**: Recording chunks, meeting metadata, speaker data, comments
- **Sync Storage**: User preferences, recording settings, workspace ID, language code
- **Session Storage**: Active recording state, tab IDs, current meeting ID

**No evidence of**:
- Cookie harvesting from other sites
- Credential theft
- Keystroke logging
- Ad injection
- Extension enumeration/killing
- Residential proxy infrastructure
- Remote kill switches
- Market intelligence SDKs

## Overall Risk Assessment

**Risk Level**: CLEAN

**Justification**:
1. **Legitimate functionality**: All code serves the stated purpose (meeting recording & AI transcription)
2. **Appropriate permissions**: Sensitive permissions are necessary for core features
3. **Transparent data handling**: Users are notified when recording starts
4. **Vendor-only communications**: All network traffic goes to `bluedothq.com` or standard services (Amplitude, Sentry)
5. **No malicious patterns**: No obfuscation, remote code execution, credential theft, or tracking beyond standard analytics
6. **Commercial product**: Bluedot is a legitimate SaaS company with a transparent business model

**Recommendations**:
- Extension could reduce `host_permissions` to specific meeting domains: `["*://meet.google.com/*", "*://*.teams.microsoft.com/*", "*://zoom.us/*"]` instead of `*://*/*`
- Consider adding permission warnings in UI to clarify why broad permissions are needed

## Conclusion

Bluedot is a **legitimate and safe** Chrome extension for AI-powered meeting recording and transcription. While it uses sensitive permissions (screen/audio capture, broad host access), these are all justified and properly used for its core functionality. The extension does not exhibit any malware characteristics, does not collect excessive data, and maintains appropriate security practices for a commercial product.

**Final Verdict**: CLEAN
