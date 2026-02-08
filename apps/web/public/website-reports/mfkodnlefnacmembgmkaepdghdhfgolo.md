# Security Analysis Report: Genio Notes (formerly Glean)

## Metadata
- **Extension ID**: mfkodnlefnacmembgmkaepdghdhfgolo
- **Extension Name**: Genio Notes (formerly Glean)
- **Version**: 2.2.1113.8981
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Genio Notes is a legitimate note-taking and meeting recording Chrome extension that captures tab audio/video and streams it to the Genio web application via WebRTC. The extension implements proper security boundaries with restrictive `externally_connectable` configuration and communicates only with authenticated Genio/Glean domains. No malicious behavior detected.

**Overall Risk Level: CLEAN**

The extension's powerful permissions (tabCapture, desktopCapture, cookies) are appropriately scoped for its stated functionality of recording meetings and synchronizing with the Genio Notes web application.

## Permissions Analysis

### Declared Permissions
- `sidePanel` - Opens side panel UI for note-taking interface
- `tabCapture` - Captures tab audio/video for meeting recording
- `desktopCapture` - Allows screen/window selection for capture
- `activeTab` - Required for injecting microphone permission request UI
- `cookies` - Reads userId cookie from app.genio.co for authentication
- `scripting` - Injects iframe for microphone permission flow

### Host Permissions
- `https://app.genio.co/notes/*` - Primary web application domain

### Externally Connectable
Restricted to legitimate Genio/Glean domains:
- `https://app.genio.co/*`
- `https://*.dev.genio.ninja/*`
- `https://app.glean.co/*` (legacy domain)
- `https://*.dev.glean.ninja/*` (legacy dev domain)

**Verdict**: Permissions are appropriately scoped for a meeting recording/note-taking extension. No excessive or suspicious permissions requested.

## Vulnerability Analysis

### 1. Audio/Video Capture Implementation
**Severity**: LOW (False Positive - Intended Functionality)

**Location**:
- `/deobfuscated/assets/sidePanel-BYL_vE8u.js:7336-7356` (TabRecorder class)
- `/deobfuscated/assets/ExtensionConstants-IIhyCQck.js:38-43` (Chrome API wrapper)

**Code**:
```javascript
captureCurrentTab: async () => {
  const u = this.tabProvider.getSidePanelTabId();
  await this.chromeApi.updateTab(u, { active: !0 });
  const s = await this.chromeApi.captureTab({
    audio: !0,
    video: !0,
    audioConstraints: Xv
  });
  return this.continuePlayingAudioToUser(s), s
}
```

**Analysis**: Extension captures tab audio/video using chrome.tabCapture API and streams it back to user via AudioContext. This is the core functionality for meeting recording. Capture only occurs when user explicitly triggers recording from the side panel.

**Verdict**: FALSE POSITIVE - Legitimate meeting recording functionality

---

### 2. WebRTC Peer Connection to External Domain
**Severity**: LOW (False Positive - Intended Data Flow)

**Location**: `/deobfuscated/assets/sidePanel-BYL_vE8u.js:7357-7393`

**Code**:
```javascript
class qv {
  constructor(u, s) {
    Ue(this, "peerConnection", new RTCPeerConnection);
    // ...
    this.peerConnection.onicecandidate = s => {
      this.gleanMessageSender.postMessage({
        type: kt.PEER_CONNECTION_CANDIDATE,
        candidate: ((c = s.candidate) == null ? void 0 : c.toJSON()) ?? void 0
      })
    }
  }
}
```

**Analysis**: Extension establishes WebRTC peer connection to stream captured audio/video to app.genio.co. The offer/answer exchange is mediated through postMessage to the embedded iframe. Media stream is sent directly via WebRTC, bypassing the extension's network stack.

**Data Flow**:
1. User initiates recording in side panel
2. Extension captures tab audio/video via chrome.tabCapture
3. WebRTC connection established with app.genio.co origin
4. Media streams sent to Genio backend for processing/storage

**Verdict**: FALSE POSITIVE - Standard WebRTC implementation for legitimate meeting recording service

---

### 3. Cookie Access for Authentication
**Severity**: LOW (False Positive - Legitimate Auth Flow)

**Location**: `/deobfuscated/assets/sidePanel-BYL_vE8u.js:7284-7293`

**Code**:
```javascript
handleReadyMessage: async () => {
  const u = this.tabProvider.getSidePanelTabId(),
    s = await this.tabProvider.getSidePanelTab(),
    c = await this.chromeApi.findCookie({
      url: "https://app.genio.co/notes",
      name: Uu  // "userId"
    });
  this.gleanMessageSender.postMessage({
    type: kt.INITIALISATION_INFO,
    tabId: u,
    tabTitle: s.title ?? "",
    userId: c == null ? void 0 : c.value
  })
}
```

**Analysis**: Extension reads single userId cookie from app.genio.co for authentication/session management. This is sent to the embedded iframe via postMessage (origin-checked). No cookie harvesting or exfiltration detected.

**Verdict**: FALSE POSITIVE - Legitimate authentication mechanism

---

### 4. Microphone Permission Request Flow
**Severity**: LOW (False Positive - User Permission Flow)

**Location**:
- `/deobfuscated/assets/sidePanel-BYL_vE8u.js:7256-7257` (Injection)
- `/deobfuscated/assets/requestPermissions-JSFKrYvn.js:1` (Permission request)

**Code**:
```javascript
// Injection of permission iframe
const o = document.createElement("iframe");
o.setAttribute("hidden", "hidden");
o.setAttribute("id", "permissionsIFrame");
o.setAttribute("allow", "microphone");
o.src = chrome.runtime.getURL("src/requestPermissions/requestPermissions.html");
document.body.appendChild(o)

// Permission request
const n = async () => {
  try {
    (await navigator.mediaDevices.getUserMedia({audio: !0}))
      .getTracks().forEach(function(s) { s.stop() })
  } catch {
    o.info(a, "Microphone permission not granted")
  }
}
```

**Analysis**: Extension injects hidden iframe to request microphone permissions via getUserMedia. This is required because chrome.tabCapture.capture() needs microphone permissions pre-granted. Tracks are immediately stopped after permission grant. This is a standard Chrome extension pattern for permission requests.

**Verdict**: FALSE POSITIVE - Legitimate permission request pattern

---

### 5. Embedded Iframe to External Domain
**Severity**: LOW (Acceptable Risk - Scoped Communication)

**Location**: `/deobfuscated/assets/sidePanel-BYL_vE8u.js:7240-7247`

**Code**:
```javascript
ae.jsx("iframe", {
  ref: o,
  title: "Genio",
  src: "https://app.genio.co/notes/extension-landing-page",
  allow: "microphone; autoplay; storage-access; clipboard-write",
  className: Wv.iframe,
  "data-test": Vv.iframe
})
```

**Analysis**: Side panel embeds iframe pointing to app.genio.co. Communication is mediated via postMessage with origin validation:
```javascript
async f => {
  "https://app.genio.co/notes".startsWith(f.origin) &&
    await c.handleMessage(f.data)
}
```

The iframe allows microphone, autoplay, storage-access, and clipboard-write permissions. These are required for the note-taking interface functionality.

**Verdict**: ACCEPTABLE RISK - Proper origin validation implemented

---

### 6. Sentry Error Tracking
**Severity**: LOW (False Positive - Standard Telemetry)

**Location**: `/deobfuscated/assets/ExtensionMessage-TCtZk8Sf.js:12348-12386`

**Code**:
```javascript
class Xs {
  constructor() {
    ct(this, "logToSentry", (e, i) => {
      const o = `[${e.code}] ${e.message}`,
        s = this.buildTagsFromExtraFields(e);
      e.stackTrace !== void 0 ? Kw(i, {
        extra: { ...e.extraFields, message: o, loggingCode: e.code },
        tags: { loggingCode: e.code, ...s },
        fingerprint: [e.code, "{{ default }}"]
      }) : Yw(o, { /* ... */ })
    })
  }
}
```

**Analysis**: Extension includes Sentry SDK (v9.27.0) for error tracking and debugging. Sentry integration is disabled in production Chrome extension builds (`!Ta() && !Xh()` check). Only console and AJAX logging destinations are active. No personal data is included in error reports.

**Verdict**: FALSE POSITIVE - Standard error tracking SDK, disabled in production extension builds

---

### 7. AJAX Logging to Backend
**Severity**: LOW (False Positive - Legitimate Telemetry)

**Location**: `/deobfuscated/assets/ExtensionMessage-TCtZk8Sf.js:11697-11710`

**Code**:
```javascript
ct(this, "uploadLog", async e => {
  const i = "FetchLogApi.uploadLog",
    o = `${this.urlPrefix}/api/logs`,  // https://app.glean.co/notes/api/logs
    s = await fw(_w, i, o, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(e)
    });
  s.ok || await cw(i, s)
})
```

**Analysis**: Extension sends structured logs to https://app.glean.co/notes/api/logs endpoint. Logs include timestamp, severity, code, message, and contextFields (filtered to exclude undefined values). No PII beyond userId (from cookie) is transmitted. Logging is only active when user is online and authenticated.

**Verdict**: FALSE POSITIVE - Standard application logging for debugging

## API Endpoints Table

| Endpoint | Method | Purpose | Data Transmitted |
|----------|--------|---------|------------------|
| `https://app.glean.co/notes/api/logs` | POST | Application logging | Structured logs (timestamp, severity, code, message, contextFields) |
| `https://app.genio.co/notes/extension-landing-page` | GET (iframe) | Side panel UI | None (loaded as iframe) |
| `https://app.genio.co/notes/event/{eventId}` | GET (tab) | Opens recorded event | None (navigation) |
| WebRTC (STUN/TURN) | N/A | Media streaming | Encrypted audio/video streams |

## Data Flow Summary

### Data Collection
1. **Tab Title**: Current tab title sent to iframe during initialization
2. **Tab ID**: Internal Chrome tab identifier for coordination
3. **User ID**: Single cookie value from app.genio.co for authentication
4. **Audio/Video Streams**: Captured via chrome.tabCapture, streamed to Genio backend via WebRTC
5. **Logs**: Application errors/debug logs sent to /api/logs endpoint

### Data Transmission
- All network requests use HTTPS with credentials included
- WebRTC streams are encrypted end-to-end
- Communication with iframe validated against origin (app.genio.co)
- No third-party analytics or tracking SDKs detected

### Data Storage
- No localStorage, sessionStorage, or indexedDB usage detected
- Extension relies on cookies set by app.genio.co for authentication
- No local file system access

## False Positive Summary

| Pattern | Explanation | Legitimate Use |
|---------|-------------|----------------|
| React SVG innerHTML | Standard React rendering | React library code (lodash, scheduler) |
| tabCapture/desktopCapture | Core extension functionality | Meeting recording feature |
| WebRTC RTCPeerConnection | Standard media streaming | Audio/video transmission to backend |
| Cookie access | Authentication | Single userId cookie read |
| Sentry SDK hooks | Error tracking | Disabled in production builds |
| Iframe injection | Permission flow | Microphone permission request |
| postMessage communication | Cross-origin messaging | Validated origin checks |

## Security Observations

### Positive Security Practices
1. **Restrictive externally_connectable**: Only allows Genio/Glean domains
2. **Origin validation**: postMessage handlers check message origin
3. **Minimal cookie access**: Only reads userId, no harvesting
4. **No eval/Function**: No dynamic code execution detected
5. **No content scripts**: Extension doesn't inject code into arbitrary pages
6. **CSP compliance**: No CSP bypass attempts detected
7. **Manifest V3**: Uses modern manifest version with service workers

### Areas of Note (Not Vulnerabilities)
1. **Powerful permissions**: tabCapture and desktopCapture are high-privilege, but required for stated functionality
2. **Embedded iframe**: Side panel embeds third-party origin, but communication is properly validated
3. **Audio playback**: Captured audio is played back to user via AudioContext (prevents silent recording)

## Conclusion

Genio Notes (formerly Glean) is a legitimate meeting recording and note-taking extension with no malicious behavior detected. All permissions are appropriately scoped for the extension's functionality. The extension implements proper security boundaries including origin validation, restrictive externally_connectable configuration, and minimal data collection.

The extension's architecture follows best practices for Chrome extensions that need to coordinate between extension context and web application context via iframes and WebRTC.

**Overall Risk Assessment: CLEAN**

No security vulnerabilities or malicious behavior detected. All flagged patterns are false positives related to legitimate meeting recording and note-taking functionality.
