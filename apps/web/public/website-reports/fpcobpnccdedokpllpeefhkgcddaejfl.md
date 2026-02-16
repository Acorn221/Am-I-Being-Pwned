# Vulnerability Report: Supernormal AI Meeting Notes

## Metadata
- **Extension Name**: Supernormal: AI Meeting Notes
- **Extension ID**: fpcobpnccdedokpllpeefhkgcddaejfl
- **Version**: 4.0.62
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Supernormal is an AI meeting notes extension that captures Google Meet transcriptions and chat messages. The extension exhibits **LEGITIMATE BUT INVASIVE** behavior patterns consistent with its advertised functionality. It intercepts Google Meet WebRTC data channels, network requests, and user cookies to enable transcription capture and synchronization with the Supernormal backend.

**Overall Risk Level**: **MEDIUM**

The extension demonstrates legitimate meeting transcription capabilities but employs highly invasive techniques including:
- Cookie harvesting (SAPISID) for Google API authentication
- Global fetch/XHR hooking to intercept Google Meet network traffic
- RTCPeerConnection/WebRTC data channel interception for live transcription capture
- Injection into MAIN world context with full page access
- Storage of authentication tokens and meeting data

While these techniques serve the extension's stated purpose, they represent significant privacy implications and create potential attack surface if the extension or its backend were compromised.

## Vulnerability Analysis

### 1. Cookie Harvesting from Google Meet [MEDIUM]
**Severity**: MEDIUM
**Files**: `googlemeetrtcplug.bundle.js:2706`

**Description**:
The extension extracts Google's SAPISID cookie to generate SAPISIDHASH authentication headers for making authenticated requests to Google Meet APIs.

**Code Evidence**:
```javascript
// Line 2706
}(document.cookie.split("SAPISID=")[1].split("; ")[0], "https://meet.google.com")

// Line 2901 - Usage for authentication
r.authorization = `SAPISIDHASH ${await pn()}`, r["X-Goog-Api-Key"] = "AIzaSyCG_6Rm6c7ucLr2NwAq33-vluCp2VfSkf0"
```

**Verdict**: **PRIVACY CONCERN** - The extension harvests sensitive Google authentication cookies. While this is used to send chat messages on behalf of the user (legitimate functionality), it represents a significant trust assumption. If the extension were compromised, this cookie access could enable unauthorized Google API calls.

**Risk**: Legitimate use but creates potential for abuse. The SAPISID cookie provides access to Google services on behalf of the authenticated user.

---

### 2. Global Fetch/XHR Hooking [MEDIUM]
**Severity**: MEDIUM
**Files**: `googlemeetrtcplug.bundle.js:2915-3036`

**Description**:
The extension globally hooks `window.fetch` and `XMLHttpRequest` prototypes to intercept ALL network traffic from Google Meet pages.

**Code Evidence**:
```javascript
// Lines 2915-2923 - XHR hooking
const Bn = window.XMLHttpRequest.prototype.open,
  Cn = window.XMLHttpRequest.prototype.send,
  Pn = window.XMLHttpRequest.prototype.setRequestHeader;

window.XMLHttpRequest.prototype.open = function(e, t) {
  0 === t.toString().indexOf(zn) && (window.__savedXGoogMeetingToken = t, this.__requestUrl = zn)
  Bn.apply(this, arguments)
}

// Lines 2944-3036 - Fetch hooking
const jn = window.fetch;
window.fetch = function(e, t) {
  // Intercepts specific Google Meet API endpoints
  if ("https://meet.google.com/$rpc/google.rtc.meetings.v1.MeetingSpaceService/SyncMeetingSpaceCollections" === t.url) {
    // Extracts device info and meeting metadata
  }
  // ... more interceptions
}
```

**Intercepted Endpoints**:
- `SyncMeetingSpaceCollections` - Participant device info
- `CreateMeetingMessage` - Chat messages
- `CreateMeetingRecording` - Recording events
- `UpdateMediaSession` - Language/caption settings
- `/hangouts/v1_meetings/media_sessions/modify` - Meeting metadata

**Verdict**: **LEGITIMATE BUT INVASIVE** - The hooking is necessary to capture meeting events since Google Meet doesn't provide official APIs. However, this creates a complete man-in-the-middle position for all Google Meet network traffic.

**Risk**: If extension is compromised, all Google Meet API traffic could be exfiltrated.

---

### 3. RTCPeerConnection Hijacking [MEDIUM]
**Severity**: MEDIUM
**Files**: `googlemeetrtcplug.bundle.js:3037-3173`

**Description**:
The extension replaces the native `RTCPeerConnection` constructor to intercept WebRTC data channels used for live transcription.

**Code Evidence**:
```javascript
// Lines 3037-3173
const Nn = window.RTCPeerConnection;
window.RTCPeerConnection = function(e, t) {
  const n = new Nn(e, t);
  return n.addEventListener("datachannel", (function(e) {
    "collections" === e.channel.label && (Ln = n, e.channel.addEventListener("message", (e => {
      // Intercepts collection data channel messages
    })))
  })), n
}

// Lines 3051-3086 - Data channel creation hooking
Nn.prototype.createDataChannel = function() {
  const t = Gn.apply(this, arguments);
  if (t && "captions" === t.label) {
    t.addEventListener("message", (e => {
      const t = On(En(e.data));  // Decodes caption messages
      t && function(e) {
        xn.push(e)  // Stores captions
      }(t)
    }));
  }
  return t
}
```

**Verdict**: **LEGITIMATE FUNCTIONALITY** - This is required to capture live captions/transcriptions from Google Meet's WebRTC data channels. Google Meet uses data channels named "captions" and "collections" for real-time communication.

**Risk**: Low, as this serves the core functionality. However, represents deep integration into WebRTC communications.

---

### 4. MAIN World Script Injection [MEDIUM]
**Severity**: MEDIUM
**Files**: `manifest.json:19-29`, `googlemeetrtcplug.bundle.js`

**Description**:
The extension injects `googlemeetrtcplug.bundle.js` into the MAIN world context with `run_at: document_start`, giving it full access to page globals before page scripts execute.

**Code Evidence**:
```json
{
  "js": ["./googlemeetrtcplug.bundle.js"],
  "world": "MAIN",
  "run_at": "document_start",
  "matches": ["*://meet.google.com/*-*-*"]
}
```

**Verdict**: **NECESSARY FOR FUNCTIONALITY** - MAIN world injection is required to intercept page-level JavaScript objects (fetch, XHR, RTCPeerConnection) before Google Meet initializes. This cannot be done from ISOLATED world.

**Risk**: MAIN world scripts have same privileges as page scripts, creating potential for conflicts or exploitation if extension is compromised.

---

### 5. Authentication Token Storage [LOW]
**Severity**: LOW
**Files**: `background.bundle.js:5047-5059`

**Description**:
The extension stores authentication tokens in chrome.storage.local for API communication with Supernormal backend.

**Code Evidence**:
```javascript
// Lines 5047-5059
const r = "authToken";
function i(t) {
  chrome.storage.local.set({
    authToken: t
  })
}
async function s() {
  return (await chrome.storage.local.get(r))[r] || null
}
```

**Verdict**: **STANDARD PRACTICE** - Token storage is normal for authenticated extensions. Tokens are stored in chrome.storage.local which is sandboxed per-extension.

**Risk**: Minimal, standard implementation.

---

### 6. External Message Handling [LOW]
**Severity**: LOW
**Files**: `background.bundle.js:3886-3921`, `manifest.json:65-73`

**Description**:
The extension accepts external messages from specific domains for sign-in/sign-out coordination.

**Code Evidence**:
```javascript
// Lines 3886-3905
chrome.runtime.onMessageExternal.addListener(nt);
const nt = async t => {
  if (t.type) switch (t.type) {
    case "SN_SIGN_IN":
      await et({ type: o.u.SET_AUTH_TOKEN, token: t.token });
      break;
    case "SN_SIGN_OUT":
      await et({ type: o.u.DELETE_AUTH_TOKEN });
      break;
  }
};
```

**Manifest externally_connectable**:
```json
"externally_connectable": {
  "matches": [
    "http://localhost:3001/*",
    "https://app.staging.supernormal.com/*",
    "https://app.supernormal.com/*",
    "https://events.statsigapi.net/*",
    "https://featuregates.org/*"
  ]
}
```

**Verdict**: **ACCEPTABLE** - External messaging is limited to known Supernormal domains plus localhost for development. Message types are restricted to authentication actions.

**Risk**: Low, appropriate domain restrictions in place.

---

### 7. Sentry Error Reporting [LOW]
**Severity**: LOW
**Files**: `background.bundle.js:3793`

**Description**:
The extension uses Sentry for error reporting to monitor crashes and exceptions.

**Code Evidence**:
```javascript
// Line 3793
C.S({
  dsn: "https://b2072076a5224083956cf4d933b5d038@o382053.ingest.sentry.io/6004388",
  release: "4.0.62",
  environment: "production"
})
```

**Verdict**: **STANDARD PRACTICE** - Sentry is a legitimate error monitoring service. DSN is public-facing (not a secret).

**Risk**: Minimal, standard development practice.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | googlemeetrtcplug.bundle.js:760 | Webpack polyfill for global object access |
| `innerHTML` usage | controls.bundle.js:813 | React SVG rendering (known safe pattern) |
| `MSApp.execUnsafeLocalFunction` | controls.bundle.js:819 | React compatibility for IE/Edge legacy |
| Sentry SDK hooks | background.bundle.js:* | Official Sentry browser SDK |
| Statsig/Featuregates.org | controls.bundle.js:* | Feature flag service (Statsig) |

## API Endpoints & Data Flow

### Supernormal Backend API
| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `api.supernormal.com/api/v1/posts` | POST | Create meeting note | Meeting metadata |
| `api.supernormal.com/api/v1/posts/{id}` | PATCH | Update meeting note | Transcription data |
| `api.supernormal.com/api/v1/bots/active-by-url` | GET | Check for active bot | Meeting URL |
| `api.supernormal.com/api/v1/user/events` | POST | Telemetry events | User actions, errors |

### Google Meet Endpoints (Intercepted)
| Endpoint | Purpose | Data Extracted |
|----------|---------|----------------|
| `$rpc/.../SyncMeetingSpaceCollections` | Meeting metadata | Participant devices, names |
| `$rpc/.../CreateMeetingMessage` | Chat messages | User messages |
| `$rpc/.../UpdateMediaSession` | Settings | Language preferences |
| `/hangouts/v1_meetings/media_sessions/modify` | Session control | Meeting tokens |

### Data Flow Summary
1. **Capture Phase**: Extension intercepts Google Meet WebRTC data channels and network requests
2. **Extract Phase**: Decodes protobuf messages to extract transcriptions, chat, participant info
3. **Aggregate Phase**: Buffers speech segments (500ms intervals) in `xn` array
4. **Transmit Phase**: POSTs aggregated data to `api.supernormal.com` with Bearer token auth
5. **Storage Phase**: Saves session state to chrome.storage.local for persistence

**PII Collected**:
- Meeting transcriptions (speech-to-text)
- Chat messages
- Participant names and device IDs
- Meeting URLs
- User email (via Google authentication)
- Meeting duration and timestamps

## Security Considerations

### Positive Security Practices
1. ✓ Uses Content Security Policy (implied by MV3)
2. ✓ Limited host_permissions to Google Meet only
3. ✓ Restricts external messaging to known domains
4. ✓ Uses HTTPS for all API communication
5. ✓ Proper error handling with Sentry

### Concerns & Recommendations
1. **Cookie Access**: SAPISID cookie harvesting creates potential for abuse if extension compromised
   - *Recommendation*: Consider alternative authentication methods that don't require cookie access

2. **Comprehensive Network Interception**: Global fetch/XHR hooking intercepts ALL page network traffic
   - *Recommendation*: Cannot be avoided given Google Meet's architecture, but represents significant trust requirement

3. **Sensitive Data Transmission**: Meeting transcriptions contain PII and confidential information
   - *Recommendation*: Ensure backend has proper encryption, access controls, and data retention policies

4. **Third-party Analytics**: Uses Statsig (featuregates.org/events.statsigapi.net)
   - *Recommendation*: Review Statsig data collection practices

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

**Justification**:
The extension exhibits **legitimate functionality** consistent with its advertised purpose as an AI meeting notes tool. All invasive behaviors (cookie harvesting, network interception, WebRTC hijacking) directly serve the core transcription capture functionality.

However, the extension requires an extremely high level of trust due to:
- Complete visibility into Google Meet communications
- Access to sensitive authentication cookies
- Interception of all meeting content (audio transcriptions, chat, participants)
- Transmission of meeting data to third-party backend

**Risk Category**: **Privacy-Invasive but Legitimate**

The extension is **not malware** but represents significant privacy implications that users should understand before installation. The invasive techniques are necessary given Google Meet's closed architecture and lack of official APIs for transcription access.

**Trust Requirements**:
- Users must trust Supernormal company with all meeting content
- Users must trust Supernormal's security practices (backend, data retention)
- Users must trust extension won't be compromised (supply chain risk)
- Meeting participants should be informed of transcription capture

## Conclusion

Supernormal is a **legitimate meeting transcription extension** that uses highly invasive but necessary techniques to capture Google Meet content. The implementation is technically sound for its purpose, but users should be aware of the significant privacy implications.

**Recommendation**: **MEDIUM** risk - Acceptable for users who explicitly want AI meeting notes and trust the Supernormal service, but represents privacy concerns for meeting participants who may not be aware of transcription capture.

**No critical vulnerabilities or malicious behavior detected.**
