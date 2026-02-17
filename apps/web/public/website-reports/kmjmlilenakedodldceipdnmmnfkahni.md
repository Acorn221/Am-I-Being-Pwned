# Vulnerability Report: Scribbl - AI Note Taker for Google Meet, Zoom

## Extension Metadata
- **Extension ID**: kmjmlilenakedodldceipdnmmnfkahni
- **Extension Name**: Scribbl: AI Note Taker for Google Meet, Zoom
- **Version**: 16.8
- **User Count**: ~30,000
- **Manifest Version**: 3

## Executive Summary

Scribbl is a legitimate AI note-taking extension designed to capture and transcribe Google Meet conversations. The extension intercepts Google Meet's WebRTC data channels and API responses to extract captions and participant information, then sends this data to Scribbl's backend servers for processing. While the extension implements invasive monitoring techniques, these behaviors align with its stated purpose of recording and transcribing meetings. The extension uses appropriate permissions, implements proper authentication, and does not exhibit malicious characteristics.

**Overall Risk: CLEAN**

The extension is invasive by design but serves its intended purpose without evidence of malicious behavior or key vulnerabilities.

---

## Vulnerability Analysis

### 1. WebRTC Data Channel Interception (INFORMATIONAL)
**Severity**: Informational
**Files**: `js/inject-rtc.js`, `content/content.js`
**Code Evidence**:
```javascript
// inject-rtc.js:7-16
window.RTCPeerConnection = function(...n) {
  const o = new e(...n),
    r = o.createDataChannel;
  return o.createDataChannel = function(e, n) {
    const o = r.call(this, e, n);
    return "captions" !== e && "collections" !== e || t(o, e), o
  }, o
```

```javascript
// inject-rtc.js:24-28
window.postMessage({
  source: "captions" === n ? "scribbl-caption" : "scribbl-participant",
  buffer: t,
  time: Date.now()
}, "*", [t])
```

**Description**: The extension patches `window.RTCPeerConnection` to intercept WebRTC data channels named "captions" and "collections". It listens for messages on these channels and forwards them via `postMessage` to the content script.

**Verdict**: **NOT A VULNERABILITY**. This is the core functionality for capturing live captions from Google Meet. The extension only intercepts specific named channels used by Google Meet for captions/participants and does not monitor all WebRTC traffic.

---

### 2. Google Meet API Response Interception (INFORMATIONAL)
**Severity**: Informational
**Files**: `js/inject-rtc.js`
**Code Evidence**:
```javascript
// inject-rtc.js:46-87
window.fetch = function(...e) {
  const [t] = e, o = "string" == typeof t ? t : t.toString();
  return n.apply(this, e).then((async e => {
    if (o.includes("SyncMeetingSpaceCollections") || o.includes("collections") ||
        o.includes("spaces") || o.includes("$rpc/google.rtc") ||
        o.includes("users/me") || o.includes("GetMeetingSpace")) try {
      // ... extracts and decodes response data
      window.postMessage({
        source: "scribbl-participant-fetch",
        buffer: r,
        url: o,
        time: Date.now()
      }, "*", [r])
```

**Description**: The extension wraps `window.fetch` to intercept Google Meet API responses containing participant and space information. It decodes base64-encoded protobuf responses and forwards them to the content script.

**Verdict**: **NOT A VULNERABILITY**. This is necessary for extracting participant names/avatars for attribution in transcripts. The extension only intercepts Google Meet-specific API endpoints.

---

### 3. Protobuf Message Parsing (INFORMATIONAL)
**Severity**: Informational
**Files**: `content/content.js`, `proto-bundle.js`
**Code Evidence**:
```javascript
// content.js:20052-20073
case "scribbl-caption":
  const n = Bt.BTranscriptMessageWrapper.decode(t);
  if (null == n ? void 0 : n.message) ci(n.message);

case "scribbl-participant":
  const g = Bt.CollectionsWrapper.decode(m),
    v = null === (o = ... ) ? void 0 : o.device;
  (null == v ? void 0 : v.deviceId) && (null == v ? void 0 : v.deviceName) ?
    function(e) { si.participants.set(e.deviceId, e); }
```

**Description**: The extension decodes protobuf-encoded messages from Google Meet's internal protocols to extract transcript text, participant names, device IDs, and avatar URLs.

**Verdict**: **NOT A VULNERABILITY**. This is legitimate reverse engineering of Google Meet's internal protocol for the extension's stated purpose. No sensitive data beyond meeting participants is extracted.

---

### 4. Backend Data Transmission (INFORMATIONAL)
**Severity**: Informational
**Files**: `background.js`
**Code Evidence**:
```javascript
// background.js:4441-4448
const e = yield o("https://backend.scribbl.co/auth/userinfo", {
  method: "POST",
  credentials: "include"
});

// background.js:4455-4465
const n = yield fetch("https://backend.scribbl.co/meeting/create-or-reuse", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    googleMeetID: e,
    localMeetingID: t
  })
});
```

**Description**: The extension sends meeting IDs, transcripts, and participant information to `backend.scribbl.co` and `extension.app.scribbl.co`. All communication uses HTTPS and includes authentication via cookies.

**Verdict**: **NOT A VULNERABILITY**. Data transmission to backend is the expected behavior for a cloud-based transcription service. The extension uses proper authentication and secure connections. Host permissions are explicitly declared in the manifest.

---

### 5. Third-Party Analytics (INFORMATIONAL)
**Severity**: Informational
**Files**: `background.js`, `js/amplitude.js`, `js/sentry_content.js`
**Code Evidence**:
```javascript
// background.js:5062-5064
new("x7CXMZ8yWKUzTS2EqpNW4fr3", {
  endpoint: "https://s1278380.eu-nbg-2.betterstackdata.com"
});
```

**Description**: The extension includes BetterStack logging (Logtail), Amplitude analytics, and Sentry error reporting SDKs.

**Verdict**: **NOT A VULNERABILITY**. Standard telemetry/error reporting for a SaaS product. No evidence of excessive data collection beyond error logs and usage metrics.

---

### 6. OAuth2 Integration (INFORMATIONAL)
**Severity**: Informational
**Files**: `manifest.json`
**Code Evidence**:
```json
"oauth2": {
  "client_id": "522707397645-5g8ioeo87sb5ikjseh0e252b1tbn15t4.apps.googleusercontent.com",
  "scopes": ["profile email", "https://www.googleapis.com/auth/drive.file"]
}
```

**Description**: The extension requests Google Drive file access scope for saving transcripts to user's Google Drive.

**Verdict**: **NOT A VULNERABILITY**. OAuth2 scopes are appropriate for the extension's functionality (saving meeting notes to Drive). Uses standard Google OAuth2 flow.

---

## False Positive Analysis

| Pattern | File | Reason for False Positive |
|---------|------|--------------------------|
| `new Function` | background.js:4346 | Webpack runtime helper, not dynamic code execution |
| `setTimeout/setInterval` | background.js (multiple) | Standard async operations and polling loops |
| `postMessage` | inject-rtc.js:24 | Legitimate IPC between injected script and content script |
| `fetch` wrapper | inject-rtc.js:46 | Intercepting Google Meet APIs for caption extraction |
| `RTCPeerConnection` patching | inject-rtc.js:7 | Monitoring WebRTC data channels for live captions |
| Protobuf decoding | content.js:20064 | Parsing Google Meet's internal protocol messages |
| Dexie IndexedDB library | background.js:4501 | Standard client-side database for offline storage |
| Sentry SDK hooks | sentry.js | Known FP - error reporting SDK |

---

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://backend.scribbl.co/auth/userinfo` | User authentication | Cookies (credentials: include) |
| `https://backend.scribbl.co/auth/logout` | Sign out | Cookies (credentials: include) |
| `https://backend.scribbl.co/meeting/create-or-reuse` | Create meeting session | googleMeetID, localMeetingID |
| `https://backend.scribbl.co/meeting/{uuid}/claim` | Claim meeting ownership | claimToken |
| `https://extension.app.scribbl.co/*` | Extension UI/auth | User sign-in flow |
| `https://scribbl-enhanced-recordings-prd.s3.us-east-2.amazonaws.com/*` | S3 upload destination | Video recordings (via tabCapture) |
| `https://s1278380.eu-nbg-2.betterstackdata.com` | Logging/telemetry | Error logs, usage metrics |

**Data Flow Summary**:
1. Injected script intercepts Google Meet WebRTC captions + API responses
2. Content script parses protobuf messages → extracts transcripts + participants
3. Background script syncs data to Scribbl backend via authenticated API calls
4. Video recordings uploaded to S3 bucket (when recording feature used)
5. Analytics/errors sent to BetterStack, Amplitude, Sentry

---

## Manifest Permissions Analysis

### Declared Permissions
- `unlimitedStorage` - Storing large video recordings locally
- `offscreen` - Background video recording processing
- `alarms` - Periodic sync of transcript snippets
- `tabCapture` - Recording Google Meet tabs (video/audio)

### Host Permissions
- `https://meet.google.com/*` - Content script injection for Meet UI
- `https://extension.app.scribbl.co/*` - Auth/settings iframe
- `https://backend.scribbl.co/*` - API communication
- `https://scribbl-enhanced-recordings-prd.s3.us-east-2.amazonaws.com/*` - Video upload

**Assessment**: All permissions are justified and aligned with the extension's functionality. No excessive or suspicious permissions requested.

---

## Security Concerns (Not Vulnerabilities)

### Privacy Considerations
- **Meeting Content Capture**: The extension captures all spoken content in Google Meet sessions, including potentially sensitive conversations
- **Participant Tracking**: Collects names, device IDs, and avatar URLs of all meeting participants
- **Cloud Storage**: All transcript data transmitted to and stored on Scribbl's servers
- **Recording Capability**: With user permission, can record full video/audio of meetings

**Mitigation**: These are inherent to the extension's purpose. Users should be aware that using this extension means all meeting content is processed by a third-party service.

### Design Observations
- No evidence of local keylogging or credential harvesting
- No cryptocurrency mining or ad injection
- No extension enumeration or killing mechanisms
- No residential proxy infrastructure
- No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- No unauthorized cookie/storage access
- No XHR/fetch hooking for non-Google Meet domains

---

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification
Scribbl is a legitimate productivity tool that performs invasive monitoring of Google Meet sessions, but this behavior is:
1. **Explicitly disclosed**: The extension's name and description clearly state it's for recording/transcribing meetings
2. **Functionally necessary**: Cannot provide transcription without capturing meeting audio/captions
3. **Properly permissioned**: Manifest permissions align with functionality
4. **Appropriately scoped**: Only monitors Google Meet, not all web traffic
5. **Securely implemented**: Uses HTTPS, OAuth2, and proper authentication

While the extension collects extensive meeting data (transcripts, participants, recordings), this is the core value proposition and users knowingly install it for this purpose. No evidence of:
- Data misuse or unauthorized access
- Malicious code injection
- Privacy violations beyond stated functionality
- Security vulnerabilities that could be exploited

### Recommendations for Users
- Only use in meetings where recording/transcription is permitted
- Review Scribbl's privacy policy regarding data retention
- Understand that all meeting content is processed by third-party servers
- Disable when not needed to minimize data collection

---

## Conclusion

Scribbl is a **CLEAN** extension that implements sophisticated but legitimate meeting transcription capabilities. The invasive monitoring techniques (WebRTC interception, API response parsing, protobuf decoding) are necessary for the extension's stated purpose and do not constitute malicious behavior. Users should make an informed decision about the privacy trade-offs inherent in using a cloud-based transcription service.
