# Security Analysis: Felo Subtitles (ponokiofkijoolhebggofhhibnafebna)

## Extension Metadata
- **Name**: Felo Subtitles
- **Extension ID**: ponokiofkijoolhebggofhhibnafebna
- **Version**: 3.0.2
- **Manifest Version**: 3
- **Estimated Users**: ~40,000
- **Developer**: Felo (felo.me/felo.cc)
- **Analysis Date**: 2026-02-15

## Executive Summary
Felo Subtitles is a real-time transcription and translation extension for video conferencing platforms (Google Meet, Microsoft Teams, Zoom) and YouTube. The extension provides live captions and translations using Microsoft Edge Translator API and the developer's backend services.

**Critical Security Findings**: The extension contains **15 separate postMessage event handlers without origin validation**, creating a significant attack surface where malicious websites can inject commands to control transcription behavior, manipulate UI state, and trigger internal operations. However, analysis revealed these handlers primarily control UI/state and do not directly enable data exfiltration beyond the extension's intended translation functionality.

**Data Flow Assessment**: The extension captures audio via tabCapture and getUserMedia permissions, sends transcribed text to Microsoft Edge Translator API and Felo backend services. While this constitutes sensitive data handling, it aligns with the extension's stated purpose of real-time translation.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. PostMessage Handlers Without Origin Validation (15 INSTANCES)
**Severity**: HIGH
**CWE**: CWE-346 (Origin Validation Error)
**Files**:
- `/js/translate.js` (lines 3974, 20165, 34307, 37863, 37951)
- `/js/subtitle.js` (lines 4033, 20226, 36853, 38855, 38943)
- `/js/capture.js` (line 11617)
- `/common/zoom.inline.js` (line 74)
- `/common/youtube.inline.js` (line 13)
- `/common/teams.inline.js` (line 52)
- `/common/googlemeet.inline.js` (line 34)

**Analysis**:
The extension injects multiple inline scripts into target platforms (Google Meet, Teams, Zoom, YouTube) that listen for window postMessage events without validating the event origin. This allows ANY website in the same browsing context to send commands to the extension.

**Code Evidence** (`common/teams.inline.js`, line 52):
```javascript
window.addEventListener("message", (({data}) => {
    "update-remote-audio" === data.type && function() {
        const tm = setInterval((() => {
            const remotes = document.querySelectorAll("body>audio");
            console.log("@@gm", remotes, remotes.length), 0 !== remotes.length && (console.log("@@gm", remotes, 3 === remotes.length, tm),
            setRemoteAudio(remotes), clearInterval(tm));
        }), 1e3);
    }();
}));
```

**Attack Scenarios**:
1. **Malicious iframes on legitimate conferencing sites** could send messages like:
   - `{type: "subtitle:start"}` - Force transcription to start
   - `{type: "subtitle:end"}` - Force transcription to stop
   - `{type: "subtitle:pause"}` - Manipulate recording state
   - `{type: "update-remote-audio"}` - Trigger audio element queries

2. **YouTube attack**: Any page embedding malicious scripts could send:
   ```javascript
   window.postMessage({type: "subtitle:transcribe-pause", from: "youtube"}, "*");
   ```

3. **Cross-context attacks**: If the user has the extension active and visits a malicious page, that page can manipulate the extension's state.

**Impact Assessment**:
- **Direct Data Exfiltration**: LOW - Handlers primarily control internal state, not data export
- **Service Disruption**: HIGH - Attackers can disable transcription, trigger unwanted operations
- **UI Manipulation**: HIGH - Can control subtitle display, audio processing
- **Privacy Impact**: MEDIUM - Could force transcription on/off without user consent

**Affected Message Types**:
| Message Type | Location | Impact |
|-------------|----------|--------|
| `subtitle:start` | youtube.inline.js | Starts transcription timer |
| `subtitle:end` | youtube.inline.js | Stops transcription |
| `subtitle:pause` | youtube.inline.js | Pauses transcription |
| `subtitle:transcribe-pause` | youtube.inline.js | Pauses transcription service |
| `subtitle:transcribe-continue` | youtube.inline.js | Resumes transcription |
| `subtitle:video-muted` | youtube.inline.js | Updates mute state |
| `subtitle:video-paused` | youtube.inline.js | Updates pause state |
| `subtitle:microphone-enabled` | teams.inline.js | Updates microphone state |
| `update-remote-audio` | teams.inline.js | Triggers audio element processing |
| `update-local-audio` | teams.inline.js | Updates local audio state |

**Recommended Fix**:
```javascript
// Add origin validation
window.addEventListener("message", (event) => {
    const allowedOrigins = [
        'https://meet.google.com',
        'https://teams.microsoft.com',
        'https://teams.live.com',
        'https://zoom.us',
        'https://www.youtube.com'
    ];

    if (!allowedOrigins.some(origin => event.origin.startsWith(origin))) {
        console.warn('Rejected message from unauthorized origin:', event.origin);
        return;
    }

    const {data} = event;
    // Process message...
});
```

**Verdict**: **HIGH SEVERITY** - Multiple attack vectors, though limited direct impact on data confidentiality.

---

### 2. Audio Capture and Processing
**Severity**: MEDIUM
**Files**:
- `/js/capture.js` (line 15655 - chrome.tabCapture)
- `/js/subtitle.js` (line 3829 - captureStream)
- `/js/translate.js` (line 20543 - video.captureStream)
- `/common/teams.inline.js` (lines 34-41 - getUserMedia hook)

**Analysis**:
The extension uses multiple audio capture mechanisms to obtain audio from video conferencing sessions:

1. **Chrome tabCapture API** - Captures entire tab audio
2. **MediaStream captureStream()** - Captures from video/audio elements
3. **getUserMedia() interception** - Hooks native MediaDevices.getUserMedia

**Code Evidence** (`common/teams.inline.js`, lines 34-41):
```javascript
const origGetUserMedia = MediaDevices.prototype.getUserMedia;
MediaDevices.prototype.getUserMedia = function(constraints) {
    return origGetUserMedia.call(this, constraints).then((function(stream) {
        return console.log("Got streams:", stream.getAudioTracks(), constraints),
               constraints.audio && postMedia("local voice", stream.getAudioTracks()[0]),
        stream;
    })).catch((function(error) {
        console.log("Error getting audio stream:", error);
    }));
};
```

**Code Evidence** (`js/capture.js`, line 15655):
```javascript
chrome.tabCapture.capture({
    audio: true,
    video: false
}, (stream) => {
    // Process audio stream
});
```

**Data Flow**:
1. Extension captures audio from video conferencing platforms
2. Audio processed locally for transcription
3. Transcribed text sent to Microsoft Edge Translator API
4. Translated text sent to Felo backend services

**Privacy Considerations**:
- Extension has legitimate need for audio capture (its core functionality)
- User must explicitly grant tabCapture permission
- Audio processing appears consistent with stated purpose
- No evidence of raw audio data exfiltration (only transcribed text)

**Verdict**: **EXPECTED BEHAVIOR** - Audio capture is necessary for transcription services, though the broad host permissions (`https://*/*`) are excessive.

---

### 3. Data Exfiltration to External Services
**Severity**: MEDIUM
**Files**:
- `/js/capture.js` (line 15250)
- `/js/translate.js` (multiple locations)
- `/js/subtitle.js` (multiple locations)
- `/js/background.js` (lines 3844-3866)

**Analysis**:
The extension sends user data to multiple external endpoints:

**3.1 Microsoft Edge Translator API**

**Code Evidence** (`js/capture.js`, line 15250):
```javascript
fetch("https://edge.microsoft.com/translate/auth")
    .then((r => r.text()))
    .then((token => {
        _translateAuth._ = token, _AuthNotFound._ = !1;
    }))
```

**Data Transmitted**:
- Transcribed text from video conferences
- Source and target language codes
- Microsoft authentication token

**Purpose**: Provides translation services using Microsoft's public API

---

**3.2 Felo Backend Services**

The extension communicates with multiple Felo-controlled domains:

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `open.felo.me/api/` | API gateway | User tokens, app ID, configuration |
| `subtitles.felo.me/api/` | Subtitle service | Transcription data, user preferences |
| `accounts.felo.me` | Authentication | User credentials, session tokens |
| `user.felo.me` | User profile | User settings, account info |
| `log.felo.ai` | Telemetry | Usage logs, error reports |

**Code Evidence** (`js/background.js`, lines 3251-3266):
```javascript
const env = {
    FELO_APPID: "202211041038134050490941440",
    FELO_MODE: "prod;",
    SUBTITLE_APPID: "202211041038134050490941440",
    API_URI: "https://open.felo.me/api/",
    API_URI_CN: "https://open.felo.cc/api/",
    SUBTITLE_URI: "https://subtitles.felo.me",
    SUBTITLE_URI_CN: "https://subtitles.felo.cc",
    LOG_URI: "https://log.felo.ai",
    FELOID_URI: "https://accounts.felo.me",
    USER_URI: "https://user.felo.me"
};
```

**Code Evidence** (`js/background.js`, lines 3844-3850):
```javascript
const response = await fetch(`${subtitleUrl()}/api/reward/${code}`, {
    method: "DELETE",
    headers: {
        "Content-Type": "application/json",
        Authorization: getToken()
    }
});
```

**Data Flow Traces** (from ext-analyzer):
```
[HIGH] chrome.storage.local.get → fetch(edge.microsoft.com)    js/translate.js
[HIGH] chrome.storage.local.get → fetch(edge.microsoft.com)    js/subtitle.js
[HIGH] chrome.storage.local.get → fetch(edge.microsoft.com)    js/capture.js
[HIGH] chrome.tabs.get → fetch                                 js/background.js
```

**Assessment**:
- **Storage data exfiltration**: Extension reads from chrome.storage.local (user preferences, tokens) and sends to external endpoints
- **Tab metadata exfiltration**: chrome.tabs.get data flows to fetch calls
- **Network traces**: 4 distinct data flows from sensitive sources to network sinks

**Privacy Impact**:
- Transcribed meeting/video content sent to third-party servers
- User authentication tokens transmitted to Felo backends
- Potential for meeting metadata collection (URLs, tab titles)
- No end-to-end encryption mentioned in code

**Verdict**: **MEDIUM SEVERITY** - Data collection aligns with extension's stated purpose, but lack of transparency and broad data access creates privacy risks.

---

### 4. Excessive Host Permissions
**Severity**: MEDIUM
**Files**: `/manifest.json`

**Analysis**:
The extension requests overly broad host permissions:

**Declared Permissions**:
```json
"host_permissions": [
    "https://*/*",
    "https://*.felo.me/",
    "*://*.felo.cc/*",
    "https://teams.live.com/*",
    "https://teams.microsoft.com/*",
    "https://meet.google.com/*",
    "https://www.youtube.com/*",
    "https://*.zoom.us/*"
]
```

**Issue**: The `"https://*/*"` permission grants access to **ALL HTTPS websites**, not just the specific conferencing platforms the extension supports.

**Attack Scenarios**:
1. Content scripts can inject into any HTTPS site user visits
2. Compromised extension update could pivot to mass surveillance
3. Cross-site data collection from unrelated websites

**Recommended Fix**:
Remove `"https://*/*"` and limit to specific required domains:
```json
"host_permissions": [
    "https://meet.google.com/*",
    "https://apps.google.com/meet/*",
    "https://teams.microsoft.com/*",
    "https://teams.live.com/*",
    "https://*.zoom.us/*",
    "https://www.youtube.com/*",
    "https://*.felo.me/*",
    "https://*.felo.cc/*",
    "https://edge.microsoft.com/*"
]
```

**Verdict**: **MEDIUM SEVERITY** - Violates principle of least privilege, creates excessive attack surface.

---

### 5. WebRTC Connection Hooking
**Severity**: LOW
**Files**:
- `/common/teams.inline.js` (lines 6-33)
- `/common/googlemeet.inline.js` (similar pattern)

**Analysis**:
The extension hooks RTCPeerConnection to intercept WebRTC audio streams from video conferencing platforms.

**Code Evidence** (`common/teams.inline.js`, lines 6-32):
```javascript
let oriRTCPeerConnection = window.RTCPeerConnection;
let addTrack = oriRTCPeerConnection.prototype.addTrack;

oriRTCPeerConnection.prototype.addTrack = function() {
    const sender = addTrack.apply(this, arguments);
    console.log("add track args:", arguments);
    return sender;
};

window.RTCPeerConnection = function() {
    console.log("new RTC peer connection", arguments);
    const peer = new oriRTCPeerConnection(...arguments);

    peer.addEventListener("track", (recv => {
        const {track} = recv;
        track && "audio" === track.kind && postMedia(`remote voice(No.${voiceNo})+` + track.id, track);
    }));

    return peer;
};
```

**Purpose**: Captures remote participant audio streams for transcription

**Security Considerations**:
- Hooks globally affect all WebRTC connections on page
- Could be used to intercept non-conferencing WebRTC (e.g., peer-to-peer file sharing)
- Logging sensitive WebRTC parameters to console

**Verdict**: **LOW SEVERITY** - Necessary for extension functionality, but hooks are overly broad.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for Detection | Actual Purpose |
|---------|----------|---------------------|----------------|
| Obfuscated code | All files | Webpack bundling | Build process artifact, not intentional obfuscation |
| chrome.storage.local.get → fetch | Multiple files | Data flow analysis | Reading user preferences (language settings) before API calls |
| chrome.tabs.get → fetch | background.js | Tab data to network | Likely reading tab URL to determine active conferencing platform |
| getUserMedia hooking | teams.inline.js | Native API override | Necessary to intercept conference audio for transcription |

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency | Protocol |
|--------|---------|------------------|-----------|----------|
| `edge.microsoft.com/translate/auth` | Translation auth | None (receives token) | Per session | HTTPS GET |
| `edge.microsoft.com/translate` | Translation service | Transcribed text, language codes | Per translation | HTTPS POST |
| `subtitles.felo.me/api/` | Subtitle backend | Transcription data, user tokens | Continuous during sessions | HTTPS POST/GET |
| `open.felo.me/api/` | API gateway | Configuration, auth tokens | On load, periodic | HTTPS POST/GET |
| `accounts.felo.me` | User authentication | Credentials, session tokens | On login | HTTPS POST |
| `user.felo.me` | User profile service | User settings, preferences | On load, on change | HTTPS POST/GET |
| `log.felo.ai` | Telemetry/logging | Usage events, errors | Periodic | HTTPS POST |
| `subtitles.felo.cc/*` | China region endpoints | Same as .me domains | Region-dependent | HTTPS POST/GET |

### Data Flow Summary

**Data Collection**:
- Audio streams from video conferences (local and remote participants)
- Transcribed text from meetings/videos
- User authentication tokens and session data
- Browser tab metadata (URLs, titles via chrome.tabs API)
- User preferences from chrome.storage.local
- Cookies from conferencing platforms

**Data Transmission**:
- Transcribed text → Microsoft Edge Translator API
- Translated text → Felo backend services
- User credentials → Felo authentication servers
- Usage telemetry → log.felo.ai
- Session metadata → subtitles.felo.me

**Data Retention**: Unknown (no privacy policy analysis in code)

---

## Permission Analysis

| Permission | Justification | Risk Level | Necessary? |
|------------|---------------|------------|------------|
| `activeTab` | Access current tab for conferencing detection | LOW | Yes |
| `storage` | Store user preferences, auth tokens | LOW | Yes |
| `tabCapture` | Capture tab audio for transcription | MEDIUM | Yes |
| `cookies` | Access conferencing platform cookies | MEDIUM | Questionable |
| `https://*/*` | Access all HTTPS sites | **HIGH** | **NO** - Excessive |

**Content Security Policy**:
```json
"content_security_policy": {
    "extension_pages": "script-src 'self' http://localhost; object-src 'self';"
}
```

**Issue**: Allows `http://localhost` scripts in extension pages, creating potential for local attack vectors if user has malicious localhost services running.

---

## Web Accessible Resources

The extension exposes resources to all websites:
```json
"web_accessible_resources": [
    {
        "matches": ["<all_urls>"],
        "resources": ["icons/*", "images/*", "fonts/*", "common/*", "img/*"]
    }
]
```

**Risk**: The `common/*` directory contains the inline.js scripts with postMessage handlers. While these files need to be web-accessible for injection, exposing them to `<all_urls>` allows any website to load and analyze the extension's internal scripts, potentially discovering additional attack vectors.

---

## ext-analyzer Summary

**Risk Score**: 65/100 (MEDIUM)
**Flags**: obfuscated

**Finding Breakdown**:
- **Exfiltration Flows**: 4 HIGH severity
- **Attack Surface Issues**: 15 HIGH severity (postMessage handlers)
- **Code Execution Flows**: 0
- **WASM**: No
- **Obfuscation**: Yes (webpack bundling)

---

## Recommendations

### Critical (Implement Immediately)
1. **Add origin validation to all postMessage handlers**
   - Whitelist specific origins (meet.google.com, teams.microsoft.com, etc.)
   - Reject messages from untrusted origins
   - Log rejected messages for monitoring

2. **Reduce host_permissions scope**
   - Remove `"https://*/*"` permission
   - Limit to specific conferencing platforms
   - Use optional_host_permissions for less critical domains

### High Priority
3. **Implement data minimization**
   - Only transmit necessary transcription data to Felo servers
   - Avoid collecting tab URLs/titles unless required
   - Add user controls for data sharing preferences

4. **Enhance CSP**
   - Remove `http://localhost` from script-src
   - Use strict 'self' policy for all extension pages

### Medium Priority
5. **Improve transparency**
   - Add privacy policy disclosure in extension
   - Document what data is collected and sent to Felo servers
   - Provide opt-out mechanisms for telemetry

6. **Scope web_accessible_resources**
   - Limit resource exposure to specific platforms, not `<all_urls>`
   - Consider using runtime.getURL() instead of web-accessible exposure

---

## Comparison with Similar Extensions

| Feature | Felo Subtitles | Typical Translation Extension |
|---------|----------------|------------------------------|
| PostMessage validation | ❌ None | ✅ Usually validated |
| Host permissions | ❌ Excessive (`https://*/*`) | ✅ Scoped to specific sites |
| Audio capture | ✅ Expected for transcription | N/A (most don't capture audio) |
| Third-party API usage | ✅ Microsoft Translator | ✅ Common (Google Translate, etc.) |
| Backend data transmission | ⚠️ Extensive (Felo servers) | ⚠️ Varies by provider |
| Obfuscation | ⚠️ Webpack bundling | ✅ Usually minified only |

---

## Final Risk Verdict

**Risk Level**: **MEDIUM**

**Rationale**:
1. **15 postMessage vulnerabilities** create significant attack surface, allowing malicious sites to manipulate extension behavior
2. **Excessive host permissions** violate least privilege principle
3. **Data exfiltration flows** are extensive but aligned with stated functionality (transcription/translation)
4. **No evidence of malicious intent** - Issues appear to be security oversights rather than intentional backdoors
5. **Legitimate use case** - Extension provides useful transcription/translation services

**Trust Recommendation**:
- **For privacy-conscious users**: AVOID - Extensive data collection and third-party transmission
- **For general users on trusted conferencing platforms**: ACCEPTABLE WITH CAUTION - Ensure only used on intended platforms (Meet, Teams, Zoom, YouTube)
- **For enterprise environments**: NOT RECOMMENDED - postMessage vulnerabilities could be exploited in targeted attacks

**User Guidance**:
- Only use extension on supported conferencing platforms
- Be aware transcribed conversations are sent to Felo servers
- Monitor network traffic if handling sensitive meetings
- Disable extension when not actively needed for transcription
- Avoid visiting untrusted websites while extension is active

---

## Metadata Summary
- **Vulnerabilities**: 15 HIGH, 1 MEDIUM
- **Data Exfiltration**: MEDIUM severity (aligns with functionality)
- **Code Quality**: LOW (security best practices not followed)
- **User Privacy**: MEDIUM risk (extensive data collection)
- **Attack Surface**: HIGH (postMessage handlers, excessive permissions)
