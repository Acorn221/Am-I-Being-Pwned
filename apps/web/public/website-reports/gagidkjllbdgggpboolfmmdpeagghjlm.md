# Vulnerability Report: Arcade - AI Interactive Product Demos

## Extension Metadata

- **Extension Name**: Arcade: AI Interactive Product Demos
- **Extension ID**: gagidkjllbdgggpboolfmmdpeagghjlm
- **Version**: 1.8.3
- **Users**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Arcade is a legitimate screen recording and interactive demo creation tool designed to help teams create product demonstrations. The extension captures user interactions, screenshots, and optionally video/audio to generate step-by-step product demos. While the extension has **extensive and invasive permissions**, all capabilities align with its stated purpose of creating interactive product demos. The extension uses proper security practices including Sentry error tracking and Segment analytics with OAuth2 authentication.

**Overall Risk: CLEAN**

The extension is privacy-invasive by design (screen recording, tab capture, cookie access) but serves its legitimate intended purpose. Users should be aware that this extension captures comprehensive interaction data when actively recording demos.

## Vulnerability Details

### 1. Extensive Permissions (CLEAN - Intentional Functionality)

**Severity**: INFORMATIONAL
**Status**: CLEAN - Required for core functionality
**Files**: manifest.json

**Details**:
The extension requests highly invasive permissions:
- `<all_urls>` host permissions
- `storage`, `unlimitedStorage`
- `activeTab`, `tabs`, `tabCapture`
- `scripting`, `webNavigation`
- `system.display`, `offscreen`
- `webRequest` (for CSP inspection)
- Optional: `cookies`, `nativeMessaging`

**Analysis**:
All permissions are necessary for the extension's core functionality:
- **Tab capture & screen recording**: Required to capture user interactions and generate demos
- **WebRequest**: Used only to inspect Content Security Policy headers during embed diagnostics
- **Cookies**: Optional permission for capturing full page context during demo recording
- **System.display**: Used to determine optimal recording window sizes

**Code Evidence**:
```javascript
// background.js:29717 - CSP inspection via webRequest
chrome.webRequest.onHeadersReceived.addListener(n, {
  urls: ["<all_urls>"],
  types: ["main_frame"],
  tabId: e
}, ["responseHeaders"])

// background.js:30035 - Cookie capture during recording
const n = await chrome.cookies.getAll({
  url: e
});
```

**Verdict**: CLEAN - Permissions align with intended functionality

---

### 2. Screen Recording & Data Collection (CLEAN - Core Feature)

**Severity**: INFORMATIONAL
**Status**: CLEAN - Transparent core functionality
**Files**: background.js, recording-manager.js

**Details**:
The extension captures extensive user interaction data during demo recording:
- Screenshots at 500ms intervals during recording
- Mouse clicks, drags, scrolls, keypresses
- Tab navigation and page HTML
- Optional camera/microphone streams
- Optional cookies for page context

**Analysis**:
Recording is user-initiated and clearly indicated:
- Countdown timer before recording starts
- Visual recording indicators
- Keyboard shortcuts to start/stop/pause recording
- Data is only captured when user actively creates a demo

**Code Evidence**:
```javascript
// background.js:27964 - Screenshot capture during active recording
this.screenshotTimer = setTimeout(this.takeScreenshot, 500)

// background.js:28181 - Tab capture API usage
const t = chrome.tabCapture.getMediaStreamId

// Recording state management shows user control
this.status = Lu.Recording  // Only when user initiates
```

**Verdict**: CLEAN - User-initiated, purpose-aligned functionality

---

### 3. Data Upload to Arcade Servers (CLEAN - Expected Behavior)

**Severity**: INFORMATIONAL
**Status**: CLEAN - Necessary for service delivery
**Files**: background.js, popup.js

**Details**:
Recorded demo data is uploaded to Arcade's servers:
- API endpoint: `https://app.arcade.software/api/extension/*`
- Worker URL: `https://worker.arcade.software`
- CDN: `https://cdn.arcade.software`

Data uploaded includes:
- Screenshots and video recordings
- Captured events (clicks, scrolls, inputs)
- Page HTML and cookies (if user enabled)
- Metadata about the recording session

**Analysis**:
Upload is expected and necessary:
- Users explicitly create demos to share/host them
- Upload happens after recording completes
- Data is sent to process and generate the interactive demo
- No background/silent data collection detected

**Code Evidence**:
```javascript
// background.js:28404 - Payload sent to Arcade after recording
this.sendPayloadToFlowBuilderUploadTab({
  ...m,
  flowId: o
})

// Defined upload endpoint
const ha = "https://app.arcade.software"

// Recording data structure includes user-captured content
capturedEvents: k,
screenshots: S,
capturedHTML: Object.fromEntries(O.entries())
```

**Verdict**: CLEAN - Expected service behavior

---

### 4. Analytics & Error Tracking (CLEAN - Standard Telemetry)

**Severity**: INFORMATIONAL
**Status**: CLEAN - Standard SDKs
**Files**: background.js, popup.js

**Details**:
The extension uses legitimate third-party services:
- **Sentry**: Error tracking and crash reporting
- **Segment**: Product analytics with OAuth2 authentication

**Analysis**:
Both are industry-standard, privacy-respecting services:
- Sentry: Only sends error/crash data for debugging
- Segment: Tracks usage metrics (feature usage, not user data)
- OAuth2 implementation follows best practices
- No evidence of tracking user browsing outside recording sessions

**Code Evidence**:
```javascript
// background.js:24241 - Segment OAuth2 authentication
grantType = "client_credentials"
this.authServer = e.authServer ?? "https://oauth2.segment.io"

// Sentry configuration
Sentry Logger - standard error tracking

// Analytics track events, not user content
zu.track("Created Upload Tab", {})
zu.track("Record", { type: "screenshot" })
```

**Verdict**: CLEAN - Standard, ethical telemetry practices

---

### 5. Content Script Injection (CLEAN - Required Functionality)

**Severity**: INFORMATIONAL
**Status**: CLEAN - Purpose-aligned
**Files**: manifest.json, recording-manager.js, link-expander.js

**Details**:
Content scripts run on all pages:
- `recording-manager.js`: Captures user interactions during recording
- `link-expander.js`: Expands Arcade demo links embedded in Gmail, Outlook, GitHub

**Analysis**:
Content scripts are benign:
- Recording manager only active during user-initiated recording
- Link expander enhances Arcade links in specific apps (opt-in feature)
- No evidence of ad injection, XHR hooking, or malicious behavior
- Scripts use message passing for communication (no eval/Function abuse)

**Code Evidence**:
```javascript
// manifest.json - Targeted content scripts
{
  "matches": ["<all_urls>"],
  "js": ["recording-manager.js"],
  "all_frames": true  // Required to capture iframe interactions
},
{
  "matches": ["https://mail.google.com/*", "https://outlook.live.com/*"],
  "js": ["link-expander.js"]  // Only for link expansion
}
```

**Verdict**: CLEAN - Functionality matches description

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` usage | Multiple files | React/Zod library code for UI rendering, not user-controlled injection |
| `XMLHttpRequest` | ffmpeg-core.js | Part of FFmpeg WASM library for video encoding |
| `fetch` calls | link-expander.js | Fetching Arcade demo metadata from CDN |
| `Function.prototype.toString` | background.js | Sentry SDK instrumentation for error tracking |
| Password field detection | recording-manager.js | Detecting password fields to AVOID capturing sensitive input |
| Cookie API usage | background.js | Optional feature for capturing page context (user must enable) |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://app.arcade.software/api/extension/image` | Upload screenshots | Image data, flow ID, click positions |
| `https://app.arcade.software/api/extension/*` | Demo creation | Recording data, metadata |
| `https://worker.arcade.software` | Background processing | Video encoding tasks |
| `https://cdn.arcade.software/fonts/*` | Font resources | None (static assets) |
| `https://oauth2.segment.io/token` | Analytics auth | OAuth2 client credentials |
| `https://api.segment.io/v1/batch` | Analytics events | Usage metrics (anonymized) |
| Sentry endpoints | Error tracking | Error reports, stack traces |

## Data Flow Summary

### Recording Flow
1. **User initiates recording** → Extension shows countdown
2. **During recording** → Captures clicks, scrolls, keypresses, screenshots every 500ms
3. **User stops recording** → Processing begins (video encoding, data packaging)
4. **Upload to Arcade** → Sends recording data to create interactive demo
5. **Demo available** → User can view/share via Arcade platform

### Optional Data Collection
- **Cookies**: Only if user enables, captures cookies from recorded tabs
- **HTML**: Captures page HTML for specific demo types
- **Video/Audio**: Only if user enables camera/mic recording

### Privacy Considerations
- ✅ Recording is user-initiated and clearly indicated
- ✅ No passive background surveillance
- ✅ Data uploaded serves stated purpose (demo creation)
- ✅ No evidence of selling/sharing user data
- ⚠️ Users should be aware: when recording, ALL interactions on that tab are captured

## Overall Risk Assessment

**Risk Level**: CLEAN

**Justification**:
Arcade is a legitimate productivity tool that functions exactly as advertised. While it requires extensive permissions and captures invasive data (screenshots, interactions, cookies), this is **necessary and transparent** for its core purpose of creating interactive product demos. The extension:

1. **Only captures data during active user-initiated recording sessions**
2. **All permissions align with documented features**
3. **Uses industry-standard security practices** (OAuth2, Sentry, proper CSP)
4. **No evidence of malicious behavior** (no ad injection, XHR hooking, extension killing, proxy infrastructure, etc.)
5. **Data upload serves legitimate purpose** (generating shareable demos)

**Recommendation**: CLEAN with disclosure

Users should be informed that when actively recording demos, this extension captures comprehensive interaction data including screenshots, clicks, keystrokes, and optionally cookies/video/audio. This is expected behavior for a screen recording tool but users should avoid recording sensitive information they don't want uploaded to Arcade's servers.

## Notes

- Extension properly uses offscreen documents for media capture (MV3 best practice)
- Implements proper error handling and retry logic
- Uses Zod for runtime schema validation
- FFmpeg WASM for local video encoding before upload
- Segment analytics uses proper OAuth2 authentication
- Sentry hooks are standard SDK implementation (not malicious)

---

**Analyst verdict**: This extension serves its intended purpose without deception. The invasive permissions are necessary for screen recording functionality and are transparent to users who understand they're installing a demo creation tool.
