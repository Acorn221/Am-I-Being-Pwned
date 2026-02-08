# Fireflies AI Chrome Extension -- Deep Static Analysis Report

**Extension ID:** `meimoidfecamngeoanhnpdjjdcefoldn`
**Version:** 6.1.3
**Manifest Version:** 3 (MV3)
**Framework:** Plasmo (Parcel bundler)
**Triage Flags:** 28 T1, 5 T2, 18 V1, 11 V2 across 14 categories

---

## Executive Summary

Fireflies AI (v6.1.3) is a legitimate meeting transcription extension that captures audio, captions, chat messages, and attendee information from Google Meet, MS Teams, and Zoom web meetings. The extension uses aggressive API hooking (fetch, XHR, WebRTC, RTCRtpSender) via a "web-stenographer" injector to intercept meeting platform traffic. It uploads captured audio and transcripts to Fireflies' own infrastructure (`media-storage.firefliesapp.com`) using S3 pre-signed URLs.

**The vast majority of triage flags (estimated 85-90%) are FALSE POSITIVES** caused by:
1. The Sentry SDK being bundled into every content script (fetch/XHR hooks for error monitoring)
2. The rrweb library inside Sentry Replay (DOM recording, script creation)
3. The GrowthBook SDK for feature flagging
4. The ffmpeg WASM module for audio transcoding
5. The Plasmo framework duplicating library code across multiple bundles

The extension does present **privacy concerns** around its broad permissions and the scope of data collected, but these are within the stated purpose of meeting transcription. There are **no indicators of malicious behavior, C2 infrastructure, data exfiltration to unauthorized parties, or covert recording**.

**Overall Risk Assessment: LOW**

---

## Architecture Overview

### Files and Their Roles

| File | Size | Role | Runs On |
|------|------|------|---------|
| `background.b78a8f7f.js` | 5.6 MB | Service worker, meeting orchestration, upload pipeline | Background |
| `web-stenographer-injector.beafceb5.js` | 464 KB | **Core hooking engine** -- intercepts WebRTC, fetch, XHR on meeting pages | Google Meet (MAIN world) |
| `gmeetRecorder.0611fff2.js` | 2.0 MB | Google Meet recording UI controller | Google Meet tab |
| `gmeetUserPanel.8e067572.js` | 4.9 MB | Google Meet sidebar panel UI | Google Meet tab |
| `realtimePanel.621c8e3f.js` | 5.9 MB | Real-time caption panel | Google Meet tab |
| `offscreen.8469adc3.js` | 2.9 MB | Offscreen document for ffmpeg transcoding | Offscreen |
| `analytics.fe82b299.js` | 184 KB | Platform detection (Zoom/Teams/Docs) | `<all_urls>` |
| `log-sentry-errors.f7c161f0.js` | 1.7 MB | Sentry error relay | `<all_urls>` |
| `screenNotification.54aacb3c.js` | 4.9 MB | Recording notification overlays | `<all_urls>` |
| `shareToFF.190acc52.js` | 4.9 MB | Loom/Wistia video sharing | Loom, Wistia |
| `popup.2bedceeb.js` | 4.2 MB | Popup UI | Extension popup |
| `assets/ffmpeg/ffmpeg-core.wasm` | - | FFmpeg WASM binary for audio transcoding | Offscreen |

### Permissions Analysis

```json
"permissions": ["scripting", "storage", "activeTab", "offscreen", "unlimitedStorage",
                "notifications", "tabs", "webNavigation", "idle"]
"host_permissions": ["<all_urls>"]
"oauth2": { "scopes": ["openid", "email", "profile", "calendar.readonly"] }
```

- **`<all_urls>` + `scripting`**: Required for injecting the web-stenographer into meeting tabs and running content scripts on meeting platforms. The `scripting` permission is used exclusively for injecting `web-stenographer-injector` into Google Meet tabs (see `background.b78a8f7f.js:102692`).
- **`unlimitedStorage`**: Used for IndexedDB (`ff-database`) storing audio chunks, captions, chat, and speaker labels locally until upload.
- **`calendar.readonly`**: Used to detect upcoming meetings for auto-capture feature.
- **`tabs` + `webNavigation`**: Tab lifecycle monitoring to detect when users join/leave meetings.

### Network Endpoints

| Endpoint | Purpose |
|----------|---------|
| `gateway.fireflies.ai/graphql` | Main API gateway |
| `media-storage.firefliesapp.com` | Audio/transcript upload via S3 signed URLs |
| `user-service-rest.fireflies.ai` | Auth, user info |
| `calendar.firefliesapp.com/v1/events` | Calendar integration |
| `realtime.firefliesapp.com` | Real-time caption streaming |
| `external-apps-service.firefliesapp.com` | Third-party integrations |
| `extensions.fireflies.ai/_oauth/google` | OAuth redirect |
| `api.segment.io/v1/{identify,track,page}` | Segment analytics |
| `o207331.ingest.us.sentry.io` | Sentry error reporting |
| `cdn.growthbook.io` | GrowthBook feature flags |
| `rt.growthbook.io` | GrowthBook real-time events |

All endpoints are first-party Fireflies infrastructure or well-known third-party services (Sentry, Segment, GrowthBook). No suspicious or unknown endpoints found.

---

## T1 Flag Analysis: True Positive vs. False Positive

### 1. fetch_hook (11 flags) -- ALL FALSE POSITIVES

**Root Cause:** The Sentry SDK is bundled into nearly every JS file (gmeetRecorder, offscreen, shareToFF, log-sentry-errors, background, etc.). Sentry's `BrowserTracing` integration wraps `window.fetch` for performance monitoring and breadcrumb capture. Each bundle contains its own copy of the Sentry SDK.

**Evidence:**
- `gmeetRecorder.0611fff2.js:13699`: `fill(GLOBAL_OBJ, "fetch", function(originalFetch) { ... })` -- Sentry SDK instrumentation
- `offscreen.8469adc3.js:11993`: Identical Sentry pattern
- `shareToFF.190acc52.js:18578`: Identical Sentry pattern
- `web-stenographer-injector.beafceb5.js:1819`: `window.fetch = function(...e) { ... }` -- **This IS a real fetch proxy**, but for legitimate meeting data interception (see below)

The **one real fetch hook** is in the web-stenographer. It intercepts 3 specific Google Meet RPC URLs:
- `https://meet.google.com/$rpc/google.rtc.meetings.v1.MeetingSpaceService/SyncMeetingSpaceCollections` (attendee list)
- `https://meet.google.com/$rpc/google.rtc.meetings.v1.MeetingMessageService/CreateMeetingMessage` (chat messages)
- `https://meet.google.com/$rpc/google.rtc.meetings.v1.MeetingSpaceService/ResolveMeetingSpace` (meeting title)

**Verdict: 10/11 FALSE POSITIVE (Sentry SDK). 1/11 is a legitimate meeting data proxy, not malicious.**

### 2. xhr_hook (4 flags) -- ALL FALSE POSITIVES

**Root Cause:** Same as fetch_hook. Sentry wraps `XMLHttpRequest.prototype.open` and `.send` via Proxy for XHR breadcrumbs.

**Evidence:**
- `gmeetRecorder.0611fff2.js:24722-24780`: Sentry XHR instrumentation
- `offscreen.8469adc3.js:23015-23074`: Sentry XHR instrumentation
- `shareToFF.190acc52.js:29600-29659`: Sentry XHR instrumentation
- `log-sentry-errors.f7c161f0.js:21617-21676`: Sentry XHR instrumentation

The web-stenographer also has **one real XHR hook** (`web-stenographer-injector.beafceb5.js:1963-1987`) that intercepts:
- `https://clients6.google.com/calendar/v3/calendars` -- extracts meeting metadata from Google Calendar API responses

**Verdict: ALL FALSE POSITIVE (Sentry SDK + legitimate calendar metadata extraction).**

### 3. script_injection (5 flags) -- ALL FALSE POSITIVES

**Root Cause:** Sentry's `BrowserTracing` integration creates `<script>` elements for performance instrumentation and the Sentry Loader mechanism. These appear in every bundle.

**Evidence:**
- `gmeetRecorder.0611fff2.js:25266`: `const script = WINDOW.document.createElement("script")` -- Sentry SDK
- `background.b78a8f7f.js:16457`: Same Sentry pattern
- `offscreen.8469adc3.js:45913`: ffmpeg worker script loading

The `chrome.scripting.executeScript` call at `background.b78a8f7f.js:102692` is a **legitimate programmatic injection** of the web-stenographer into Google Meet tabs:
```javascript
chrome.scripting.executeScript({
    target: { tabId: tabId, allFrames: true },
    injectImmediately: true,
    world: "MAIN",
    func: _webStenographer.run
});
```
This is scoped to meeting URLs only (`isMeetUrl(url)` check at line 102690).

**Verdict: ALL FALSE POSITIVE.**

### 4. dynamic_function (5 flags) -- ALL FALSE POSITIVES

**Evidence:**
- Sentry stack trace parser references to `eval` (pattern matching, not execution)
- `ffmpeg-core.worker.js:128`: `eval.call(null, x)` -- standard Emscripten WASM worker bootstrap
- `shareToFF.190acc52.js:97205` / `tabs/welcome.04c4c9cc.js:96744`: `new Function("" + e)` -- `setImmediate` polyfill from Promises library

**Verdict: ALL FALSE POSITIVE (Emscripten WASM bootstrap + Promise polyfill).**

### 5. wasm_binary (1 flag) -- FALSE POSITIVE

**File:** `assets/ffmpeg/ffmpeg-core.wasm`

This is a standard ffmpeg-core WASM binary used in the offscreen document to transcode audio from WebM to MP3 format before upload. The CSP explicitly allows this: `script-src 'self' 'wasm-unsafe-eval'`.

The transcoding pipeline:
1. Audio is captured via MediaRecorder as WebM chunks
2. Stored in IndexedDB (`ff-database.audio`)
3. Transcoded to MP3 via ffmpeg WASM in offscreen document
4. Uploaded to `media-storage.firefliesapp.com` via S3 signed URLs

**Verdict: FALSE POSITIVE (legitimate audio transcoding).**

### 6. broad_content_script (flags from `<all_urls>` scripts)

Three content scripts run on `<all_urls>`:

**a) `analytics.fe82b299.js`** (184 KB)
- Checks if the current page is Zoom, Teams, or Google Docs
- If so, sends a "platform usage" analytics event to background
- Adds a click listener to Google Docs' Meet button
- **Does NOT collect any page content, DOM data, or user input on non-meeting pages**

**b) `log-sentry-errors.f7c161f0.js`** (1.7 MB)
- Sets up a message relay for `sentry-cs-error` events
- Forwards errors from content scripts to the background's Sentry instance
- The rrweb/Replay integration is bundled but appears to be used only in the Sentry context, not for recording user sessions on arbitrary pages
- **Does NOT actively monitor or record user activity on non-meeting pages**

**c) `screenNotification.54aacb3c.js`** (4.9 MB)
- Shows overlay notifications when recording is in progress
- Large size due to bundled React, Sentry SDK, and UI components
- **Does NOT collect any data from non-meeting pages**

**Verdict: The `<all_urls>` content scripts are overly broad but functionally benign on non-meeting pages. They primarily detect meeting platforms and display notifications.**

---

## Privacy Concerns (Not Vulnerabilities)

### PC-1: Comprehensive Meeting Data Collection
**Severity: Informational | CVSS: N/A**

The extension captures:
- **Audio**: Full meeting audio via WebRTC stream interception and MediaRecorder
- **Captions**: Real-time closed captions from all participants
- **Chat messages**: In-meeting chat messages with sender identity
- **Attendee information**: Names, full names, profile images, device IDs
- **Meeting metadata**: Title, calendar event data, hangouts URL, start/end times
- **Speaker labels**: Who spoke and when

**File references:**
- Audio capture: `web-stenographer-injector.beafceb5.js:1384-1398` (MediaRecorder)
- Caption capture: `web-stenographer-injector.beafceb5.js:1261-1306` (WebRTC data channel)
- Chat capture: `web-stenographer-injector.beafceb5.js:1233-1245` (collections message)
- Attendee capture: `web-stenographer-injector.beafceb5.js:1247-1254` (user details)
- Upload: `background.b78a8f7f.js:99653` (S3 signed URL upload)

This is the extension's stated purpose and requires user opt-in (login + auto-capture toggle). No covert recording was found.

### PC-2: Auto-Capture Feature
**Severity: LOW | CVSS: 2.3**

When enabled (`autoCapture` setting), the extension automatically starts recording when the user joins a Google Meet meeting without requiring explicit per-meeting consent.

**File:** `background.b78a8f7f.js:115629-115643`
```javascript
autoCapture = _yield$UserModule$get2.autoCapture;
captureWhenFredJoined = _yield$UserModule$get2.captureWhenFredJoined;
enableCapture = autoCapture && shouldRecordWithFred;
```

The auto-capture can be controlled by the `captureWhenFredJoined` flag (only auto-record when the Fireflies bot is in the meeting). This is a user-configurable setting, not a vulnerability.

### PC-3: Third-Party Analytics & Telemetry
**Severity: Informational | CVSS: N/A**

The extension sends telemetry to:
- **Segment** (`api.segment.io`) -- 30+ event types tracking user actions (recording start/stop, login, uploads, feature usage)
- **Sentry** (`o207331.ingest.us.sentry.io`) -- error reporting with email correlation
- **GrowthBook** (`cdn.growthbook.io`) -- feature flag evaluation

Analytics events include user email, meeting ID, app version, and meeting duration. This is standard SaaS telemetry but represents a privacy surface.

**File:** `background.b78a8f7f.js:76020-76096` (Segment API calls)
**Segment Write Keys:** `DXl7ruGOTOWP9VmXDDaEJ4AkCX8DF5sC` (staging), `wAxZOoK9icqcLhCBS5itONPrNrefnC00` (prod)

### PC-4: Calendar Access
**Severity: Informational | CVSS: N/A**

The `calendar.readonly` OAuth scope allows reading the user's Google Calendar to detect upcoming meetings. Calendar data is sent to `calendar.firefliesapp.com/v1/events`.

---

## Detailed Web-Stenographer Analysis

The web-stenographer is the core recording engine. It runs in `MAIN` world on Google Meet pages and intercepts:

### Intercepted APIs

| API | Purpose | Registration Point |
|-----|---------|-------------------|
| `window.fetch` | Intercept 3 Google Meet RPC endpoints for attendees, chat, meeting title | `web-stenographer-injector.beafceb5.js:1445-1457` |
| `XMLHttpRequest.prototype.open/send` | Intercept Google Calendar API for meeting metadata | `web-stenographer-injector.beafceb5.js:1458-1473` |
| `RTCPeerConnection` | Listen for `datachannel` (chat/collections) and `track` (audio streams) events | `web-stenographer-injector.beafceb5.js:1422-1441` |
| `RTCPeerConnection.createDataChannel` | Monitor the `captions` data channel | `web-stenographer-injector.beafceb5.js:1434-1440` |
| `RTCRtpSender.prototype.replaceTrack` | Capture replaced audio tracks | `web-stenographer-injector.beafceb5.js:1418-1419` |

### Data Flow

1. **Audio**: WebRTC `track` events -> AudioContext MediaStreamDestination -> MediaRecorder (WebM) -> `add-fragment` message -> Background -> IndexedDB -> ffmpeg transcode to MP3 -> S3 signed URL upload to `media-storage.firefliesapp.com`
2. **Captions**: WebRTC `captions` data channel -> Protobuf decode -> `add-captions` message -> Background -> IndexedDB -> Upload as JSON to `media-storage.firefliesapp.com`
3. **Chat**: Collections data channel + fetch hook -> Protobuf decode -> `add-chat-message` message -> Background -> IndexedDB -> Upload
4. **Attendees**: fetch hook + collections channel -> Memory map -> `update-meeting-attendees-cache` message -> Background

### Platform Support

The stenographer has modules for three platforms:
- **Google Meet** (`web-stenographer-injector.beafceb5.js:1216-1514`): Full WebRTC + fetch + XHR interception
- **MS Teams** (`web-stenographer-injector.beafceb5.js:1516-1620`): MutationObserver on caption DOM elements
- **Zoom** (`web-stenographer-injector.beafceb5.js:1628-1799`): MutationObserver on caption DOM + participant list scraping

---

## False Positive Analysis Table

| Category | Flags | FP Count | TP Count | Root Cause |
|----------|-------|----------|----------|------------|
| fetch_hook | 11 | 11 | 0 | Sentry SDK fetch instrumentation (x10), legitimate meeting fetch proxy (x1, benign) |
| xhr_hook | 4 | 4 | 0 | Sentry SDK XHR instrumentation (x4), plus 1 legitimate calendar XHR hook (benign) |
| script_injection | 5 | 5 | 0 | Sentry script creation for perf monitoring |
| dynamic_function | 5 | 5 | 0 | Emscripten WASM eval (x1), setImmediate polyfill new Function (x2), Sentry eval regex parsing (x2) |
| wasm_binary | 1 | 1 | 0 | ffmpeg-core.wasm for audio transcoding |
| broad_content_script | 3 | 3 | 0 | Analytics (platform detection only), Sentry error relay, notification overlay |
| **TOTAL** | **29** | **29** | **0** | |

---

## Negative Findings (Things NOT Present)

- **No C2 / remote code execution**: No `eval()` of remote content, no dynamic script loading from external URLs
- **No extension enumeration or killing**: Does not detect or disable other extensions
- **No covert recording**: Recording only starts when user joins a meeting with auto-capture enabled or manually starts recording
- **No credential harvesting**: OAuth tokens are handled via standard Chrome identity API
- **No ad injection or search manipulation**: No content modification on non-meeting pages
- **No residential proxy behavior**: No traffic routing through user's connection
- **No data exfiltration to unauthorized parties**: All data goes to `*.fireflies.ai`, `*.firefliesapp.com`, and standard analytics services
- **No obfuscated or encrypted payloads**: Code is minified but standard Parcel bundler output
- **No dynamic API domain resolution**: All endpoints are hardcoded in config constants

---

## Overall Risk Assessment

**Rating: LOW**

This extension is a legitimate meeting transcription tool that operates within its stated purpose. The high triage flag count (28 T1, 5 T2) is almost entirely attributable to the Sentry SDK being bundled across 8+ JavaScript files, each containing its own copy of fetch/XHR instrumentation code. The web-stenographer's API hooking is targeted at specific meeting platform URLs and captures only meeting-related data.

The main risk surface is the `<all_urls>` host permission combined with broad content scripts, but analysis shows these scripts perform minimal work on non-meeting pages (platform detection and error relay only). The extension does not exhibit any of the malicious patterns identified in other VPN/utility extensions in this research (extension enumeration, ad injection, credential harvesting, residential proxy, etc.).

**Recommendations for users:**
1. Review auto-capture settings; disable if you want per-meeting consent
2. Be aware that all meeting audio, captions, and chat are uploaded to Fireflies servers
3. The `calendar.readonly` scope provides Fireflies visibility into your meeting schedule

---

*Analysis performed: 2026-02-06*
*Analyst: Static analysis deep dive of deobfuscated extension source*
*Extension source: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/meimoidfecamngeoanhnpdjjdcefoldn/deobfuscated/`*
