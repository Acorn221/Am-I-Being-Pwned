# Screencastify (mmeijimgabbpbgpdklnllpncmdofkcpn) -- Security Analysis Report

**Extension:** Screencastify - Screen Video Recorder
**Version:** 4.22.2.5517
**Manifest Version:** 3
**Analysis Date:** 2026-02-06
**Analyst:** Automated deep static analysis

---

## Executive Summary

Screencastify is a legitimate screen recording extension for Chrome with approximately 10M+ users. The triage flagged 28 T1 / 23 T2 / 23 V1 / 38 V2 hits across 19 categories. After deep manual analysis, **the overwhelming majority of flags are FALSE POSITIVES** caused by bundled third-party libraries (Firebase SDK, OpenTelemetry, Pendo analytics, Axios, MobX, ffmpeg-wasm, MediaPipe) and standard webpack boilerplate.

**No malicious intent was identified.** The extension does what it says: records screens/tabs/webcam and uploads to Google Drive / Screencastify's cloud. However, there are several **privacy and attack surface concerns** worth noting, primarily around the breadth of permissions, Pendo session replay capabilities, and exposed API keys.

**Overall Risk Assessment: LOW**

---

## Architecture Overview

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Service Worker | `background.js` | 71,416 | Auth, storage orchestration, message routing, OTel tracing |
| Controller | `controller.js` | 122,028 | Recording UI, MediaRecorder, Pendo agent, ffmpeg processing |
| Popup/Initializer | `initializer.js` | ~80K | Login UI, settings |
| Offscreen Document | `offscreen.js` | ~25K | Offscreen API for tab capture |
| Content Script (Castify) | `extension-installed-post-message.js` | 24,473 | Posts "CFY-INSTALLED" to Castify app domains |
| Content Script (Gmail) | `gmail-script.js` | ~90K | Inserts "Record" / "Insert Video" button in Gmail compose |
| Content Script (Outlook) | `outlook-script.js` | ~90K | Same for Outlook |
| Content Script (YouTube) | `youtube-script.js` | ~84K | Record/share integration on YouTube |
| Content Script (Drive) | `google-drive-script.js` | ~65K | Drive integration |
| Content Script (Slides) | `google-slides-script.js` | ~65K | Slides integration |
| DOM Injection | `base-dom-injection.js` | 100,057 | Injected into recorded tab for webcam overlay, countdown UI |
| Webcam | `webcam.js` | ~85K | Webcam preview/controls |
| WASM: ffmpeg | `assets/ffmpeg/ffmpeg-core.wasm` | 32MB | Video transcoding (faststart, format conversion) |
| WASM: MediaPipe | `assets/mediapipe/vision_wasm_*.wasm` | ~9.5MB each | Selfie segmentation (background blur/replacement) |
| Pendo Agent | `assets/pendo/pendo.debugger.min.js` | 1.7MB | Product analytics, in-app guides, session replay |
| Pendo Replay Worker | `assets/pendo/replay.worker.min.js` | 605 lines | Compresses and ships DOM replay recordings to Pendo servers |

### Permissions Analysis

```json
"permissions": ["alarms", "storage", "tabs", "activeTab", "offscreen",
                "scripting", "unlimitedStorage", "tabCapture", "desktopCapture",
                "webNavigation", "notifications", "system.display"],
"host_permissions": ["<all_urls>", "*://*/*"]
```

- `tabCapture` + `desktopCapture`: Core functionality (screen recording)
- `<all_urls>` host permissions: Required for injecting the recording overlay (`base-dom-injection.js`) into any tab being recorded, and for the webcam iframe overlay
- `scripting`: Used to inject `base-dom-injection.js` into recorded tabs and to clean up on install
- `unlimitedStorage`: Video data stored locally before upload
- `webNavigation`: Monitors tab navigation during recording

The permissions are broad but consistent with the stated purpose of a screen recorder.

---

## Hardcoded Secrets Analysis (12 flagged)

### 1. Firebase Configuration (TRUE POSITIVE -- LOW risk)

**File:** `background.js:47434-47443`

```javascript
firebaseConfig: {
  apiKey: "AIzaSyDraAcnfh7TewzYJS9yt8Togm6_VzB_RJE",
  authDomain: "castify-storage.firebaseapp.com",
  databaseURL: "https://castify-storage.firebaseio.com",
  projectId: "castify-storage",
  storageBucket: "castify-storage.appspot.com",
  messagingSenderId: "37637381719",
  appId: "1:37637381719:web:379c0d7b8ecdfae2bd8d12",
  measurementId: "G-Q9YB5M9JPP"
}
```

**Assessment:** This is a standard Firebase web app configuration. Firebase API keys are designed to be public -- they identify the project but do not grant unauthorized access. Security is enforced via Firebase Security Rules and Firebase Auth on the backend. The `measurementId` is a Google Analytics 4 measurement ID.

**CVSS:** 0.0 (Not a vulnerability)

### 2. Google Analytics Measurement ID (FALSE POSITIVE)

`G-Q9YB5M9JPP` -- Standard GA4 tag for analytics. Public by design.

### 3. Firebase Messaging Sender ID (FALSE POSITIVE)

`37637381719` -- Public identifier for Firebase Cloud Messaging. Not a secret.

### 4. Firebase App ID (FALSE POSITIVE)

`1:37637381719:web:379c0d7b8ecdfae2bd8d12` -- Public Firebase app identifier.

### 5. Manifest Public Key (FALSE POSITIVE)

`manifest.json:231` -- The `key` field is a standard CRX public key used to ensure consistent extension ID across development builds. It is public by design.

### 6-12. Additional "secrets" flagged

The remaining flagged items are:
- **OpenTelemetry service name/version strings** -- Not secrets
- **Firebase project identifiers** (`castify-storage`) -- Public
- **Service endpoint URLs** (log.svc.screencastify.com, api.auth.screencastify.com, etc.) -- Public API endpoints
- **Webpack `new Function("return this")()` pattern** -- Standard globalThis polyfill

**Verdict: 0 of 12 "hardcoded secrets" are actual credential leaks.** All are public-facing Firebase config values, analytics IDs, or API endpoint URLs that are designed to be embedded in client-side code.

---

## XHR/Fetch Hook Analysis

### OpenTelemetry Instrumentation (FALSE POSITIVE)

**Files:** `background.js:10518-10695` (FetchInstrumentation), `background.js:14536+` (XMLHttpRequestInstrumentation)

The extension uses `@opentelemetry/instrumentation-fetch` v0.40.0-sc1 (a Screencastify-customized build) and `@opentelemetry/instrumentation-xml-http-request` to instrument outbound fetch/XHR calls for distributed tracing.

**What it patches:**
- `fetch()` -- wraps to create trace spans with HTTP method, URL, status code
- `XMLHttpRequest.prototype.open` / `.send` -- same tracing

**Where traces go:**
- `https://otel-collector.castify.com/v1/traces` (OTLP trace exporter)

**What URLs are traced:**
Only requests to Screencastify's own API domains (dev, staging, production):
```
/https:\/\/app.castify.com/, /https:\/\/studio-backend.castify.com/,
/https:\/\/api.lti.screencastify.com/, /https:\/\/api.licensing.screencastify.com/,
/https:\/\/api.features.screencastify.com/, /https:\/\/api.content.screencastify.com/,
/https:\/\/api.auth.screencastify.com/, /https:\/\/api.assignment.screencastify.com/,
/https:\/\/umbrella.svc.screencastify.com/, /https:\/\/edit.screencastify.com/,
/https:\/\/submit.svc.screencastify.com/, /https:\/\/dashboard.svc.screencastify.com/,
/http:\/\/localhost:*/, /https:\/\/api.cfy-local.com/
```

**Verdict: FALSE POSITIVE.** This is standard application performance monitoring (APM). The instrumentation only traces requests to Screencastify's own backend services, not arbitrary user traffic. The `OTLPTraceExporterBrowserWithXhrRetry` class at line 10703 is a retry wrapper that falls back from `sendBeacon` to XHR if beacon fails.

---

## Beacon Exfiltration Analysis

### sendBeacon Usage (FALSE POSITIVE)

**All beacon references fall into two categories:**

1. **OpenTelemetry trace export** (`background.js:15501`, `getting-started.js:15515`, etc.):
   ```javascript
   navigator.sendBeacon(t._params.url, new Blob([e], { type: "application/json" }))
   ```
   This is the OTLP exporter shipping trace spans to `otel-collector.castify.com`. Standard APM behavior.

2. **Firebase/Firestore session termination** (`background.js:50387-50388`, `getting-started.js:59715-59716`):
   ```javascript
   r = o.navigator.sendBeacon(t.v.toString(), "")
   ```
   This is the standard Firebase `WebChannel` transport sending a `TYPE=terminate` signal when the session closes. Built into the Firebase JS SDK.

**Verdict: FALSE POSITIVE.** No user data exfiltration via beacons. All beacon traffic goes to Screencastify's own OTLP collector or Firebase infrastructure.

---

## Cookie Access Analysis

### Axios Cookie Utility (FALSE POSITIVE)

**Files:** `options.js:52751-52754`, `outlook-script.js:62579-62582`, `gmail-script.js:62808-62811`, `controller.js:68297-68300`, `initializer.js:55154-55157`

All instances are the standard **Axios HTTP library** cookie read/write utility (`document.cookie = a.join("; ")` / `document.cookie.match(...)`). This is used internally by Axios for CSRF token handling. The extension does NOT use the `chrome.cookies` API.

### Firebase Cookie (FALSE POSITIVE)

**File:** `background.js:47862`, and equivalent in all script bundles:
```javascript
e = document.cookie.match(/__FIREBASE_DEFAULTS__=([^;]+)/)
```
Standard Firebase SDK code that reads its own configuration cookie. Present in all Firebase web apps.

### Pendo Cookie Management (FALSE POSITIVE)

**File:** `controller.js:106344-106353`

Pendo reads/writes its own analytics cookies (`_pendo_*`) for visitor identification and guide state. This is standard Pendo SDK behavior.

**Verdict: FALSE POSITIVE.** No third-party cookie harvesting. All cookie access is by bundled libraries (Axios, Firebase, Pendo) for their own session management.

---

## WASM Binary Analysis

### 1. ffmpeg-core.wasm (32 MB) -- FALSE POSITIVE

**File:** `assets/ffmpeg/ffmpeg-core.wasm`
**Loaded by:** `controller.js:102073`
```javascript
wasmURL: chrome.runtime.getURL("assets/ffmpeg/ffmpeg-core.wasm")
```

This is the **ffmpeg.wasm** library used for client-side video processing (faststart optimization, format conversion). The binary contains standard ffmpeg codec strings (HTTP proxy references are part of ffmpeg's network module, not indicative of proxy behavior).

### 2-3. MediaPipe Vision WASM (9.5 MB each) -- FALSE POSITIVE

**Files:** `assets/mediapipe/vision_wasm_internal.wasm`, `assets/mediapipe/vision_wasm_nosimd_internal.wasm`
**Loaded by:** `controller.js:96666-96669`, `webcam.js:84523-84526`
**Model:** `assets/mediapipe/selfie_segmenter.tflite` (250 KB)

These are Google's **MediaPipe Vision** WASM binaries used for selfie segmentation (background blur/replacement during webcam recording). The `selfie_segmenter.tflite` model confirms this purpose. Two variants are provided: SIMD and non-SIMD for browser compatibility.

**Verdict: FALSE POSITIVE.** All WASM binaries are well-known open-source libraries (ffmpeg, MediaPipe) used for legitimate video processing functionality.

---

## Dynamic Eval / CSP Analysis

### webpack `new Function("return this")()` (FALSE POSITIVE)

**File:** `background.js:47362`
```javascript
return this || new Function("return this")()
```
Standard webpack globalThis polyfill. Present in virtually all webpack-bundled extensions.

### protobuf.js `eval("quire".replace(/^/, "re"))` (FALSE POSITIVE)

**File:** `background.js:24118`
```javascript
var mod = eval("quire".replace(/^/, "re"))(moduleName);
```
This is the well-known `@protobufjs/inquire` module that obfuscates `require` to avoid bundler warnings. It's dead code in a browser context (the try/catch silently fails). Used by Firebase's protobuf serialization.

### CSP: `wasm-unsafe-eval` (FALSE POSITIVE)

**File:** `manifest.json:229`
```json
"extension_pages": "script-src 'self' 'wasm-unsafe-eval';"
```
Required for ffmpeg.wasm and MediaPipe WASM execution. This is the recommended MV3 approach for WASM -- it only allows WASM instantiation, not arbitrary JS eval.

**Verdict: FALSE POSITIVE.** No real dynamic code execution. All instances are standard library patterns.

---

## Externally Connectable Analysis

### Domains That Can Message This Extension

**File:** `manifest.json:198-209`

```json
"externally_connectable": {
  "matches": [
    "https://app.castify.com/*",
    "https://app.cfy-local.com/*",
    "https://app.cfy-stage.com/*",
    "https://app.dev1.screencastify.com/*",
    "https://app.staging.screencastify.com/*",
    "https://app.screencastify.com/*",
    "http://localhost:4205/*",
    "http://localhost:8080/*"
  ]
}
```

**Message handlers** (`background.js:71168-71360`):

1. **`bg:isInstalled` / `mv3:isInstalled`** -- Version check, returns extension version
2. **`mv3:openExtension`** -- Opens the popup
3. **`mv3:openController`** -- Opens the recording controller tab
4. **`mv3:extensionAuth:signInWithToken`** -- Accepts a Firebase custom token or Google OAuth tokens to sign the user in from the web app
5. **`mv3:extensionAuth:signout`** -- Signs the user out

### Concern: `http://localhost:4205/*` and `http://localhost:8080/*`

These localhost entries allow any local web server on ports 4205 and 8080 to send messages to the extension. This is clearly a **development convenience** that was left in the production build.

**Risk:** If an attacker can run a local web server on port 4205 or 8080 (e.g., via a malicious app, or if the user is a developer with something running on those ports), they could send `mv3:extensionAuth:signInWithToken` with a crafted token. However, this would require:
1. A valid Firebase custom token for the `castify-storage` project, AND
2. Local access to the machine

**CVSS: 2.0** (AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N) -- Very low real-world risk.

---

## Pendo Analytics Integration

### Session Replay (INFORMATIONAL -- Privacy Concern)

**Files:** `controller.js:105428+` (Pendo agent), `assets/pendo/replay.worker.min.js`

Screencastify embeds the full Pendo agent which includes:
- **Page/feature analytics** -- Tracks which UI elements users interact with (via `data-pendo-event` attributes)
- **In-app guides** -- Tooltips and walkthroughs for user onboarding
- **Session replay** -- Records DOM mutations and ships them to Pendo's servers (compressed via the replay worker)

The Pendo session replay records the extension's own UI (controller page, options page), NOT the content of recorded videos or arbitrary web pages. The recording is DOM-based (text content, element positions) not screenshot-based.

**Privacy concern:** Pendo receives information about how users interact with the Screencastify UI, including potentially visible user email addresses, video titles, and navigation patterns within the extension's own pages.

**CVSS: 0.0** (This is disclosed product analytics, not a vulnerability, but worth noting for privacy-conscious users)

---

## Video Data Flow

The screen recording pipeline works as follows:

1. **Capture:** `chrome.desktopCapture.chooseDesktopMedia()` or `chrome.tabCapture.getMediaStreamId()` gets a media stream
2. **Record:** `MediaRecorder` encodes the stream as WebM (VP8/VP9)
3. **Store locally:** Chunks stored via IndexedDB (`LT.recordingData.add()`)
4. **Process:** ffmpeg.wasm applies faststart optimization
5. **Upload:** Video uploaded to Google Drive (`googleapis.com/upload/drive/v3`) or Screencastify's content service (`api.content.screencastify.com`)

There is no evidence of video data being sent to unauthorized endpoints. Uploads go exclusively to:
- `https://www.googleapis.com/upload/drive/v3` (Google Drive)
- `https://www.googleapis.com/upload/drive/v2` (Google Drive legacy)
- `https://api.content.screencastify.com/content` (Screencastify cloud)

---

## Firebase Remote Config

**File:** `background.js:63600-63866`

The extension includes Firebase Remote Config SDK (v0.6.0). This allows Screencastify to remotely toggle features and adjust settings. This is standard Firebase functionality -- the config values are fetched from Firebase's servers and cached in IndexedDB.

**No evidence of server-controlled behavior changes** that could enable malicious functionality. The Remote Config is used for feature flags and settings, not for downloading or executing code.

---

## Content Script Analysis

### Gmail Script (`gmail-script.js`)

Injects a Screencastify button into Gmail's compose toolbar:
- Adds "Start New Recording", "Insert a video", and "Turn Email into Video" options
- Uses MutationObserver to detect new compose windows (`div[role="dialog"]`)
- Inserts video thumbnails and links into email body when user selects a video
- Does NOT read email content, contacts, or any Gmail data

### YouTube Script (`youtube-script.js`)

Similar integration for YouTube -- adds recording/sharing functionality. Does NOT scrape video data or user behavior on YouTube.

### Outlook Script (`outlook-script.js`)

Same pattern as Gmail -- inserts Screencastify buttons into Outlook's compose UI.

### Google Drive/Slides Scripts

Integration for browsing/managing Screencastify videos from Drive and inserting into Slides presentations.

### Extension Installed Script (`extension-installed-post-message.js`)

**File:** Line 24470:
```javascript
window.postMessage("CFY-INSTALLED", window.location.origin)
```

This script runs on Castify/Screencastify app domains only and simply posts a "CFY-INSTALLED" message so the web app can detect the extension is installed. The message is sent to `window.location.origin` (same-origin), not to any external target.

---

## False Positive Analysis Table

| # | Category | Flag | Actual Source | Verdict | Reason |
|---|----------|------|---------------|---------|--------|
| 1 | hardcoded_secret | Firebase apiKey | Firebase SDK config | FP | Public client-side key by design |
| 2 | hardcoded_secret | Firebase appId | Firebase SDK config | FP | Public identifier |
| 3 | hardcoded_secret | measurementId | GA4 tag | FP | Public analytics ID |
| 4 | hardcoded_secret | messagingSenderId | Firebase config | FP | Public FCM identifier |
| 5 | hardcoded_secret | projectId | Firebase config | FP | Public project name |
| 6 | hardcoded_secret | storageBucket | Firebase config | FP | Public bucket name |
| 7 | hardcoded_secret | databaseURL | Firebase config | FP | Public Realtime DB URL |
| 8 | hardcoded_secret | authDomain | Firebase config | FP | Public auth domain |
| 9 | hardcoded_secret | Manifest key | CRX public key | FP | Public by design |
| 10 | hardcoded_secret | Service URLs | API endpoints | FP | Public API URLs |
| 11 | hardcoded_secret | OTel collector URL | Trace endpoint | FP | Public observability endpoint |
| 12 | hardcoded_secret | uninstallUrl | Google Forms URL | FP | Public survey link |
| 13 | xhr_hook | XMLHttpRequest.prototype.open/send | OpenTelemetry instrumentation | FP | APM tracing, own domains only |
| 14 | fetch_hook | fetch() wrap | OpenTelemetry instrumentation | FP | APM tracing, own domains only |
| 15 | beacon_exfil | navigator.sendBeacon | OTel exporter + Firebase WebChannel | FP | Trace export + session teardown |
| 16 | cookie_access | document.cookie read/write | Axios, Firebase, Pendo SDKs | FP | Library-internal cookie management |
| 17 | wasm_binary | ffmpeg-core.wasm | ffmpeg.wasm | FP | Video transcoding |
| 18 | wasm_binary | vision_wasm_internal.wasm | MediaPipe Vision | FP | Selfie segmentation |
| 19 | wasm_binary | vision_wasm_nosimd_internal.wasm | MediaPipe Vision (no SIMD) | FP | Selfie segmentation fallback |
| 20 | csp_unsafe_eval | wasm-unsafe-eval | manifest.json CSP | FP | Required for WASM, MV3 standard |
| 21 | dynamic_eval | `new Function("return this")()` | webpack globalThis polyfill | FP | Standard bundler pattern |
| 22 | dynamic_eval | `eval("quire".replace(/^/,"re"))` | protobuf.js inquire | FP | Dead code in browser context |
| 23 | externally_connectable_many | 8 domain patterns | Screencastify domains + localhost | TP-LOW | Dev localhost entries left in prod |
| 24 | innerHTML | React SVG namespace, dangerouslySetInnerHTML | React runtime | FP | Standard React DOM operations |

---

## True Positive Findings

### Finding 1: Development Localhost in externally_connectable (LOW)

**CVSS: 2.0** (AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N)

**File:** `manifest.json:207-208`
```json
"http://localhost:4205/*",
"http://localhost:8080/*"
```

**Description:** The production extension allows any web page served from localhost on ports 4205 and 8080 to send messages to the extension via `chrome.runtime.sendMessage`. While the message handlers validate origin against `a.webAppUrl` (which is `https://app.screencastify.com`), the `bg:isInstalled` and `mv3:isInstalled` handlers at line 71170-71174 respond to ANY external sender without origin validation.

**PoC Scenario:**
1. Attacker runs malicious local server on port 8080
2. Serves a page that calls `chrome.runtime.sendMessage("mmeijimgabbpbgpdklnllpncmdofkcpn", {type: "mv3:isInstalled"})`
3. Receives `{success: true, version: "4.22.2.5517"}` confirming extension presence

**Impact:** Extension detection / fingerprinting. The auth-related handlers (`signInWithToken`) DO validate origin, so auth abuse is not possible via this vector.

**Recommendation:** Remove localhost entries from production builds, or add origin validation to all external message handlers.

### Finding 2: Broad `<all_urls>` Host Permission (INFORMATIONAL)

**CVSS: N/A** (Design concern, not vulnerability)

**File:** `manifest.json:52-55`
```json
"host_permissions": ["<all_urls>", "*://*/*"]
```

**Description:** The extension requests access to all URLs. This is functionally required for injecting the recording overlay (`base-dom-injection.js`) into any tab being recorded, and for the webcam iframe. However, it grants the extension theoretical access to read/modify any page.

**Impact:** If the extension were compromised (e.g., via a supply chain attack on a dependency), the broad permissions would maximize the blast radius.

### Finding 3: Pendo Session Replay in Extension UI (INFORMATIONAL)

**CVSS: N/A** (Privacy concern)

**Files:** `controller.js:105428+`, `assets/pendo/replay.worker.min.js`

**Description:** The Pendo analytics agent includes session replay capabilities. The replay worker compresses DOM recordings and ships them to Pendo's servers. This captures the extension's own UI (recording controls, video list, settings), which may include user email addresses, video titles, and interaction patterns.

**Impact:** User behavior within the extension UI is sent to a third-party analytics provider (Pendo). Users are likely not explicitly informed of this level of monitoring.

---

## Summary of Endpoints

| Endpoint | Purpose | Suspicious? |
|----------|---------|-------------|
| `https://app.screencastify.com` | Web app | No |
| `https://log.svc.screencastify.com/api/logService/log` | Application logging | No |
| `https://api.features.screencastify.com/features` | Feature flags | No |
| `https://api.content.screencastify.com/content` | Video content API | No |
| `https://api.auth.screencastify.com/auth` | Authentication | No |
| `https://api.licensing.screencastify.com/licensing` | License management | No |
| `https://api.user.screencastify.com/user` | User profile | No |
| `https://api.notifications.screencastify.com/notifications` | Push notifications | No |
| `https://otel-collector.castify.com/v1/traces` | OpenTelemetry traces | No |
| `https://castify-storage.firebaseio.com` | Firebase Realtime DB | No |
| `https://castify-storage.appspot.com` | Firebase Storage | No |
| `https://www.googleapis.com/upload/drive/v3` | Google Drive upload | No |
| `https://firebaseremoteconfig.googleapis.com` | Firebase Remote Config | No |
| Pendo CDN (via pendo agent) | Analytics/session replay | Privacy concern |

---

## Overall Risk Assessment

### **LOW**

Screencastify is a legitimate, well-built screen recording extension. All 19 flagged triage categories resolve to false positives caused by standard third-party libraries (Firebase, OpenTelemetry, Pendo, Axios, MobX, ffmpeg.wasm, MediaPipe, protobuf.js, webpack).

**Key findings:**
- **0 hardcoded secrets** that pose a security risk (all are public Firebase/GA config)
- **0 data exfiltration endpoints** beyond expected analytics (Pendo, Firebase Analytics, OTel)
- **0 XHR/fetch hooks** intercepting user traffic (OTel only traces Screencastify's own API calls)
- **0 cookie harvesting** (all cookie access is by bundled libraries for their own use)
- **3 WASM binaries** are well-known open-source libraries (ffmpeg, MediaPipe)
- **1 minor issue:** localhost entries in `externally_connectable` (very low risk)
- **1 privacy concern:** Pendo session replay on extension UI pages

**No indicators of malware, data harvesting, residential proxy behavior, extension enumeration, ad injection, or any of the malicious patterns seen in other extensions analyzed in this project.**
