# Vulnerability Report: Honorlock

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Honorlock |
| Extension ID | hnbmpkmhjackfpkpcbapafmpepgmmddc |
| Version | 6.67.0.0 |
| Manifest Version | 3 |
| Users | ~3,000,000 |
| Category | Online Exam Proctoring |
| Overall Risk | **CLEAN** |

## Executive Summary

Honorlock is an online exam proctoring extension used by universities and educational institutions to monitor students during exams. The extension requires extremely broad permissions (desktopCapture, tabs, management, history, webRequest, scripting, contentSettings, `<all_urls>`) and performs highly invasive operations including: disabling other extensions, monitoring all web traffic, capturing screen/webcam, detecting devtools, blocking keyboard shortcuts, preventing copy/paste, deleting browser history, and blocking tab creation during exams.

**Despite being extremely invasive, all functionality is directly tied to its legitimate proctoring purpose.** The extension only communicates with `app.honorlock.com` and `prep.honorlock.com` -- no third-party analytics, market intelligence SDKs, proxy infrastructure, or suspicious external domains were found. There is no evidence of data exfiltration beyond what is required for proctoring, no ad/coupon injection, no obfuscated remote code loading, and no residential proxy behavior. The CSP is strict (`script-src 'self'; object-src 'self'`). The code is minified/bundled (webpack) but not obfuscated.

## Vulnerability Details

### 1. Extension Enumeration and Force-Disabling Other Extensions
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js` (InstalledExtensionsControl class)
- **Code:**
  ```js
  getInstalledExtensions(){return ct(this,null,function*(){const t=yield chrome.management.getAll()...})}
  _disableAllBlockedExtensions(){return ct(this,null,function*(){this._blockedExtensions&&this._blockedExtensions.forEach(t=>ct(this,null,function*(){yield chrome.management.setEnabled(t.id,!1)...}))})}
  ```
- **Verdict:** The extension enumerates all installed extensions via `chrome.management.getAll()` and disables those on a blocklist. The blocklist comes from the Honorlock server (via `blocked_extension_query_results` message). This is standard proctoring behavior to prevent cheating extensions. Unknown extensions are also flagged and reported.

### 2. Full Web Traffic Monitoring During Exams
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js` (NetworkRequestLogger class, ProctoringActions class)
- **Code:**
  ```js
  chrome.webRequest.onCompleted.addListener(this._boundLogCompletedRequest, {urls:["<all_urls>"]})
  // Logs host of every web request (excluding images, stylesheets, scripts, fonts, and Honorlock/Sentry/LiveChat/Pusher/Twilio/Stripe domains)
  this.cameraWindowControl.sendMessageToWebcam("log_network_request",{network_request_details:{host:a}})
  ```
- **Verdict:** During active exams, all web navigation is logged (host only, not full URL content) and sent to the proctoring webcam window for transmission to Honorlock servers. Tab URL changes are also tracked. Web traffic logging is enabled/disabled via `enableTrackWebTraffic`/`disableTrackWebTraffic`, controlled by exam state. This is standard exam proctoring to detect if students browse to unauthorized sites.

### 3. Browser History Deletion
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js`
- **Code:**
  ```js
  deleteRange(t){chrome.history.deleteRange({startTime:t.valueOf(), endTime:Date.now()...})}
  clearExamBrowserHistory(t){this.deleteRange(t.data.startTime)}
  ```
- **Verdict:** Deletes browser history created during the exam period (from exam start time to current time). This is a privacy feature to remove exam-related browsing data after completion.

### 4. DevTools Detection and Exam Pausing
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js` (BrowserGuard class)
- **Code:**
  ```js
  this._handleDeveloperToolsOnConnect = t => {
    t.name === "hl-developer-tools-connection" && (
      this._SYNC_openDeveloperToolsCount = this._openDeveloperToolsCount + 1,
      ...sendMessage({action:"devtools_open"})
    )
  }
  // Also detects devtools via devtools-tabid-* port connections
  _devToolsPauseTabs(t) { /* pauses exam if devtools opened on exam tab */ }
  ```
- **Verdict:** Monitors for DevTools connections via `runtime.onConnect`. When DevTools are opened during an active exam, the exam is paused and the event is logged. This is standard anti-cheating behavior.

### 5. Keyboard Shortcut Detection and Blocking
- **Severity:** LOW (by design for proctoring)
- **Files:** `js/hotkey_detection.js`, `js/shortcut_detection.js`
- **Code:**
  ```js
  document.addEventListener("keyup", this._onKeyUp)
  document.addEventListener("keydown", this._onKeyDown)
  // Captures: shift+i (devtools shortcut) and other key sequences
  chrome.runtime.sendMessage({message:"detected_shortcut_usage", data:C})
  ```
- **Verdict:** Monitors keydown/keyup events to detect use of keyboard shortcuts (like Shift+I for DevTools) during proctored exams. Detected shortcuts are reported to the background script. No evidence of full keystroke logging -- only specific shortcut combinations are tracked.

### 6. Copy/Paste Prevention
- **Severity:** LOW (by design for proctoring)
- **Files:** `js/disable_copy_paste.js`
- **Code:**
  ```js
  this._listenedEvents = {contextmenu:"Right Click", copy:"Copy", paste:"Paste", cut:"Cut"}
  this._blockDisabledEvent = R => this._eventHandlersMemo[R] || (this._eventHandlersMemo[R] = w => {
    w.preventDefault(), chrome.runtime.sendMessage({message:"blocked_copy_paste", event_name:...})
  })
  ```
- **Verdict:** Blocks copy, paste, cut, and right-click context menu during exams when the `disable_copy_paste` toggle is enabled. Events are reported but content is not captured.

### 7. Tab Blocking and Forced Focus During Exams
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js` (AllowedBrowserAccess class, BrowserGuard fullscreen/forceFocus)
- **Code:**
  ```js
  enableBlockNewTabs() { u().tabs.onUpdated.addListener(this._closeTabOnUpdatedHandler)... }
  // Closes any new tabs not on the allowed list during exam
  // Forces fullscreen and focus back to exam tab
  ```
- **Verdict:** During active exams, new tab creation is blocked (tabs not on the allow list are immediately closed). The extension also forces the browser to stay focused on the exam tab and maintains fullscreen mode. Standard lockdown browser behavior.

### 8. Screen and Webcam Capture
- **Severity:** LOW (by design for proctoring)
- **Files:** `background.js`, `js/webcam.js`
- **Code:**
  ```js
  chrome.desktopCapture.chooseDesktopMedia(d, h, A => {d(A)})
  // Camera managed via app.honorlock.com/webapp/camera window
  chrome.contentSettings.camera.set({primaryPattern: l, setting: "allow"})
  ```
- **Verdict:** Uses `chrome.desktopCapture` API (requires user consent dialog) for screen recording and opens a camera window via `app.honorlock.com/webapp/camera`. Camera content settings are managed to ensure webcam access. All media streams go to Honorlock's own servers only.

### 9. Browser Detection / Anti-Cheating Browser Detection
- **Severity:** LOW (informational)
- **Files:** `background.js` (BrowserDetector class)
- **Code:**
  ```js
  // Detects cheating browsers: Atlas (hidden ChatGPT tab), Comet, Vivaldi
  checkForAtlasBrowser() { /* looks for 1x1 pixel ChatGPT tabs */ }
  checkForCometBrowser() { /* uses chrome.management */ }
  checkForVivaldiBrowser() { /* probes vivaldi:// protocol */ }
  // Uses navigator.userAgentData, offscreen document for DOM checks
  ```
- **Verdict:** Detects specialized "cheating browsers" that disguise themselves as Chrome. The Atlas browser check specifically looks for hidden 1x1 pixel ChatGPT tabs. Uses `chrome.offscreen` API for additional browser verification signals. This is anti-fraud detection, not fingerprinting for tracking.

### 10. External Message Channel
- **Severity:** LOW (properly scoped)
- **Files:** `manifest.json`, `background.js`
- **Code:**
  ```json
  "externally_connectable": { "matches": ["*://app.honorlock.com/*", "*://*.app.honorlock.com/*"] }
  ```
  ```js
  u().runtime.onMessageExternal.addListener(this._handleOnMessageExternalEvent)
  // Handles: HL_LAUNCH_PROCTORING, HL_CAMERA_BLADE messages
  ```
- **Verdict:** The extension accepts external messages only from `app.honorlock.com` subdomains. Messages are used to initiate proctoring sessions and manage the camera blade. The origin check is enforced by Chrome's `externally_connectable` manifest declaration.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")` | `background.js` | Standard globalThis polyfill |
| `btoa()` / `atob()` | `background.js` | LocalForage blob encoding + browser detection verdict encoding |
| `chrome.scripting.executeScript` | `background.js` | Injecting own bundled content scripts (exam tools, cleanup) -- no remote code |
| `innerHTML` / DOM manipulation | Various content scripts | Creating UI elements (toolbar, notifications, modals) with static content |
| `webRequest.onCompleted` | `background.js` | Web traffic monitoring during exams only (host-level logging) |
| `chrome.management.setEnabled` | `background.js` | Disabling blocked extensions during proctored exams |

## API Endpoints Table

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://app.honorlock.com/lms/studentinit` | POST | Initialize student exam session |
| `https://app.honorlock.com/webapp/camera` | GET | Open proctoring webcam window |
| `https://app.honorlock.com/launch` | GET | Exam launch page |
| `https://app.honorlock.com/extension/uninstall/{session_id}` | GET | Uninstall callback URL |
| `https://app.honorlock.com/proctoring/chat` | GET | Live proctor chat |
| `https://app.honorlock.com/survey/student/*` | GET | Post-exam student survey |
| `https://app.honorlock.com/webrtc/init*` | GET | WebRTC initialization for webcam |
| `https://app.honorlock.com/hl-frame/*` | GET | Honorlock iframe for LMS integration |
| `https://prep.honorlock.com` | GET | Student tutorial/onboarding |

## Data Flow Summary

1. **Initialization:** When a student opens an exam on a supported LMS (Canvas, Blackboard, D2L, etc.), the content script detects the exam page and sends a message to the background script.
2. **Session Setup:** The background script POSTs to `app.honorlock.com/lms/studentinit` with student/exam metadata. The server responds with session configuration, exam toggles, and a blocked extension list.
3. **Proctoring Active:** The extension opens a camera window (`app.honorlock.com/webapp/camera`), enables screen capture via `desktopCapture`, starts monitoring web traffic (host-level), blocks new tabs, disables blocked extensions, and enters fullscreen/focus lock.
4. **During Exam:** Keyboard shortcuts, DevTools openings, copy/paste attempts, browser focus loss, and web navigation are all monitored and reported to the camera window (which relays to Honorlock servers via WebRTC/WebSocket).
5. **Exam End:** Upon submission, the extension re-enables blocked extensions, stops web traffic monitoring, removes tab restrictions, deletes exam-period browser history, and cleans up local storage.

**All data flows exclusively to `*.honorlock.com` domains.** No third-party analytics, tracking pixels, or external data collection was observed.

## Overall Risk: **CLEAN**

Honorlock is an extremely invasive extension by necessity -- it is a full lockdown browser proctoring solution. It disables other extensions, monitors all web traffic, captures screen and webcam, blocks keyboard shortcuts, prevents copy/paste, forces fullscreen, detects DevTools, and deletes exam browser history. However, **all of these capabilities serve the legitimate purpose of online exam proctoring**. The extension:

- Communicates exclusively with `*.honorlock.com` domains
- Has a strict CSP (`script-src 'self'`)
- Does not load remote code
- Does not contain any market intelligence SDKs, ad injection, proxy infrastructure, or data harvesting beyond proctoring requirements
- Does not persist monitoring outside of active exam sessions
- Properly cleans up state and re-enables extensions after exams

The invasive permissions and behaviors are well-documented, expected by the educational institutions that deploy it, and proportionate to the exam proctoring use case.
