# Security Analysis: Sound Booster (pmilcmjbofinpnbnpanpdadijibcgifc)

## Extension Metadata
- **Name**: Sound Booster
- **Extension ID**: pmilcmjbofinpnbnpanpdadijibcgifc
- **Version**: 1.0.10
- **Manifest Version**: 3
- **Estimated Users**: ~40,000
- **Description**: Adjust volume in Chrome tabs separately. Boost music volume and video up to 60 lvl.
- **Analysis Date**: 2026-02-15

## Executive Summary
Sound Booster is a **CLEAN** volume control extension that allows users to adjust audio levels on individual Chrome tabs beyond the system maximum. The extension uses the Web Audio API with Chrome's `tabCapture` permission to intercept and amplify tab audio through a GainNode. Analysis of the codebase revealed no malicious behavior, no tracking mechanisms, no data exfiltration, and no external network communications beyond a single legitimate "Rate us" link to the Chrome Web Store.

The ext-analyzer tool flagged 4 potential exfiltration flows involving `chrome.tabs.get/query → fetch` and `*.src(reactjs.org)`, but detailed code inspection confirms these are false positives caused by React's bundled error handling code and the module preload polyfill's use of `fetch()` for internal resource loading.

**Overall Risk Assessment: CLEAN**

## Vulnerability Assessment

### Summary
**No vulnerabilities detected.** This extension implements its stated functionality (per-tab volume boosting) using standard Chrome APIs without any malicious patterns.

---

## Core Functionality Analysis

### 1. Audio Capture and Volume Amplification
**Files**: `/js/popup.js` (lines 6930-6946)

**Analysis**:
The extension's primary functionality is implemented using the Web Audio API to amplify tab audio:

**Code Evidence**:
```javascript
chrome.tabCapture.getMediaStreamId({
  targetTabId: a
}, (async e => {
  const n = await navigator.mediaDevices.getUserMedia({
    audio: {
      mandatory: {
        chromeMediaSource: "tab",
        chromeMediaSourceId: e
      }
    },
    video: !1
  }),
  r = new AudioContext,
  o = r.createMediaStreamSource(n),
  a = r.createGain();
  a.gain.value = Yc(t),
  o.connect(r.destination),
  o.connect(a),
  a.connect(r.destination),
  d(a), h(n)
}))
```

**Mechanism**:
1. Captures target tab's audio stream using `chrome.tabCapture.getMediaStreamId()`
2. Creates an `AudioContext` and `MediaStreamSource` from the captured stream
3. Applies a `GainNode` with user-controlled gain value (function `Yc(t)` converts slider value)
4. Routes audio through gain node to output destination
5. Stops stream when tab audio becomes silent

**Safety Indicators**:
- Audio processing is entirely client-side (Web Audio API)
- No audio data transmitted to external servers
- Gain values are user-controlled via UI slider
- Streams properly cleaned up when inactive (`p.getTracks().forEach((e => e.stop()))`)

**Verdict**: **LEGITIMATE FUNCTIONALITY** - Standard implementation of browser-based volume boosting.

---

### 2. Tab State Monitoring
**Files**:
- `/js/popup.js` (lines 6950-6964) - tabCapture status changes
- `/js/popup.js` (lines 6966-6972) - tab updates/removal
- `/js/popup.js` (lines 6974-6982) - active tab query

**Analysis**:
The extension monitors tab state to update its UI and manage fullscreen behavior:

**Code Evidence** (Tab Capture Status Handler):
```javascript
chrome.tabCapture.onStatusChanged.addListener((function(e) {
  "active" == e.status && e.tabId && chrome.tabs.get(e.tabId, (t => {
    chrome.windows.get(t.windowId, (t => {
      const n = t.id;
      !0 !== na.load("fullScreen") ? e.fullscreen ?
        (na.save("windowState", t.state),
         chrome.windows.update(n, { state: "fullscreen", focused: !0 })) :
        chrome.windows.update(n, { state: na.load("windowState") }) :
        chrome.windows.update(n, { state: t.state })
    }))
  }))
}))
```

**Purpose**:
- Detects when tab capture becomes active
- Manages window fullscreen state based on user preference (`na.load("fullScreen")`)
- Stores/restores window state when entering/exiting fullscreen
- Updates popup UI with tab title and favicon
- Closes popup when target tab is removed

**Data Accessed**:
- Tab ID, title, favicon URL, audible status
- Window state (normal/fullscreen/maximized)
- All data used purely for UI display and state management

**Storage**:
- `chrome.storage.local` via wrapper object `na` for preferences:
  - `fullScreen` (boolean preference)
  - `windowState` (previous window state string)

**Verdict**: **NOT MALICIOUS** - Standard tab state tracking for audio control UI.

---

### 3. Service Worker Window Management
**Files**: `/js/serviceWorker.js` (lines 1-78)

**Analysis**:
The service worker manages popup window lifecycle to ensure single-instance popup per tab:

**Code Evidence**:
```javascript
const n = {
  set: async e => {
    const t = await n.get();
    await chrome.storage.local.set({
      [o.Service]: { ...t, ...e }
    })
  },
  get: () => new Promise((e => {
    chrome.storage.local.get(o.Service, (t => {
      const i = { ...d, ...t[o.Service] };
      e(i)
    }))
  }))
}
```

**Functionality**:
1. `chrome.action.onClicked` handler checks if popup window already exists for tab
2. Reuses existing window via `chrome.windows.update(i.w, { focused: !0 })` if found
3. Creates new popup window with fixed dimensions (432x342) if not found
4. Stores tab-to-window mappings in `activeWindows` array
5. Cleans up mappings when windows are closed

**Data Stored**:
- `activeWindows`: Array of `{t: tabId, w: windowId}` objects
- Used purely for window state management, no user data

**Verdict**: **NOT MALICIOUS** - Standard service worker pattern for popup lifecycle.

---

## ext-analyzer False Positives Explained

### Flagged Flow 1: `chrome.tabs.get → fetch` (js/popup.js)
**Analysis**: This is a **FALSE POSITIVE** caused by React's module preload polyfill.

**Code Evidence** (lines 21-44):
```javascript
const e = document.createElement("link").relList;
if (!(e && e.supports && e.supports("modulepreload"))) {
  for (const e of document.querySelectorAll('link[rel="modulepreload"]')) t(e);
  new MutationObserver((e => {
    for (const n of e)
      if ("childList" === n.type)
        for (const e of n.addedNodes)
          "LINK" === e.tagName && "modulepreload" === e.rel && t(e)
  })).observe(document, { childList: !0, subtree: !0 })
}

function t(e) {
  if (e.ep) return;
  e.ep = !0;
  const t = function(e) {
    const t = {};
    return e.integrity && (t.integrity = e.integrity),
           e.referrerPolicy && (t.referrerPolicy = e.referrerPolicy),
           "use-credentials" === e.crossOrigin ? t.credentials = "include" :
           "anonymous" === e.crossOrigin ? t.credentials = "omit" :
           t.credentials = "same-origin", t
  }(e);
  fetch(e.href, t)
}
```

**Explanation**:
- This is standard React/Vite build output for module preloading polyfill
- `fetch()` loads **local** extension modules from `e.href` (same-origin resources)
- No connection to `chrome.tabs.get()` - they appear in same file but are unrelated code paths
- Data flow analysis incorrectly linked tab API usage with this internal fetch

**Verdict**: **FALSE POSITIVE** - No actual exfiltration; internal module loading only.

---

### Flagged Flow 2: `chrome.tabs.query → *.src(reactjs.org)` (js/popup.js)
**Analysis**: This is a **FALSE POSITIVE** from React's bundled error message URL constructor.

**Code Evidence** (line 673):
```javascript
for (var t = "https://reactjs.org/docs/error-decoder.html?invariant=" + e,
     n = 1; n < arguments.length; n++)
  t += "&args[]=" + encodeURIComponent(arguments[n]);
```

**Explanation**:
- This code is part of React's production build error handling
- Constructs error documentation URLs when React errors occur
- **NEVER ACTUALLY LOADED** - URL only used in console error messages
- No `.src` assignment occurs; ext-analyzer misidentified string concatenation
- No connection to tab query APIs; co-location in bundle caused false correlation

**Verification**:
- Searched entire codebase: no `<script>` element `.src` assignments
- No `createElement("script")` calls with reactjs.org URLs
- React error URLs are documentation references only, not loaded resources

**Verdict**: **FALSE POSITIVE** - Static error message URL, never fetched.

---

## Network Analysis

### External Endpoints
**Total External Domains**: 1

1. **chrome.google.com** (Chrome Web Store)
   - **Purpose**: "Rate us!" button opens extension's CWS review page
   - **Trigger**: User clicks "Rate us!" button in popup footer
   - **Data Transmitted**: None (standard browser navigation)
   - **Code**: `chrome.tabs.create({ url: 'https://chrome.google.com/webstore/detail/volume-booster/${chrome.runtime.id}/reviews' })` (line 11688-11690)
   - **Risk**: None - Legitimate CWS review link

### Internal Resources
- All JavaScript/CSS loaded from local extension files via `chrome-extension://` protocol
- No CDN dependencies (React bundled into `popup.js`)
- No analytics, tracking pixels, or third-party scripts
- HTML popup uses inline module script tag with local path (`/js/popup.js`)

### Network Communication Summary
- **No XMLHttpRequest or fetch calls to external servers**
- **No WebSocket connections**
- **No postMessage to external origins**
- **No iframe embedding of external content**
- **No dynamic script loading from external sources**

**Verdict**: Extension is essentially **offline** except for the optional review page link.

---

## Permission Analysis

### Requested Permissions
1. **`tabCapture`** (HIGH SENSITIVITY)
   - **Purpose**: Capture audio from browser tabs for volume amplification
   - **Usage**: `chrome.tabCapture.getMediaStreamId()` to obtain tab audio stream
   - **Risk**: Could be abused for eavesdropping, but only used for legitimate audio processing
   - **Justified**: Essential for stated functionality (volume boosting)

2. **`tabs`** (MEDIUM SENSITIVITY)
   - **Purpose**: Query active tab for UI updates (title, favicon, audible status)
   - **Usage**: `chrome.tabs.get()`, `chrome.tabs.query()`, event listeners for tab state
   - **Risk**: Could access tab URLs/titles, but only used for popup display
   - **Justified**: Necessary to show which tab is being controlled

3. **`storage`** (LOW SENSITIVITY)
   - **Purpose**: Persist user preferences (fullscreen behavior, window states)
   - **Usage**: `chrome.storage.local` via wrapper object for settings
   - **Data Stored**: Window management state, no user data
   - **Risk**: Minimal
   - **Justified**: Standard preference storage

### Host Permissions
- **`<all_urls>`**: Required by `tabCapture` API to capture audio from any tab
- **Risk**: Broad permission, but extension has no content scripts or web request interception
- **Usage**: Only via `tabCapture` API for audio stream access

### Web Accessible Resources
- **Pattern**: `*` (all resources exposed to `*://*/*`)
- **Risk**: Allows any website to detect extension installation via resource probing
- **Files Exposed**: All extension files (icons, CSS, JS, layouts)
- **Fingerprinting Risk**: HIGH - Extension can be detected by any website
- **Note**: Common pattern for extensions but unnecessarily broad; should be scoped to specific resources

---

## Content Security Policy

**CSP**: `script-src 'self'; object-src 'self'`

**Analysis**:
- **Secure**: Only allows scripts from extension origin
- **No `unsafe-eval`**: Prevents dynamic code execution
- **No `unsafe-inline`**: Prevents inline script execution
- **No external script sources**: Cannot load scripts from CDNs or external domains

**Verdict**: CSP is properly configured and restrictive.

---

## Code Quality and Obfuscation

### Obfuscation Status
- **Obfuscated**: YES (flagged by ext-analyzer)
- **Type**: Production build minification (Vite/Rollup)
- **Characteristics**:
  - Shortened variable names (e.g., `e`, `t`, `n`, `r`)
  - React production bundle with minified core library
  - Legitimate build tooling, not intentional obfuscation

### Deobfuscation Results
- Code successfully beautified using jsbeautifier
- Control flow is readable after formatting
- No string encryption, array obfuscation, or anti-debugging code
- Minification is standard for React apps built with Vite

**Verdict**: Standard production build minification, not malicious obfuscation.

---

## Privacy and Data Collection

### Data Collection Assessment
**NO DATA COLLECTION DETECTED**

- **No analytics libraries** (Google Analytics, Mixpanel, etc.)
- **No tracking pixels or beacons**
- **No user identifiers generated or transmitted**
- **No browsing history collection**
- **No form data interception**
- **No clipboard access**
- **No screenshot/screen capture**

### Local Storage Contents
**Only Extension Settings Stored**:
- User volume preference (slider value)
- Fullscreen behavior preference (boolean)
- Window state for fullscreen restoration (string)
- Active popup window mappings (tab-to-window IDs)

**No sensitive data stored**: No credentials, tokens, user data, or browsing history.

---

## Attack Surface

### Potential Risks (All Mitigated)
1. **Tab Audio Eavesdropping**
   - **Mitigation**: Audio only processed client-side, never transmitted
   - **User Control**: User must actively enable volume boost per tab

2. **Extension Fingerprinting**
   - **Issue**: Web accessible resources allow website detection
   - **Impact**: LOW - Detection only, no data leakage
   - **Recommendation**: Scope WAR to specific resources

3. **Fullscreen State Manipulation**
   - **Impact**: MINIMAL - Only changes window state based on user preference
   - **Not exploitable**: No security bypass, purely cosmetic behavior

### No Exploitable Vulnerabilities Found
- No eval/Function usage
- No dynamic code execution
- No message passing attack surface (no external message listeners)
- No CORS bypass attempts
- No privilege escalation vectors

---

## Manifest V3 Compliance

**Fully MV3 Compliant**:
- Service worker instead of persistent background page
- Declarative permissions model
- No remotely hosted code
- No `executeScript` with code strings
- CSP enforced on extension pages

---

## Final Risk Verdict

**RISK LEVEL: CLEAN**

### Summary
Sound Booster is a **legitimate, single-purpose volume control extension** with no malicious behavior. The extension:

✅ Implements its stated functionality (per-tab volume boosting) accurately
✅ Uses appropriate Chrome APIs (tabCapture, Web Audio) for audio processing
✅ Performs all audio manipulation client-side with no external transmission
✅ Has no tracking, analytics, or data collection mechanisms
✅ Makes no external network requests (except optional CWS review link)
✅ Stores only benign user preferences locally
✅ Uses proper CSP to prevent code injection
✅ Has no exploitable vulnerabilities or attack vectors

### ext-analyzer Findings Assessment
All 4 flagged "exfiltration flows" are **FALSE POSITIVES**:
- 2 flows from React's module preload polyfill (internal fetch only)
- 2 flows from React error message URLs (never loaded, documentation strings only)
- No actual data exfiltration occurs

### Recommendations
1. **For Users**: Safe to install. Extension does what it claims without privacy risks.
2. **For Developer**: Consider scoping `web_accessible_resources` to specific files to reduce fingerprinting surface.

---

## Technical Details

### Build Information
- **Framework**: React 18.2.0 (production build)
- **Build Tool**: Vite (based on module preload polyfill presence)
- **Bundle Size**: ~339KB (popup.js)
- **Architecture**: MV3 service worker + React popup UI

### Code Patterns
- Modern React hooks usage (`useEffect`, `useState`, `useCallback`, `useContext`)
- Context API for state management (`Gp.Provider` for volume/audible state)
- Proper cleanup in effect hooks (stream stopping, event listener management)
- Defensive programming (null checks with `??` operator, optional chaining)

**No malicious patterns detected.**

---

**Analysis Completed**: 2026-02-15
**Analyst**: Claude Sonnet 4.5 (Automated Static Analysis)
**Confidence Level**: HIGH (Clean verdict confirmed through manual code review)
