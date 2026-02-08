# Security Analysis: Picture in Picture - floating video player

**Extension ID:** gmehookibnphigonphocphhcepbijeen
**Version:** 1.0.6
**Users:** ~300,000
**Analysis Date:** 2026-02-06
**Risk Level:** LOW (Clean)

---

## Executive Summary

Picture in Picture - floating video player is a simple browser extension that enables Picture-in-Picture (PiP) mode for videos on web pages. The extension consists of minimal code (43 total lines across 2 JavaScript files) with straightforward functionality and no detected security issues.

**Verdict: CLEAN** - This extension performs its stated function without any malicious behavior, excessive permissions, or privacy violations.

---

## Manifest Analysis

### Permissions
```json
"permissions": ["scripting", "storage"]
"host_permissions": ["<all_urls>"]
```

**Assessment:**
- `scripting`: Required to inject content script into MAIN world when extension icon is clicked
- `storage`: Used to store user preference (count setting, defaults to 1/enabled)
- `<all_urls>`: Necessary to enable PiP on any website with video content

**Concerns:** None. All permissions are justified for the extension's functionality.

### Content Security Policy
- **No custom CSP defined** - Uses Manifest V3 defaults
- **Assessment:** Acceptable for this simple extension with no external resources

### Content Scripts
```json
{
  "matches": ["<all_urls>"],
  "js": ["content.js"],
  "all_frames": true,
  "run_at": "document_start"
}
```

**Assessment:**
- Runs on all URLs and all frames to detect videos in iframes
- `document_start` timing is appropriate for intercepting video elements early
- No security concerns

---

## Code Analysis

### Background Service Worker (`worker.js` - 7 lines)

**Functionality:**
```javascript
chrome.action.onClicked.addListener((t => {
    chrome.storage.sync.get({count: 1}, (e => {
        if (e.count) {
            let e = ["content.js"];
            chrome.scripting.executeScript({
                target: {tabId: t.id, allFrames: !0},
                world: "MAIN",
                files: e
            })
        }
    }))
}))
```

**Behavior:**
1. Listens for extension icon clicks
2. Checks if feature is enabled via storage (default: enabled)
3. Injects content.js into MAIN world context on the active tab
4. Targets all frames to handle videos in iframes

**Security Assessment:** Clean. No network calls, no sensitive data access, standard injection pattern.

---

### Content Script (`content.js` - 36 lines)

**Core Functionality:**

1. **Video Element Selection (`function e()`)**
   - Queries all `<video>` elements on page
   - Filters out videos with readyState=0 (no data loaded)
   - Filters out videos with disablePictureInPicture=true
   - Sorts by size (width × height) descending
   - Returns largest eligible video

2. **PiP Activation (`function t(e)`)**
   - Calls native `requestPictureInPicture()` API
   - Sets custom `__pip__` attribute for tracking
   - Adds one-time event listener for PiP exit
   - Observes video resizing via ResizeObserver

3. **Video Switching (`function i(i, r)`)**
   - Monitors for video size changes
   - If active PiP video shrinks, searches for larger video
   - Automatically switches PiP to largest video

4. **Main Execution**
   - Finds largest video on page
   - If video already has `__pip__` attribute, exits PiP
   - Otherwise activates PiP mode

**Security Assessment:**
- Uses only native browser APIs (Document API, PiP API)
- No DOM manipulation beyond custom attribute
- No form interaction or data harvesting
- No network communication (except analytics - see below)

---

## Potential Issues Identified

### 1. Undefined Analytics Reference (Minor)

**Location:** `content.js:33`
```javascript
await t(i), _gaq.push(["_trackPageview", "/"])
```

**Analysis:**
- References Google Analytics `_gaq` object (legacy ga.js API)
- `_gaq` is never defined in extension code
- No analytics library loaded (no ga.js script injection)
- **Result:** This is dead code that will fail silently with `ReferenceError`

**Impact:** None. The error is caught and doesn't affect functionality. No tracking occurs.

**Classification:** Likely leftover from development or removed analytics implementation.

---

## Threat Model Assessment

### Extension Enumeration/Killing
**Status:** Not present. No `chrome.management` API usage.

### XHR/Fetch Hooking
**Status:** Not present. No XMLHttpRequest or fetch modifications.

### Network Exfiltration
**Status:** Not present. No fetch/XHR calls, no beacon API, no external domains.

### Cookie/Storage Harvesting
**Status:** Not present. No cookie access, only reads own storage for settings.

### Keylogging/Form Interception
**Status:** Not present. No keyboard event listeners or form field access.

### DOM Scraping
**Status:** Not present. Only queries video elements, no text/data extraction.

### Dynamic Code Execution
**Status:** Not present. No eval, Function(), or dynamic imports.

### Residential Proxy Infrastructure
**Status:** Not present. No WebRTC, no proxy configuration APIs.

### Remote Config/Kill Switches
**Status:** Not present. No external configuration fetching.

### Market Intelligence SDKs
**Status:** Not present. No third-party SDKs detected.

### AI Conversation Scraping
**Status:** Not present. No platform-specific targeting or data collection.

### Ad/Coupon Injection
**Status:** Not present. No ad networks, no affiliate links, no DOM injection.

### Obfuscation
**Status:** Minimal. Code is minified but not intentionally obfuscated. Uses standard bundler output format.

---

## Privacy Analysis

### Data Collection
**None detected.** The extension:
- Does not access browsing history
- Does not read page content beyond video element metadata
- Does not access cookies
- Does not make external network requests
- Only stores internal enable/disable toggle

### Third-Party Services
**None.** No external dependencies or services.

### User Tracking
**Attempted but non-functional.** The broken `_gaq` reference indicates analytics was planned but never implemented.

---

## Code Quality Assessment

### Positive Indicators
1. Minimal codebase (43 lines total)
2. Uses native browser APIs (no polyfills or libraries)
3. Proper use of async/await
4. ResizeObserver for efficient video monitoring
5. Single-purpose extension with clear functionality
6. Manifest V3 compliant

### Negative Indicators
1. Dead code referencing undefined analytics object
2. No error handling around PiP API (fails silently)
3. Minified variable names (standard for production bundles)

### Overall Assessment
The code quality is acceptable for a simple utility extension. The dead analytics code is the only concern, but it's non-functional and harmless.

---

## Comparison with Known Malicious Patterns

### False Positive Patterns (Not Applicable)
This extension does not trigger any known false positive patterns:
- No React/Vue framework code
- No Sentry SDK
- No Floating UI or focus trapping
- No AdGuard/uBlock scriptlets
- No MobX observables
- No Firebase configs
- No OpenTelemetry instrumentation

### Malicious Patterns (Not Present)
- No extension killing behavior (VeePN, YouBoost, Troywell pattern)
- No XHR/fetch hooking (Urban VPN, StayFree, Flash Copilot pattern)
- No market intelligence SDKs (Sensor Tower Pathmatics pattern)
- No AI conversation scraping (StayFree/StayFocusd pattern)
- No remote configuration (YouBoost, Troywell "thanos" pattern)
- No ad injection (YouBoost pattern)
- No coupon engines (Troywell CityAds pattern)
- No proxy infrastructure (Troywell residential proxy pattern)

---

## Recommendations

### For Users
**Safe to use.** This extension performs its advertised function without privacy violations or malicious behavior.

### For Developers
1. Remove dead `_gaq.push()` code from content.js
2. Add error handling for PiP API (may fail on certain video types)
3. Consider minification source maps for debugging
4. Add `web_accessible_resources` if future versions require additional assets

### For Researchers
This extension serves as a clean baseline example for comparison with more complex or malicious PiP extensions.

---

## Technical Details

### File Inventory
```
gmehookibnphigonphocphhcepbijeen/
├── manifest.json (905 bytes)
├── worker.js (280 bytes, 7 lines)
├── content.js (1.1KB, 36 lines)
├── images/ (5 PNG icons: 16, 38, 48, 64, 128px)
└── _locales/ (24 language files)
```

### Total Code Size
- JavaScript: 1.38KB (43 lines)
- Manifest: 905 bytes
- Total executable code: 2.28KB

### Chrome API Usage
- `chrome.action.onClicked`
- `chrome.storage.sync.get`
- `chrome.scripting.executeScript`
- Native PiP API (`requestPictureInPicture`, `exitPictureInPicture`)
- ResizeObserver (Web API)

---

## Conclusion

Picture in Picture - floating video player is a **CLEAN** extension with no security vulnerabilities or privacy concerns. The extension performs its advertised function using minimal code and standard browser APIs. The only noteworthy finding is a non-functional analytics reference, which is harmless dead code.

**Risk Score: 0/10**

This extension is safe for users and does not warrant any security warnings or restrictions.

---

## Appendix: Complete Code Listing

### worker.js
```javascript
chrome.action.onClicked.addListener((t => {
    chrome.storage.sync.get({count: 1}, (e => {
        if (e.count) {
            let e = ["content.js"];
            chrome.scripting.executeScript({
                target: {tabId: t.id, allFrames: !0},
                world: "MAIN",
                files: e
            })
        }
    }))
}))
```

### content.js
```javascript
(() => {
  function e() {
    let e = Array.from(document.querySelectorAll("video"))
      .filter((e => 0 != e.readyState))
      .filter((e => 0 == e.disablePictureInPicture))
      .sort(((e, t) => {
        let i = e.getClientRects()[0] || {width: 0, height: 0},
            r = t.getClientRects()[0] || {width: 0, height: 0};
        return r.width * r.height - i.width * i.height
      }));
    if (0 !== e.length) return e[0]
  }

  async function t(e) {
    await e.requestPictureInPicture(),
    e.setAttribute("__pip__", !0),
    e.addEventListener("leavepictureinpicture", (t => {
      e.removeAttribute("__pip__")
    }), {once: !0}),
    new ResizeObserver(i).observe(e)
  }

  function i(i, r) {
    let n = i[0].target;
    if (!document.querySelector("[__pip__]")) return void r.unobserve(n);
    let u = e();
    u && !u.hasAttribute("__pip__") && (r.unobserve(n), t(u))
  }

  (async () => {
    let i = e();
    if (i) {
      if (i.hasAttribute("__pip__")) return void document.exitPictureInPicture();
      await t(i), _gaq.push(["_trackPageview", "/"]) // Dead code
    }
  })()
})();
```
