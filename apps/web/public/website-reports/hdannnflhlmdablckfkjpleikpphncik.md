# Security Analysis: Youtube Playback Speed Control

**Extension ID:** hdannnflhlmdablckfkjpleikpphncik
**Version:** 0.0.15
**Users:** ~300,000
**Manifest Version:** 3
**Analysis Date:** 2026-02-06
**Risk Level:** CLEAN

---

## Executive Summary

Youtube Playback Speed Control is a **CLEAN** extension that provides legitimate video playback speed control functionality. The extension shows no evidence of malicious behavior, data exfiltration, or privacy violations. It is a straightforward utility that modifies HTML5 video playback rates using keyboard shortcuts and on-screen controls.

---

## Manifest Analysis

### Permissions
```json
{
  "permissions": ["storage"],
  "content_scripts": [{
    "all_frames": true,
    "matches": ["http://*/*", "https://*/*"],
    "css": ["css/inject.css"],
    "js": ["src/inject/inject.js"],
    "run_at": "document_end"
  }]
}
```

**Findings:**
- **Minimal permissions**: Only requests `storage` permission for saving user preferences
- **No dangerous permissions**: No access to cookies, tabs, webRequest, management, or other sensitive APIs
- **Broad content script injection**: Runs on all websites (`http://*/*`, `https://*/*`) to support HTML5 videos beyond YouTube
  - This is justified by the "Enable to all videos (not just youtube)" feature (BETA)
  - Legitimate use case for video speed control across different sites
- **No CSP issues**: No `content_security_policy` override that would weaken security

**Assessment:** Permissions are appropriate for the stated functionality. The broad host permissions are explained by the all-videos feature.

---

## Background Script Analysis

**File:** `src/background.js` (3 lines, minified)

### Key Behaviors

1. **Message handling** - Opens extension reviews page when toolbar icon clicked:
```javascript
chrome.action.onClicked.addListener(function (o){
  var p="https://chrome.google.com/webstore/detail/youtube-playback-speed-co/hdannnflhlmdablckfkjpleikpphncik/reviews?hl=en";
  chrome.tabs.create({url:p});
});
```

2. **Options page launcher**:
```javascript
chrome.runtime.onMessage.addListener(function (o){
  switch(o.action){
    case"openOptionsPage": chrome.runtime.openOptionsPage(); break;
  }
});
```

**Findings:**
- No network requests beyond opening Chrome Web Store reviews
- No dynamic code execution (eval, Function, etc.)
- No chrome.management, chrome.cookies, or other sensitive API calls
- No extension enumeration or killing behavior
- No external script loading

**Assessment:** Background script is benign. Only handles UI interactions.

---

## Content Script Analysis

**File:** `src/inject/inject.js` (357 lines)

### Core Functionality

1. **Video playback control**:
   - Uses MutationObserver to detect new `<video>` elements on the page
   - Modifies `video.playbackRate` property to control speed
   - Supports speeds from 0x to 16x (default step: 0.25x)

2. **Keyboard shortcuts**:
   - Default: `+` (increase), `-` (decrease), `*` (reset to 1x)
   - Customizable via options page
   - Checks for text input focus to avoid conflicts:
```javascript
if ((document.activeElement.nodeName === "INPUT" && document.activeElement.getAttribute("type") === "text") ||
    (document.activeElement.parentElement.nodeName === "YT-FORMATTED-STRING" &&
     document.activeElement.parentElement.getAttribute("id") === "contenteditable-textarea")) {
  return false;
}
```

3. **UI overlay**:
   - Creates floating speed indicator panel via `document.createElement`
   - CSS-based positioning (TopRight, TopCenter, etc.)
   - No innerHTML usage with external data

4. **Mouse wheel control** (optional):
   - Shift + Mouse wheel to adjust speed
   - Disabled by default, user-configurable

5. **Settings persistence**:
   - Uses `chrome.storage.sync` to save user preferences
   - Saves: speed, speedStep, key bindings, display options
   - Tracks "time saved" metric (seconds saved by watching at faster speeds)

### Security Assessment

**DOM Manipulation:**
- Uses legitimate DOM APIs: `createElement`, `appendChild`, `querySelectorAll`
- No suspicious innerHTML with external content
- querySelector calls are scoped to extension's own UI elements (`.PlayBackRatePanelYPSC`)

**Event Listeners:**
- Listens to `keydown` events - but only for speed control shortcuts
- No suspicious keylogging (ignores text inputs, filters key codes)
- Event listeners on video elements are for playback rate synchronization

**Data Collection:**
- **None detected** - No XHR, fetch, or network calls
- chrome.storage.sync only stores user preferences locally
- No cookies, localStorage access beyond extension settings
- "Time saved" metric (secSaved) is calculated locally, not exfiltrated

**Third-party code:**
- jQuery 3.6.3 (legitimate, options page only)
- Bootstrap 5.x (legitimate, options page only)
- No analytics SDKs, tracking pixels, or market intelligence frameworks

**Red flag checks:**
- ❌ No XHR/fetch hooking or monkey-patching
- ❌ No postMessage to external origins
- ❌ No extension enumeration (chrome.management)
- ❌ No dynamic code execution (eval, Function)
- ❌ No obfuscation beyond standard minification
- ❌ No remote config or kill switches
- ❌ No AI conversation scraping
- ❌ No ad/coupon injection
- ❌ No residential proxy infrastructure

---

## Options Page Analysis

**File:** `src/option/options.js` (157 lines)

### Functionality

1. **Settings UI**:
   - Manages keyboard shortcut customization
   - Display position/mode configuration
   - Feature toggles (mouse wheel, remember speed, all videos)

2. **Donation links**:
   - PayPal donation form (https://www.paypal.com/donate)
   - Venmo link (@Pujan-Shrestha)
   - BTC/LTC wallet addresses with QR codes
   - Links to Chrome Web Store reviews

3. **Legitimate local file access**:
```javascript
$.getJSON("keycodedict.json", function(M) {
  // Loads key code mappings for dropdown
});
```

**Findings:**
- All network links are hardcoded, legitimate destinations (PayPal, Venmo, CWS reviews)
- No analytics or tracking scripts
- No external data loading beyond local keycodedict.json

---

## Network Activity

**Analysis:** Complete review of all JavaScript files for network calls.

**Findings:**
- **Zero network requests** in content scripts or background
- No XMLHttpRequest, fetch(), WebSocket, or beacon API usage
- No external script loading (all resources bundled)
- No analytics (Google Analytics, Sentry, etc.)
- No CDN dependencies at runtime

**Hardcoded URLs (all benign):**
1. Chrome Web Store reviews: `https://chrome.google.com/webstore/detail/youtube-playback-speed-co/hdannnflhlmdablckfkjpleikpphncik/reviews`
2. PayPal donation: `https://www.paypal.com/donate`
3. Venmo profile: `https://account.venmo.com/u/Pujan-Shrestha`

---

## Privacy Assessment

**Data Access:**
- **None** - Extension does not access browsing history, cookies, or personal data
- Only modifies video playback speed on pages user is actively viewing

**Data Storage:**
- chrome.storage.sync: User preferences only (key bindings, display options, speed settings)
- No cross-site tracking or user profiling

**Data Transmission:**
- **None** - No data leaves the browser

**Compliance:**
- Appears compliant with Chrome Web Store policies
- No violations of user privacy detected

---

## Code Quality

**Positive indicators:**
- Clean, readable code structure
- No obfuscation (beyond standard minification for libraries)
- Proper event listener cleanup on fullscreen changes
- Input validation (checks for numeric input in options)

**Minor concerns:**
- Broad host permissions (`http://*/*`, `https://*/*`) - but justified by all-videos feature
- all_frames: true could inject into sensitive frames - but only modifies video elements

---

## Comparison with Known Malicious Patterns

| Pattern | Detected | Notes |
|---------|----------|-------|
| Extension enumeration/killing | ❌ No | No chrome.management usage |
| XHR/fetch hooking | ❌ No | No XMLHttpRequest or fetch patching |
| Market intelligence SDKs | ❌ No | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | ❌ No | No ChatGPT/Claude/Gemini scraping |
| Cookie harvesting | ❌ No | No cookie access |
| Residential proxy infra | ❌ No | No proxy configuration |
| Ad/coupon injection | ❌ No | No DOM manipulation for ads |
| Remote config | ❌ No | No external JSON fetching |
| Obfuscated code | ❌ No | Standard minification only |
| Keylogging | ❌ No | Keydown events filtered for shortcuts only |
| Data exfiltration | ❌ No | Zero network activity |

---

## False Positive Analysis

**Potential triage flags:**
- **keydown listener** → Legitimate for keyboard shortcuts (with input field filtering)
- **querySelectorAll** → Scoped to extension's own UI elements
- **MutationObserver** → Standard for detecting new video elements
- **Broad host permissions** → Required for all-videos feature
- **all_frames injection** → Needed for embedded YouTube players

**Assessment:** All "suspicious" patterns have legitimate explanations in the context of video playback control.

---

## Final Verdict

**RISK LEVEL: CLEAN**

Youtube Playback Speed Control is a legitimate, privacy-respecting browser extension that performs exactly as advertised. It:

✅ Modifies video playback speed using standard HTML5 APIs
✅ Stores only user preferences locally
✅ Makes zero network requests (no data exfiltration)
✅ Uses minimal permissions appropriate for functionality
✅ Has no analytics, tracking, or market intelligence SDKs
✅ Includes no obfuscation or hidden behavior
✅ Appears to be maintained by an independent developer (donation requests)

**Recommendation:** This extension is safe for users. No security concerns identified.

---

## Metadata

**Analysis Coverage:**
- ✅ Manifest permissions and CSP
- ✅ Background service worker
- ✅ Content scripts (inject.js)
- ✅ Options page and configuration
- ✅ Network activity analysis
- ✅ Third-party dependencies (jQuery, Bootstrap)
- ✅ Code signing verification (Chrome signatures present in verified_contents.json)

**Files Analyzed:**
- `/deobfuscated/manifest.json`
- `/deobfuscated/src/background.js`
- `/deobfuscated/src/inject/inject.js`
- `/deobfuscated/src/option/options.js`
- `/deobfuscated/src/option/options.html`
- `/deobfuscated/css/inject.css`
- `/deobfuscated/_metadata/verified_contents.json`

**Known False Positives Ignored:**
- MutationObserver for video detection
- querySelectorAll for UI element management
- keydown events with proper input filtering
- Broad host permissions justified by feature set
