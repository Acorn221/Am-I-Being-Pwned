# Security Analysis Report: Google Docs Dark Mode

## Extension Metadata
| Field | Value |
|-------|-------|
| **Extension ID** | lgjhepbpjcmfmjlpkkdjlbgomamkgonb |
| **Name** | Google Docs Dark Mode |
| **Version** | 1.5.1 |
| **Estimated Users** | ~800,000 |
| **Manifest Version** | 3 |
| **Developer** | Olive Software |
| **Permissions** | `storage` |
| **Host Permissions** | `https://docs.google.com/document/*` |

---

## Executive Summary

**Overall Risk Level: CLEAN**

Google Docs Dark Mode is a legitimate UI theming extension that applies CSS styling to Google Docs pages to provide a dark mode interface. The extension contains no malicious code, data exfiltration mechanisms, or privacy-invasive behaviors. The codebase consists primarily of React 18 and styled-components libraries used to render UI controls and apply CSS themes. All external URLs are benign (PayPal donation links, React documentation). The extension operates entirely client-side with no network requests and minimal chrome API usage limited to local storage synchronization.

**Key Findings:**
- ✅ No network requests (fetch/XMLHttpRequest) detected
- ✅ No XHR/fetch hooking or monkey-patching
- ✅ No SDK injection (Sensor Tower, analytics, telemetry)
- ✅ No extension enumeration or killing behavior
- ✅ No keylogging or input harvesting
- ✅ No cookie or credential access
- ✅ No obfuscation or dynamic code execution
- ✅ Minimal permissions (storage only)
- ✅ No content security policy violations

---

## Vulnerability Analysis

### 1. Network Activity & Data Exfiltration
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
No network activity detected. The extension makes zero HTTP requests.

**Evidence:**
```javascript
// No fetch() calls found
// No XMLHttpRequest usage found
// No axios usage despite being listed in package.json dependencies
```

**Verdict:** CLEAN - No data exfiltration mechanisms present.

---

### 2. XHR/Fetch Hooking & Traffic Interception
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
No XHR or fetch API monkey-patching detected. No request/response interception.

**Evidence:**
- Searched for `XMLHttpRequest.prototype.send`, `fetch = `, `window.fetch =` patterns
- No Sensor Tower Pathmatics SDK or similar market intelligence code
- No network traffic hooking of any kind

**Verdict:** CLEAN - No traffic interception capabilities.

---

### 3. Chrome Extension API Abuse
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
Minimal chrome API usage. Only `chrome.storage.sync` and `chrome.runtime.getURL` are used for legitimate purposes.

**Background Script (background.js):**
```javascript
chrome.action.onClicked.addListener((function(e){
  chrome.storage.sync.set({shouldRenderControls:"true"})
}));
```

**Content Script Usage:**
```javascript
// Line 9524-9525: Store dark mode state
chrome.storage.sync.set({ [i.ACTIVE_STORAGE_KEY]: !0 })

// Line 9550: Load CSS from extension resources
href: chrome.runtime.getURL(`${t}.css`)

// Line 9559: Read stored preferences
chrome.storage.sync.get([i.ACTIVE_STORAGE_KEY], (function(e) {...}))
```

**Verdict:** CLEAN - Storage API used only for user preferences. No tabs, cookies, webRequest, management, or other invasive APIs.

---

### 4. DOM Manipulation & Content Script Behavior
**Severity:** NONE
**Status:** ✅ CLEAN (React innerHTML is false positive)

**Finding:**
DOM manipulation limited to legitimate React rendering and CSS injection for theming.

**Evidence:**
```javascript
// Line 574-578: React SVG innerHTML (known false positive)
if ("http://www.w3.org/2000/svg" !== e.namespaceURI || "innerHTML" in e)
  e.innerHTML = t;

// Line 9574-9580: Creates UI control container
const e = document.createElement("div");
e.className = "controlsContainer",
document.getElementById("kix-appview").appendChild(e)

// Line 9545-9555: Injects CSS link elements for dark theme
const n = document.getElementsByTagName("head")[0],
  r = createElement("link", {
    id: e,
    href: chrome.runtime.getURL(`${t}.css`),
    rel: "stylesheet"
  });
n.appendChild(r)
```

**Verdict:** CLEAN - React's SVG namespace innerHTML is a known framework pattern. All DOM operations are for UI rendering and CSS injection.

---

### 5. Keyboard Event Listeners & Input Harvesting
**Severity:** NONE
**Status:** ✅ CLEAN (React synthetic events only)

**Finding:**
Keyboard event handling is exclusively React's synthetic event system for UI interactions. No keylogging.

**Evidence:**
```javascript
// Line 1066: React event delegation list (framework code)
"keydown keypress keyup input textInput ... click change contextmenu"

// Line 1240-1242: React keyboard event handling (framework)
case "keydown":
case "keypress":
case "keyup":
```

**Verdict:** CLEAN - All keyboard references are React framework event delegation. No raw keydown listeners or keystroke capture.

---

### 6. Local Storage & Data Collection
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
localStorage used only to store user preferences for dark mode settings and donation button visibility.

**Evidence:**
```javascript
// Line 9311-9312: Initialize preference
let n = localStorage.getItem(e);
n || (localStorage.setItem(e, "true"), n = "true")

// Line 9332: Store main dark mode toggle
localStorage.setItem("mainActive", n)

// Line 9338: Store page style toggle
localStorage.setItem("pageActive", e)

// Line 9494: Store donation button visibility
localStorage.setItem("showDonation", "false")
```

**Data Stored:**
- `mainActive`: "true" | "false" (main CSS toggle)
- `pageActive`: "true" | "false" (page inversion CSS toggle)
- `showDonation`: "true" | "false" (donate button visibility)

**Verdict:** CLEAN - Only stores UI state. No PII, browsing history, or sensitive data collection.

---

### 7. External URLs & Third-Party Services
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
Only external URLs are PayPal donation links. No analytics, tracking, or data collection services.

**Evidence:**
```javascript
// Line 9343: PayPal donation button
href: "https://www.paypal.com/donate/?hosted_button_id=F9CQY44NXP8K2"

// Line 9398: Chrome Web Store listing (info modal)
href: "https://chrome.google.com/webstore/detail/google-docs-dark-mode/lgjhepbpjcmfmjlpkkdjlbgomamkgonb"

// Line 90: React error decoder (framework)
"https://reactjs.org/docs/error-decoder.html?invariant="
```

**Verdict:** CLEAN - No telemetry, analytics, or data collection endpoints. PayPal links are benign donation requests.

---

### 8. Extension Enumeration & Killing
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
No extension enumeration (`chrome.management.getAll`) or disabling behavior (`chrome.management.setEnabled`).

**Verdict:** CLEAN - Does not interfere with other extensions.

---

### 9. Code Obfuscation & Dynamic Execution
**Severity:** NONE
**Status:** ✅ CLEAN

**Finding:**
Standard webpack minification. No malicious obfuscation, eval(), or Function() constructor abuse.

**Evidence:**
```javascript
// Line 580: MSApp.execUnsafeLocalFunction (Microsoft IE/Edge only)
// This is React's compatibility layer for Internet Explorer
MSApp.execUnsafeLocalFunction((function() {
  return ce(e, t)  // Calls innerHTML wrapper
}))
```

**Verdict:** CLEAN - MSApp.execUnsafeLocalFunction is React's IE compatibility code, not malicious. No base64 decoding, atob/btoa abuse, or dynamic script injection.

---

### 10. Permissions Analysis
**Severity:** NONE
**Status:** ✅ CLEAN

**Manifest Permissions:**
```json
{
  "permissions": ["storage"],
  "content_scripts": [{
    "matches": ["https://docs.google.com/document/*"],
    "js": ["main.js"]
  }],
  "web_accessible_resources": [{
    "resources": ["main.css", "permanent.css", "pageStyle.css", "images/*"],
    "matches": ["https://docs.google.com/*"]
  }]
}
```

**Verdict:** CLEAN - Minimal permissions. Only requests `storage` for user preferences. No cookies, tabs, webRequest, or invasive permissions.

---

## False Positive Analysis

| Pattern | Location | Classification | Reason |
|---------|----------|----------------|--------|
| `innerHTML` usage | main.js:574 | ✅ FALSE POSITIVE | React's SVG namespace check: `if ("http://www.w3.org/2000/svg" !== e.namespaceURI \|\| "innerHTML" in e)` - standard React pattern |
| `addEventListener` | main.js:1892 | ✅ FALSE POSITIVE | React synthetic event delegation system - framework code |
| `keydown`/`keypress` | main.js:1240 | ✅ FALSE POSITIVE | React keyboard event handling - no keystroke logging |
| `String.fromCharCode` | main.js:1497 | ✅ FALSE POSITIVE | React key event to character conversion - framework utility |
| `stopTracking` | main.js:434 | ✅ FALSE POSITIVE | React form value tracker cleanup - framework internals |
| `MSApp.execUnsafeLocalFunction` | main.js:580 | ✅ FALSE POSITIVE | React IE/Edge compatibility wrapper for innerHTML |
| `axios` in package.json | package.json:30 | ✅ FALSE POSITIVE | Listed as dependency but never imported/used in code |
| `document.createElement("div")` | main.js:9574 | ✅ FALSE POSITIVE | Creates UI control container - legitimate React mounting |
| `getElementById("kix-appview")` | main.js:9575 | ✅ FALSE POSITIVE | Finds Google Docs app container to inject controls |

---

## API Endpoints & External Domains

| Domain/URL | Purpose | Risk Level |
|------------|---------|------------|
| `https://www.paypal.com/donate/?hosted_button_id=F9CQY44NXP8K2` | Donation button link | ✅ CLEAN |
| `https://chrome.google.com/webstore/detail/google-docs-dark-mode/...` | Info modal extension link | ✅ CLEAN |
| `https://reactjs.org/docs/error-decoder.html` | React framework error messages | ✅ CLEAN |
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store update URL (standard) | ✅ CLEAN |

**No backend servers, APIs, or data collection endpoints detected.**

---

## Data Flow Summary

```
User Clicks Extension Icon
         ↓
Background Script (background.js)
         ↓
chrome.storage.sync.set({shouldRenderControls: "true"})
         ↓
Content Script (main.js) Detects Storage Change
         ↓
Renders React UI Controls (sun/moon toggle, settings)
         ↓
User Toggles Dark Mode
         ↓
localStorage.setItem("mainActive", "true")
chrome.storage.sync.set({gdrivedmACTIVE: true})
         ↓
Injects CSS Link Elements into <head>
         ↓
Dark Theme Applied via CSS
```

**Data Storage:**
- `chrome.storage.sync`: `shouldRenderControls`, `gdrivedmACTIVE`, `gdocsPageCSS`
- `localStorage`: `mainActive`, `pageActive`, `showDonation`

**Data Transmission:** NONE - All operations are local.

---

## Technical Stack Analysis

**Framework & Libraries:**
- React 18.x (minified production build)
- styled-components 5.x (CSS-in-JS)
- react-draggable (UI controls dragging)
- PropTypes (type checking)

**Build Tools:**
- Webpack 5.x (bundler)
- TypeScript (compiled to JS)
- Babel (transpiler)

**Package.json Dependencies (unused):**
- `axios` - Listed but never imported
- `lodash` - Listed but never imported
- `jquery` - Listed but never imported

**Verdict:** Clean React application. Listed dependencies (axios, lodash, jquery) appear to be unused remnants from development.

---

## Functionality Overview

**Primary Features:**
1. **Dark Mode Toggle**: Injects CSS to style Google Docs UI elements with dark colors
2. **Page Inversion**: Applies CSS filter `invert(1)` to document content area
3. **UI Controls**: Draggable control panel with:
   - Sun/Moon toggle (main dark mode)
   - Black/White doc icon (page inversion)
   - PayPal donation button
   - Settings modal
   - Help/info modal
   - Close button

**CSS Application Method:**
```javascript
// Creates <link> elements pointing to extension CSS files
<link
  id="gdrivedmCSS"
  href="chrome-extension://.../main.css"
  rel="stylesheet"
>
```

**Theme Files:**
- `main.css` - Google Docs UI element color overrides (4 lines minified)
- `permanent.css` - Control panel styling (1 line minified)
- `pageStyle.css` - Document content inversion filter (1 line minified)

---

## Security Best Practices Compliance

| Practice | Status | Notes |
|----------|--------|-------|
| Minimal permissions | ✅ PASS | Only `storage` permission |
| No remote code loading | ✅ PASS | All code bundled in extension |
| CSP compliance | ✅ PASS | No inline scripts or eval() |
| No third-party tracking | ✅ PASS | No analytics SDKs |
| Transparent functionality | ✅ PASS | Does what description claims |
| No obfuscation | ✅ PASS | Standard webpack minification |
| No credential access | ✅ PASS | No cookies/passwords accessed |
| No network requests | ✅ PASS | Fully offline operation |

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Details |
|-------------------|----------|---------|
| Sensor Tower Pathmatics SDK | ❌ NO | Not present |
| XHR/fetch hooking | ❌ NO | Not present |
| Extension enumeration/killing | ❌ NO | Not present |
| Residential proxy infrastructure | ❌ NO | Not present |
| AI conversation scraping | ❌ NO | Not present |
| Social media data harvesting | ❌ NO | Not present |
| Ad injection | ❌ NO | Not present |
| Coupon injection | ❌ NO | Not present |
| Remote config/kill switches | ❌ NO | Not present |
| Google Analytics proxy bypass | ❌ NO | Not present |
| Hardcoded credentials | ❌ NO | Not present |

---

## Privacy Analysis

**Data Collected:** NONE

**Data Transmitted:** NONE

**PII Access:** NONE

**Document Content Access:**
- The extension can technically read document content via DOM access (inherent to content script on docs.google.com)
- However, no code is present that reads, stores, or transmits document content
- The extension only injects CSS and renders UI controls

**Privacy Statement Verification:**
The extension's info modal states:
> "This extension does not collect, and will never collect, any personal information or access the contents of your files."

**Verdict:** ✅ ACCURATE - Code analysis confirms this claim. No data collection or document content access implemented.

---

## Recommendations

**For Users:**
- ✅ SAFE TO USE - This extension is clean and functions as advertised
- The extension requests donation via PayPal button but does not implement any malicious behavior
- User preferences are stored locally only

**For Developers:**
- Consider removing unused dependencies (axios, lodash, jquery) from package.json to reduce bundle confusion
- Add Content Security Policy to manifest.json for additional security hardening
- Consider open-sourcing the code to improve transparency

**For Security Researchers:**
- This extension can serve as a CLEAN baseline for React-based Chrome extensions
- React framework patterns (innerHTML for SVG, synthetic events) should not be flagged as malicious

---

## Conclusion

**OVERALL RISK: CLEAN**

Google Docs Dark Mode (lgjhepbpjcmfmjlpkkdjlbgomamkgonb) is a legitimate, well-implemented dark mode extension for Google Docs. The extension contains:
- ✅ No malicious code
- ✅ No data exfiltration
- ✅ No privacy violations
- ✅ No network requests
- ✅ No SDK injections
- ✅ No obfuscation beyond standard minification

The extension operates entirely client-side, uses minimal permissions, and functions exactly as described. All "suspicious" patterns detected are false positives from the React framework. The developer includes donation links but does not implement any coercive or deceptive monetization tactics.

**Confidence Level:** HIGH - Comprehensive static analysis performed on all JavaScript and JSON files.

---

## Analysis Metadata

| Field | Value |
|-------|-------|
| **Analysis Date** | 2026-02-06 |
| **Analyst** | Claude (Sonnet 4.5) |
| **Analysis Method** | Comprehensive static code analysis |
| **Files Analyzed** | 2 JS files (main.js: 9630 lines, background.js: 1 line), 3 CSS files, manifest.json |
| **Total Extension Size** | ~358KB (main.js), ~139KB (CRX file) |
| **Code Structure** | React 18 + styled-components + react-draggable |
| **Suspicious Patterns Found** | 0 (all detected patterns were React framework false positives) |
| **Network Endpoints Found** | 0 |
| **Chrome API Calls** | 2 types (storage.sync, runtime.getURL) |

---

## File Inventory

```
deobfuscated/
├── background.js          (1 line - minimal service worker)
├── main.js                (9630 lines - React bundle)
├── main.css               (4 lines minified - UI theme)
├── permanent.css          (1 line minified - controls styling)
├── pageStyle.css          (1 line minified - content inversion)
├── manifest.json          (54 lines - MV3 manifest)
├── package.json           (36 lines - build config)
└── images/
    ├── icon_128.png       (extension icon)
    ├── moon.png           (dark mode icon)
    ├── sun.png            (light mode icon)
    ├── docBlack.png       (page toggle icon)
    ├── docWhite.png       (page toggle icon)
    ├── paypal.png         (donation icon)
    ├── settings.png       (settings icon)
    ├── help.png           (help icon)
    ├── close.png          (close icon)
    └── extensionIconLocation.png (tutorial image)
```

**Total Files:** 16
**Total Lines of Code:** ~9,635
**Malicious Files:** 0

---

**END OF REPORT**
