# Vulnerability Analysis Report

## Extension Metadata
- **Name:** What Font - font finder
- **Extension ID:** opogloaldjiplhogobhmghlgnlciebin
- **User Count:** ~100,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-07

---

## Executive Summary

The "What Font - font finder" extension is a **CLEAN** browser extension designed to help users identify fonts on web pages. The extension uses legitimate techniques to analyze DOM elements and extract font information using `getComputedStyle()` and canvas text measurement. No malicious behavior, network exfiltration, tracking, or suspicious code patterns were detected.

**Overall Risk Level: CLEAN**

The extension demonstrates proper security practices:
- Legitimate manifest permissions for its functionality
- No network calls or external API endpoints
- No data exfiltration mechanisms
- Standard React UI components
- Clean service worker with proper chrome.scripting API usage
- No obfuscation beyond standard bundling

---

## Vulnerability Details

### 1. Permissions Analysis
**Severity:** CLEAN
**Files:** `manifest.json`

**Permissions Declared:**
```json
"permissions": [
  "tabs",
  "activeTab",
  "scripting"
],
"host_permissions": [
  "<all_urls>"
]
```

**Analysis:**
- `tabs` + `activeTab`: Required to query active tab and get page information
- `scripting`: Required to inject font analysis code via `chrome.scripting.executeScript()`
- `<all_urls>` host permissions: Necessary to analyze fonts on any website
- All permissions are justified for the extension's stated functionality

**Content Security Policy:**
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
- Properly restrictive CSP prevents loading external scripts
- No `unsafe-eval` or `unsafe-inline` directives

**Verdict:** ✅ CLEAN - All permissions are appropriate and necessary for font analysis functionality.

---

### 2. Background Service Worker Analysis
**Severity:** CLEAN
**Files:** `js/serviceWorker.js`

**Key Functions:**

1. **Font Analysis Function (executeScript target):**
```javascript
const A = () => {
  const e = {
    title: document.title,
    url: window.location.href,
    iconUrl: (null == (t = document.querySelector("link[rel~='icon']")) ? void 0 : t.href) || ""
  },
  r = Array.from(document.querySelectorAll("*")),
  n = Array.from(new Set(r.flatMap((t => getComputedStyle(t).fontFamily.split(","))).map((t => t.trim().replace(/^['"]|['"]$/g, ""))))),
  // Color extraction and font detection via canvas measurement
  ...
}
```

**Behavior:**
- Analyzes all DOM elements on the page using `getComputedStyle()`
- Extracts `fontFamily` and `backgroundColor` CSS properties
- Uses canvas text measurement to detect actual rendered fonts
- Returns data structure with page info, fonts, and colors
- **No network transmission** - all data stays local

2. **Message Handling:**
```javascript
chrome.runtime.onMessage.addListener(k)
chrome.action.onClicked.addListener(q)
```
- Listens for `InspectFullPage` action from popup
- Uses `chrome.tabs.sendMessage()` to communicate with content script
- No external message handlers or unauthorized listeners

**Verdict:** ✅ CLEAN - Service worker performs legitimate font analysis without data exfiltration.

---

### 3. Content Script Analysis
**Severity:** CLEAN
**Files:** `js/contentScript.js` (14,641 lines)

**Composition:**
- **React 18.2.0** bundled library (lines 1-7000+)
- **Ant Design** UI components (lines 7000-13000+)
- **Color parsing utilities** (color-convert library, lines 13000-14000)
- **Extension-specific UI code** (lines 14000-14641)

**Extension Logic:**

1. **Modal UI Injection:**
```javascript
window.onload = async () => {
  chrome.runtime.onMessage.addListener((({action: n}) => {
    switch (n) {
      case Hb.StartInspector:
        e = document.createElement("div")
        e.id = mb
        document.querySelector("body").after(e)
        t = J.createRoot(e)
        t.render(Z.jsx(U.StrictMode, { children: Z.jsx(Qb, {...}) }))
    }
  }))
}
```
- Injects React root only when user activates extension
- Creates isolated DOM element with unique ID
- Renders modal UI to display font information

2. **User Interaction:**
```javascript
const Bb = e => chrome.runtime.sendMessage(e)
// "Rate us!" button opens Chrome Web Store
window.open(`https://chrome.google.com/webstore/detail/${chrome.runtime.id}`, "_blank")
```
- Only external URL is Chrome Web Store review page
- Uses `chrome.runtime.id` to link to extension's own listing
- No tracking parameters or referral codes

3. **No Suspicious Patterns:**
- ❌ No `eval()`, `Function()`, or dynamic code execution
- ❌ No `fetch()`, `XMLHttpRequest`, or network calls
- ❌ No cookie access or localStorage harvesting
- ❌ No keylogger or input monitoring
- ❌ No WebSocket connections
- ❌ No third-party SDK injection

**Verdict:** ✅ CLEAN - Content script contains standard React UI components with no malicious behavior.

---

### 4. Data Flow Analysis

**Data Collection:**
- Page title
- Page URL (current tab only)
- Page favicon URL
- CSS font-family declarations
- Actual rendered fonts (via canvas measurement)
- Background colors (top 6 by frequency)

**Data Storage:**
- All data processed in memory only
- No persistence to `chrome.storage`
- No localStorage/sessionStorage usage
- No IndexedDB or WebSQL usage

**Data Transmission:**
- **Zero external network requests**
- Only internal messaging between content script and service worker
- Data displayed in modal UI, never transmitted externally

**Verdict:** ✅ CLEAN - All collected data remains local and is used solely for UI display.

---

### 5. Third-Party Dependencies

| Library | Version | Purpose | Risk |
|---------|---------|---------|------|
| React | 18.2.0 | UI framework | CLEAN |
| React-DOM | 18.2.0 | DOM rendering | CLEAN |
| Ant Design | ~5.x | UI components | CLEAN |
| color-convert | Unknown | Color parsing | CLEAN |
| classnames | Unknown | CSS class utilities | CLEAN |

**Analysis:**
- All libraries are legitimate open-source projects
- Used for standard UI rendering and styling
- No malicious modifications detected in bundled code
- Standard React SVG `innerHTML` usage (known false positive)

**Verdict:** ✅ CLEAN - All dependencies are legitimate and unmodified.

---

### 6. Obfuscation and Code Quality

**Bundling:**
- Code is minified/uglified by webpack/bundler
- Variable names shortened (e.g., `e`, `t`, `n`, `r`)
- No malicious obfuscation techniques detected

**Readable Patterns:**
- React component structure is identifiable
- Function logic is traceable
- String literals are unobfuscated
- No string concatenation tricks or encoding

**Verdict:** ✅ CLEAN - Standard production bundling, not malicious obfuscation.

---

## False Positive Analysis

| Pattern | Location | Reason | Status |
|---------|----------|--------|--------|
| `innerHTML` | contentScript.js:1132 | React SVG rendering (`<svg>` tags require innerHTML) | Known FP ✓ |
| `dangerouslySetInnerHTML` | contentScript.js:673 | React prop name in library code, not used in extension | Known FP ✓ |
| `MSApp.execUnsafeLocalFunction` | contentScript.js:1138 | React DOM library compatibility for old IE/Edge | Known FP ✓ |
| `window.open()` | contentScript.js:14567 | Opens Chrome Web Store for reviews, no tracking | Legitimate ✓ |

---

## API Endpoints

**Finding:** No external API endpoints or network connections detected.

| Endpoint | Purpose | Risk |
|----------|---------|------|
| N/A | N/A | N/A |

The extension operates entirely offline after installation.

---

## Attack Surface Map

### External Inputs
1. **User-triggered activation** (clicking extension icon)
   - Risk: None - standard user interaction
2. **DOM content from visited pages**
   - Risk: None - only reads CSS properties, no code execution
3. **Message passing** (chrome.runtime.onMessage)
   - Risk: None - only accepts predefined action types

### Privileged Operations
1. **chrome.scripting.executeScript()**
   - Risk: Low - only injects predefined font analysis function
   - Mitigation: Function code is static, no dynamic evaluation
2. **<all_urls> host permissions**
   - Risk: Low - read-only access to CSS properties
   - Mitigation: No data exfiltration mechanisms

### Data Exposure
- **No sensitive data accessed** (no cookies, passwords, form data, etc.)
- **No PII collection** (only public CSS information)
- **No cross-site tracking**

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Strengths
✅ Manifest V3 compliance with proper CSP
✅ No network communication whatsoever
✅ Transparent functionality matching description
✅ Minimal permissions usage (only what's necessary)
✅ No tracking, analytics, or telemetry
✅ Open-source libraries used appropriately
✅ No code obfuscation beyond standard bundling
✅ Proper use of chrome.scripting API (MV3 best practice)

### Potential Concerns
⚠️ `<all_urls>` permission is broad, but justified for font analysis
ℹ️ Large bundled React library (14K+ lines) but all legitimate

### Recommendations
- Extension is safe for users
- Functionality matches advertised purpose
- No privacy or security concerns identified
- Code quality is professional and follows best practices

---

## Conclusion

The "What Font - font finder" extension is a **legitimate, safe utility** for identifying fonts on web pages. It uses standard browser APIs to extract CSS information and display it to the user via a React-based modal interface. No malicious code, tracking, data exfiltration, or suspicious behavior was detected during this comprehensive analysis.

**Final Verdict: CLEAN**

---

## Analyst Notes

- Extension architecture follows modern MV3 patterns
- React-based UI is well-structured and professional
- Font detection algorithm using canvas text measurement is clever and legitimate
- No attempts to hide functionality or obfuscate behavior
- Chrome Web Store link for ratings is the only external navigation
- All data processing happens client-side with no server communication
