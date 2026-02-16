# Vulnerability Assessment Report

## Extension Metadata
- **Name**: Simplescraper — a fast and free web scraper
- **Extension ID**: lnddbhdmiciimpkbilgpklcglkdegdkg
- **Version**: 2.1.3
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Simplescraper is a web scraping extension that provides legitimate functionality for extracting data from web pages. The extension uses Firebase for authentication, integrates with Google's Gemini AI API for data enhancement, and employs Chrome's debugger API for network traffic monitoring. While the core functionality appears legitimate, **several security concerns warrant a MEDIUM risk rating**, primarily due to:

1. **Exposed API keys** for Gemini AI in client-side code
2. **Broad debugger permissions** allowing network request interception
3. **Optional cookies permission** that could access sensitive session data
4. **Remote authentication flow** via offscreen documents and iframes

The extension does not exhibit characteristics of malware, proxy infrastructure, or malicious data exfiltration. Its primary risk stems from the powerful permissions it requests and potential for API key abuse.

---

## Vulnerability Details

### 1. MEDIUM: Hardcoded Google Gemini API Key Exposure

**Severity**: MEDIUM
**Files**:
- `assets/sidepanel.js-55157a5e.js` (line 7625)

**Description**:
The extension contains a hardcoded Google Gemini API key embedded directly in client-side JavaScript:

```javascript
d = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=AIzaSyCrJozQpHkFVy1V7LlxPkoWUsb1MVI30W0", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify(c)
})
```

**Risk**:
- Any user who inspects the extension code can extract and abuse this API key
- Attackers could use the key for unauthorized Gemini API calls, potentially incurring costs for the extension developer
- The key has no apparent rate limiting or origin restrictions visible in the code
- All safety thresholds are set to "BLOCK_NONE", allowing potentially harmful content generation

**Verdict**: This is a definite security issue. API keys should never be exposed in client-side code. The proper approach is to proxy AI requests through a backend service that securely manages credentials.

---

### 2. MEDIUM: Chrome Debugger API for Network Traffic Interception

**Severity**: MEDIUM
**Files**:
- `service-worker-loader.js` (lines 330-666, 730, 961-963)

**Description**:
The extension uses Chrome's debugger API to attach to tabs and monitor network traffic:

```javascript
await chrome.debugger.attach({
  tabId: e
}, "1.3"), await chrome.debugger.sendCommand({
  tabId: e
}, "Network.enable"), m.add(e)
```

The background script then intercepts network requests and responses:
```javascript
const b = async (e, t, r) => {
  if (!w.isMonitoring) return;
  const a = e.tabId;
  m.has(a) && ("Network.requestWillBeSent" === t ? R(r) : "Network.responseReceived" === t && await x(a, r))
}
```

And extracts response bodies:
```javascript
const n = await chrome.debugger.sendCommand({
  tabId: e
}, "Network.getResponseBody", {
  requestId: t
})
```

**Risk**:
- The debugger API provides extremely broad access to all network traffic on monitored tabs
- While used for legitimate scraping purposes, this could capture sensitive data (auth tokens, API keys, session cookies) in transit
- The extension requests user permission with justification "To access advanced scraping capabilities for dynamic websites"
- Network data is stored in-memory and could be accessed by content scripts or exfiltrated if the extension were compromised

**Verdict**: Legitimate use for web scraping functionality, but represents significant attack surface. The permission is optional and user-gated, which mitigates risk. No evidence of data exfiltration found.

---

### 3. MEDIUM: Optional Cookies Permission

**Severity**: MEDIUM
**Files**:
- `manifest.json` (lines 20-22)

**Description**:
The extension declares optional cookies permission:

```json
"optional_permissions": [
  "cookies"
],
"optional_host_permissions": [
  "<all_urls>"
]
```

**Risk**:
- If granted, the extension could read cookies from all websites, including authentication tokens, session IDs, and tracking identifiers
- The permission is justified in `permission-manager-bfeae7e7.js` as "To save authentication state with your recipes"
- No evidence found in the analyzed code of actual cookie access, but the permission creates potential for abuse
- Combined with `<all_urls>` host permission, this grants very broad access

**Verdict**: Optional permission requiring explicit user consent mitigates risk. Justification appears legitimate for saving authenticated scraping sessions. No malicious cookie harvesting detected in code review.

---

### 4. LOW: Firebase Authentication via Offscreen Document

**Severity**: LOW
**Files**:
- `assets/offscreen.js-52b920b1.js`
- `src/offscreen/auth.html`
- `assets/auth-b7569c26.js`

**Description**:
The extension uses Chrome's offscreen document API to load an external authentication page in an iframe:

```javascript
const e = "https://simplescraper.io/extension-login/signInWithPopup.html";
const n = document.createElement("iframe");
n.src = e, n.style.width = "100%", n.style.height = "100%"
document.body.appendChild(n)
```

Firebase config is exposed in client code:
```javascript
const O = {
  apiKey: "AIzaSyAhP8Yhe4pu4ehTbRYmvMmGMEBZKkoHcEc",
  authDomain: "easy-scraper.firebaseapp.com",
  projectId: "easy-scraper",
  storageBucket: "easy-scraper.appspot.com",
  messagingSenderId: "985367128006",
  appId: "1:985367128006:web:21e1c5d87e97af3c0b8e8b"
}
```

**Risk**:
- External iframe could be compromised if `simplescraper.io` is attacked
- Firebase public config exposure is standard practice (not a vulnerability by itself)
- Authentication flow relies on cross-origin postMessage communication
- No evidence of credential theft or session hijacking

**Verdict**: Standard Firebase authentication implementation. The use of offscreen documents follows Chrome extension best practices for OAuth flows. Firebase config exposure is expected and not a security issue.

---

### 5. LOW: Content Script Injection and Dynamic Execution

**Severity**: LOW
**Files**:
- `service-worker-loader.js` (lines 41-131)
- `assets/content-bundle.js-02e637ac.js`

**Description**:
The extension dynamically injects content scripts into web pages:

```javascript
await chrome.scripting.executeScript({
  target: {
    tabId: e
  },
  files: ["assets/content-bundle.js-02e637ac.js"]
})
```

And uses programmatic script execution:
```javascript
const [n] = await chrome.scripting.executeScript({
  target: {
    tabId: e
  },
  func: e => !!window.__executeContentScript && window.__executeContentScript(e),
  args: [t]
})
```

**Risk**:
- Content scripts have access to page DOM and could modify page behavior
- The `scripting` permission combined with `activeTab` allows injection on user-visited pages
- Content scripts communicate with background via message passing and could relay sensitive data
- No evidence of malicious DOM manipulation, XSS injection, or credential theft

**Verdict**: Standard content script architecture for browser extensions. The injection is permission-gated (`activeTab`) and only occurs when user activates the extension. Code review shows legitimate scraping operations (list detection, element selection, data extraction).

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `Proxy` keyword | `assets/vue-vendor-b1160d8f.js`, `assets/firebase-vendor-54967fa2.js` | Standard JavaScript Proxy objects used by Vue.js reactivity system and Firebase SDK, not residential proxy infrastructure |
| `innerHTML` usage | `assets/vue-vendor-b1160d8f.js` | Vue.js SVG rendering (`createElementNS("http://www.w3.org/2000/svg")`), not XSS vulnerability |
| Firebase API keys | `assets/auth-b7569c26.js` | Firebase public configuration (expected and safe) |
| `fetch` calls | Multiple files | Legitimate API calls to Gemini, Firebase, and extension update checks |
| `window.__` global variables | `assets/content-bundle.js-02e637ac.js` | Extension-specific namespacing to avoid conflicts (`__ContentBridge_injected`, `__ListDetector_injected`) |

---

## API Endpoints & External Services

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| `https://simplescraper.io/*` | Official extension website, docs, upgrade pages | LOW - Developer-controlled |
| `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent` | Google Gemini AI for data enhancement | MEDIUM - Hardcoded API key |
| `https://simplescraper.io/extension-login/signInWithPopup.html` | OAuth authentication flow iframe | LOW - Standard auth pattern |
| `https://firestore.googleapis.com/*` | Firebase Firestore (via SDK) | LOW - Standard cloud storage |
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store update URL | LOW - Standard Chrome extension update |

---

## Data Flow Summary

### Data Collection
1. **Scraped Web Data**: Extension extracts DOM elements, text content, links, and structured data from user-selected web pages
2. **Network Traffic**: When debugger permission is granted, captures XHR/Fetch request/response bodies for JSON extraction
3. **User Recipes**: Stores scraping configurations (selectors, filters, pagination rules) in Chrome local storage
4. **Authentication State**: Firebase user tokens stored in Chrome local storage

### Data Storage
- **Local Storage**: Recipes, scraping state, authentication tokens, cached network data
- **IndexedDB**: Used by Firebase SDK for offline persistence
- **Firestore (Cloud)**: User recipes synced to Firebase cloud database (collection: `recipes`, `customers`)

### Data Transmission
- **To Gemini API**: Scraped data sent for AI enhancement (e.g., "extract email from text")
- **To Firebase**: User authentication, recipe storage, customer data
- **To Extension Website**: Links for upgrades, documentation (no automatic data transmission detected)

### No Evidence Of
- ✓ Data exfiltration to third-party tracking services
- ✓ Residential proxy infrastructure or P2P networking
- ✓ Keylogging or form input capture
- ✓ Credential harvesting beyond OAuth flow
- ✓ Extension fingerprinting or killing
- ✓ Ad/coupon injection
- ✓ Market intelligence SDK integration (Sensor Tower, Pathmatics, etc.)
- ✓ Cryptocurrency mining

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

### Justification
Simplescraper is a **legitimate web scraping tool** with expected functionality. The MEDIUM risk rating is assigned due to:

1. **Exposed API Key**: Hardcoded Gemini API key is a definite security flaw that could be exploited
2. **Powerful Permissions**: Debugger API + optional cookies + `<all_urls>` creates significant attack surface
3. **Privacy Concerns**: Network traffic interception (even for legitimate purposes) captures potentially sensitive data

### Mitigating Factors
- No malicious behavior detected in code analysis
- Permissions are clearly justified and user-gated (optional permissions require explicit consent)
- Extension has legitimate use case (web scraping) and active user base (60,000 users)
- No evidence of data exfiltration, tracking, or monetization beyond legitimate SaaS model
- Developer-controlled infrastructure (simplescraper.io) with no third-party analytics detected

### Recommendations
**For Users**:
- Only grant debugger and cookies permissions if you actively use the scraping features
- Be aware that scraped data may be sent to Google's Gemini API for AI enhancement
- Review what data you're scraping before using AI features

**For Developers**:
- **URGENT**: Remove hardcoded Gemini API key and implement server-side proxy for AI requests
- Consider reducing permission scope (e.g., specific host permissions instead of `<all_urls>`)
- Implement client-side encryption for sensitive recipe data before cloud sync
- Add content security policy to prevent potential injection attacks
- Audit Firebase security rules to ensure user data isolation

---

## Conclusion

Simplescraper operates as advertised: a web scraping tool with AI enhancement capabilities. The primary security concerns stem from implementation choices (exposed API keys) rather than malicious intent. With proper remediation of the API key exposure, this would be a LOW risk extension.

**Verdict**: MEDIUM risk - Legitimate functionality with security implementation issues that should be addressed.
