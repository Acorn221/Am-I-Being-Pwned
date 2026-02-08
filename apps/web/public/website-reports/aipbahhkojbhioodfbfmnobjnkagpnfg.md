# Security Analysis Report: Auto Refresh Page - Reload Pages Automatically & Page Monitor Easily

## Extension Metadata
- **Extension ID**: aipbahhkojbhioodfbfmnobjnkagpnfg
- **Extension Name**: Auto Refresh Page - Reload Pages Automatically & Page Monitor Easily
- **User Count**: ~60,000
- **Version**: 1.0.27
- **Manifest Version**: 3

## Executive Summary

This extension provides page auto-refresh and monitoring functionality. The analysis reveals **license validation tracking mechanisms** and **extensive cookie-based analytics** that sync user behavior data to remote servers. While the core auto-refresh functionality appears legitimate, the extension implements **obfuscated usage tracking** with cookies synced to third-party domains and base64-encoded counters that monitor feature usage without clear disclosure.

**Overall Risk Level**: MEDIUM

The extension does not contain malicious code like data exfiltration, credential theft, or proxy injection. However, it implements privacy-concerning tracking practices including usage counters, license validation calls, and persistent cookie synchronization. The freemium model includes remote license validation with feature gating based on server responses.

## Vulnerability Details

### 1. Obfuscated License Validation System
**Severity**: MEDIUM
**File**: `js/background.js` (lines 276-320, 1463-1492, 1720-1757)
**Code Sample**:
```javascript
const o = "https://auto-refresh.extfy.com/lempay/validate.php",
  s = "_serub_k_dgsp",
  u = "_subc_pd_dgsp",
  c = "_fxyz_s";

// Obfuscated extension ID check
function(e) {
  let t = chrome.runtime.id;
  if (e[c] = e[c].split(" "), e[c] = e[c].map(e => e.slice(2, -2)),
      function(e) {
        return e.map(e => String.fromCharCode(e)).join("")
      }(e[c]) !== t) return !1;
  return !0
}

// License validation on startup
var r = await fetch(`${o}?${_}`, {
  method: "POST",
  body: new URLSearchParams({
    license_key: n,
    type: "validate",
    extension_version: t
  })
});
```
**Description**: The extension uses character code obfuscation to store and validate the extension ID against stored values. It contacts `auto-refresh.extfy.com/lempay/validate.php` for license validation on startup. The obfuscated string "749765 4210563 9611242 459861 729735 6110463..." decodes to the extension ID "aipbah..." (first 6 chars match extension ID).

**Verdict**: MEDIUM RISK - While license validation itself is not malicious, the obfuscation techniques and silent data wiping on validation failure (clearing extension data) are concerning. The extension can remotely disable itself via license server.

### 2. Excessive Host Permissions
**Severity**: MEDIUM
**File**: `manifest.json` (line 16)
**Code Sample**:
```json
"host_permissions":["<all_urls>"],
"content_scripts": [
  {
    "matches": ["<all_urls>","file:///*"],
    "js": ["js/jquery.js","js/jquery.simple.timer.js","js/script.js"],
    "run_at": "document_end"
  }
]
```
**Description**: The extension requests access to all URLs including file:// protocol. While needed for auto-refresh functionality, this grants access to all browsing data. Content scripts inject jQuery and custom scripts into every page.

**Verdict**: MEDIUM RISK - Legitimate for core functionality but creates large attack surface. No evidence of abuse detected, but permission scope is broader than ideal.

### 3. Undisclosed Usage Tracking with Obfuscated Counters
**Severity**: MEDIUM
**File**: `js/background.js` (lines 6-12, 284-286, 307-321, 1108-1124), `js/script.js` (lines 66-131)
**Code Sample**:
```javascript
// Obfuscated counter variable names
const _ = "_werptrg_dpo",  // Notification counter
  a = "_srbop_ikf",        // Sound playback counter
  i = "_rtyio_fghj",       // URL opening counter
  s = "_serub_k_dgsp",     // Subscription status
  u = "_subc_pd_dgsp";     // Validation status

// Base64 encoding with random padding to obscure values
function U(e) {
  return E(4) + h(e) + E(3)  // Random(4) + btoa(value) + Random(3)
}

// Increment counter and sync to cookie
m++, chrome.storage.local.set({
  [a]: U(m)
}), Q(U(m), a)

// Cookie synchronization to third-party domain
function Q(e, t) {
  chrome.cookies.set({
    url: "https://auto-refresh.extfy.com/feedback.php",
    name: t,
    value: e,
    domain: "auto-refresh.extfy.com",
    httpOnly: true,
    expirationDate: (new Date).getTime() / 1e3 + 31536e4  // 1 year
  })
}

// Every 5 seconds sync
setInterval(() => {
  S(), chrome.storage.local.get([s], e => {
    Q(e[s], s)  // Sync to cookie
  })
}, 5e3)
```
**Description**: Extension tracks multiple usage metrics (notifications shown, sounds played, URLs opened) using obfuscated variable names and base64-encoded values. Counters are synced to `auto-refresh.extfy.com` cookies every 5 seconds with 1-year expiration. The encoding function wraps values in random padding to hide tracking from inspection.

**Tracked Metrics**:
- `_srbop_ikf`: Sound playback count
- `_werptrg_dpo`: Notification count
- `_rtyio_fghj`: Auto-open URL count
- `_serub_k_dgsp`: Subscription key
- `_subc_pd_dgsp`: License validation status

**Verdict**: MEDIUM RISK - Privacy-invasive telemetry without transparent disclosure. The obfuscation (base64 + random padding, cryptic variable names) suggests intent to hide tracking mechanisms. No opt-out available. Cookies persist for 1 year across browser sessions.

### 4. Remote Configuration and Kill Switch
**Severity**: MEDIUM
**File**: `js/background.js` (lines 1463-1492)
**Code Sample**:
```javascript
let e = await chrome.storage.local.get([s, u, c]);
if (void 0 === e[s] || null === e[s] || "" === e[s] || "ntvd" === e[u])
  return f = !1, Q("ntvd", u), !1;

if (!0 === e?.valid || 1 == e?.success) return chrome.storage.local.set({
  [u]: "vd"
}), f = !0, !0;

if (!1 === e?.valid || "error" === e?.status) {
  let e = {
    [u]: "ntvd"
  };
  return chrome.storage.local.set(e), f = !1, Q("ntvd", u), !1
}
```
**Description**: The extension contacts remote server on startup to validate license. Validation failure can disable features or clear user data. The server response controls extension behavior via flags.

**Verdict**: MEDIUM RISK - Remote kill switch capability. While legitimate for paid extensions, this allows developer to remotely control or disable the extension.

### 5. Usage Tracking and Analytics
**Severity**: LOW
**File**: `js/background.js` (lines 1260-1278)
**Code Sample**:
```javascript
else if ("send_suggestion" === r.action) {
  const e = new FormData;
  e.append("action", "feedback_autorefresh"),
  e.append("email", r.email),
  e.append("message", r.message),
  e.append("extension_version", chrome.runtime.getManifest().version),
  e.append("browserOsInfo", JSON.stringify(r.browserOsInfo)),
  async function(e = "", t = {}) {
    try {
      return (await fetch(e, {
        method: "POST",
        body: t
      })).json()
    } catch (e) {}
  }("https://auto-refresh.extfy.com/feedback_api.php", e)
}
```
**Description**: Extension collects browser/OS information when users submit feedback. Data sent to `auto-refresh.extfy.com/feedback_api.php`.

**Verdict**: LOW RISK - Standard analytics for feedback system. Browser info collection is reasonable for debugging but should be disclosed in privacy policy.

### 6. Page Content Monitoring and Keyword Detection
**Severity**: LOW
**File**: `js/script.js` (lines 163-278)
**Code Sample**:
```javascript
const e = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
  acceptNode: t => {
    const r = window.getComputedStyle(e);
    return "none" === r.display || "hidden" === r.visibility ?
      NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
  }
});

// Highlight and auto-click matching keywords
const r = document.createElement("span");
r.style.cssText = "background-color: yellow; color: black;";
```
**Description**: Extension uses TreeWalker to scan all page text for keywords. Can highlight matches and auto-click links containing keywords. This is the advertised functionality.

**Verdict**: LOW RISK - Legitimate feature for page monitoring. Users explicitly configure keywords to monitor. No evidence of data exfiltration.

## False Positives

| Finding | Reason | Explanation |
|---------|---------|-------------|
| jQuery usage | Library inclusion | Standard jQuery library (js/jquery.js) used for DOM manipulation |
| atob/btoa usage | Base64 encoding | Used for license key encoding/decoding, not code obfuscation for malicious purposes |
| setInterval every 2.5s | Keep-alive mechanism | Sends ping to content scripts to maintain connection (lines 1542-1551) |
| Chrome cookies API | Legitimate permission | Required for cookie-based license validation system |
| TreeWalker DOM traversal | Core functionality | Necessary for keyword detection feature |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://auto-refresh.extfy.com/lempay/validate.php` | License validation | License key, extension version, user UUID | MEDIUM |
| `https://auto-refresh.extfy.com/lempay/api-log.php` | Error logging | Error messages, browser info | LOW |
| `https://auto-refresh.extfy.com/feedback_api.php` | User feedback | Email, message, browser/OS info | LOW |
| `https://auto-refresh.extfy.com/feedback.php` | Cookie synchronization | Extension version, usage counters (every 5 seconds) | MEDIUM |
| `https://auto-refresh.extfy.com/other-data.json` | Remote config fetch | None (GET request) | LOW |
| `https://softpulseinfotech.com/extensions/auto_refresh/feedback.php` | Legacy analytics endpoint | Unknown (defined but unused) | MEDIUM |

## Data Flow Summary

1. **Installation/Startup**:
   - Extension generates or retrieves UUID
   - Contacts `validate.php` to check license status
   - Sets cookies on `auto-refresh.extfy.com` domain
   - Stores validation status in local storage

2. **Runtime Operation**:
   - Every 5 seconds: syncs license cookies with remote server
   - Every 2.5 seconds: pings content scripts to check if active
   - On page load: injects content scripts with jQuery
   - User-configured: monitors pages for keywords, auto-refreshes

3. **Data Storage**:
   - Local storage: license keys (obfuscated), validation status, user preferences
   - Cookies: license identifiers, user tracking (1-year expiration)

4. **No Evidence Of**:
   - Keystroke logging
   - Form data harvesting
   - Cookie theft from other domains
   - Proxy/VPN functionality
   - Ad/coupon injection
   - Extension enumeration/killing
   - AI conversation scraping
   - Market intelligence SDKs

## Overall Risk Assessment

**MEDIUM**

### Risk Factors:
- Obfuscated license validation with remote kill switch capability
- Excessive permissions (`<all_urls>`)
- Persistent tracking cookies synced every 5 seconds
- Remote server can disable extension or features
- Broad content script injection on all pages

### Mitigating Factors:
- Core functionality (auto-refresh, keyword monitoring) appears legitimate
- No evidence of data exfiltration beyond licensing
- No malicious payload delivery mechanisms detected
- No credential harvesting or keylogging
- Code is relatively clean and readable (aside from licensing layer)

### Recommendations:
1. Users should be aware this is a paid extension with license validation
2. Extension can be remotely disabled by developer
3. Review privacy policy for cookie and tracking disclosures
4. Consider alternatives if concerned about licensing server dependency
5. Extension legitimately needs broad permissions for its core features

### Verdict:
This extension implements legitimate auto-refresh and page monitoring features but uses **privacy-invasive tracking** via obfuscated cookie-based analytics. The licensing infrastructure creates privacy and availability concerns. **No malicious functionality** (credential theft, data exfiltration, proxy injection) was detected.

### Key Privacy Concerns:
1. **Obfuscated usage tracking**: Base64-encoded counters with cryptic variable names hide telemetry
2. **Persistent cookies**: 1-year expiration on third-party domain (`auto-refresh.extfy.com`)
3. **Frequent syncing**: Usage data synced every 5 seconds to remote server
4. **User UUID tracking**: Persistent identifier sent with license validation
5. **No opt-out**: Tracking cannot be disabled without removing extension
6. **Cookies permission misuse**: Used solely for analytics, not core functionality

### Safe for Use If:
- You accept persistent usage tracking by developer
- You trust `extfy.com` infrastructure
- You're comfortable with remote license validation
- You need the specific auto-refresh features offered

### Consider Alternatives If:
- You prioritize privacy over advanced features
- You want local-only auto-refresh tools
- You're concerned about third-party cookie tracking
- You need offline-capable extensions
