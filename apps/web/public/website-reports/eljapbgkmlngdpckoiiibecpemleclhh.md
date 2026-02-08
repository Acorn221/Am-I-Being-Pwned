# Fonts Ninja - Security Analysis Report

## Extension Metadata
- **Extension ID**: eljapbgkmlngdpckoiiibecpemleclhh
- **Name**: Fonts Ninja
- **Version**: 8.0.4
- **User Count**: ~900,000
- **Category**: Design/Productivity Tool
- **Purpose**: Font identification and inspection tool for designers

---

## Executive Summary

Fonts Ninja is a **CLEAN** extension that provides legitimate font identification functionality for web designers. The extension identifies fonts on web pages and provides detailed typography information. While it contains some sensitive patterns (hardcoded encryption key, error telemetry), these are used appropriately within the context of a legitimate design tool and do not constitute security vulnerabilities.

**Risk Level: CLEAN**

The extension demonstrates good security practices including:
- Proper CSP configuration
- No XHR/fetch hooking
- No extension enumeration or killing
- No malicious data harvesting
- No third-party tracking SDKs
- Legitimate API endpoints for font identification

---

## Detailed Analysis

### 1. Manifest Permissions Analysis

**File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/manifest.json`

**Declared Permissions**:
- `activeTab` - Access active tab for font inspection
- `tabs` - Tab management for injecting content script
- `storage` - Store user preferences and settings
- `scripting` - Execute content scripts dynamically

**Host Permissions**:
- `http://*/*` and `https://*/*` - Required to analyze fonts on all web pages

**Content Security Policy**:
```json
{
  "extension_pages": "script-src 'self'; object-src 'self'",
  "sandbox": "sandbox allow-scripts; script-src 'self'; object-src 'self'"
}
```

**Verdict**: ✅ **LEGITIMATE** - Permissions are appropriate for a font identification tool that needs to inspect CSS and fonts on any webpage. CSP properly restricts to self-hosted scripts only.

---

### 2. Content Script Analysis

**File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/contentScript.bundle.js`

**Key Behaviors**:

#### Script Injection (Lines 32-37, 50-52)
```javascript
const e = document.createElement("script");
e.id = "fonts-ninja-ext-script",
e.src = chrome.runtime.getURL("extension.bundle.js"),
(document.head || document.documentElement).appendChild(e)

// Later injects helper script
e.src = chrome.runtime.getURL("fonts-ninja-helpers/index.js")
```

**Verdict**: ✅ **LEGITIMATE** - Injects only self-hosted extension scripts (extension.bundle.js and fonts-ninja-helpers/index.js). This is standard pattern for extensions that need to run in page context to access computed styles and font metadata.

#### Message Passing (Lines 47-113)
- Bidirectional communication between content script and injected page scripts
- Messages: `inject_fonts_ninja_helpers`, `get_extension_path`, `close_fonts_ninja`, `get_machine_id`, `get_storage`, `save_storage`

**Verdict**: ✅ **LEGITIMATE** - Standard extension communication pattern. No suspicious data exfiltration.

#### Storage Access (Lines 56-72)
```javascript
chrome.storage.sync.get(s, (e => {
  const n = e && e[s] && JSON.parse(e[s]),
    t = n && n.machineId.replaceAll('"', ""),
    o = n && n.authToken && JSON.parse(n.authToken).email;
  if (t)
    if (o) chrome.storage.sync.remove(s);
    else {
      const e = Date.now();
      fetch(`https://api-v2.fonts.ninja/extension/legacy/${t}?ts=${e}`, {
        method: "GET"
      })
```

**Verdict**: ✅ **LEGITIMATE** - Legacy migration code. Checks old machineId from storage, validates with API, and cleans up. If user has email/authToken (newer auth), removes old machineId. This is proper upgrade/migration logic.

---

### 3. Background Script Analysis

**File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/background.bundle.js`

**Key Behaviors**:

#### Extension Lifecycle (Lines 2327-2346)
```javascript
chrome.action.onClicked.addListener((t => {
  chrome.tabs.sendMessage(t.id, {message: "toggle_fonts_ninja"})
}))

chrome.runtime.onInstalled.addListener((({reason: t}) => {
  t === chrome.runtime.OnInstalledReason.INSTALL &&
    chrome.runtime.setUninstallURL("https://fontsninja.typeform.com/to/cHr9TWwD")
  // Injects content script into existing tabs
}))
```

**Verdict**: ✅ **LEGITIMATE** - Standard extension activation and installation handling. Uninstall survey URL is common practice.

#### SafeFetch Function (Lines 2367-2402)
```javascript
function Ze({url: t, returnBase64: e, options: s, pageUrl: o}) {
  const r = yield fetch(t, s);
  if (r.ok) {
    return e ? btoa(arrayBuffer) : yield r.text()
  } {
    // Error reporting
    const e = {
      url: t,
      pageUrl: o,
      userAgent: navigator.userAgent,
      errorMessage: yield new Response(r.body).text(),
      statusCode: r.status,
      extensionVersion: chrome.runtime.getManifest().version,
      reason: "backgroundSafeFetch"
    },
    s = Ve.AES.encrypt(JSON.stringify(e),
      "a7457190d074fbf35ddd0f65d381ed03e281fabd9803d00b79a8c1c64d4274a6").toString();
    yield fetch("https://report.extension.k8s-hz.fontradar.com/error-report", {
      method: "POST",
      body: s
    })
  }
}
```

**Verdict**: ⚠️ **PRIVACY-SENSITIVE BUT LEGITIMATE** - Error reporting telemetry sends:
- Failed URL (font/resource URL that couldn't load)
- Page URL (where error occurred)
- User agent
- Error message
- Extension version

Data is AES-encrypted before transmission. This is error diagnostics, not malicious harvesting. The hardcoded AES key is used for transport encryption (not security-critical since it's client-side visible anyway).

**Not a vulnerability** - This is standard error reporting for debugging font loading issues.

---

### 4. Font Identification API

**File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/fonts-ninja-helpers/index.js` (Lines 8006-8025)

**Identify Function**:
```javascript
const e = "prod" === t ? "api-v2.fonts.ninja" : "api-v2-preprod.fonts.ninja",
  n = yield safeFetch(`https://${e}/extension/identify`, false, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({
      domain: location.hostname,
      url: location.href.replace(location.hash, ""),
      pairingInfos: s,
      processFontsDeflated: w  // Base64-encoded deflated font metadata
    })
  })
```

**Data Sent**:
- Current page domain/URL
- Font metadata (font families, weights, styles detected on page)
- Font file hashes (MD5) for identification

**Verdict**: ✅ **LEGITIMATE** - This is the core functionality of Fonts Ninja. The extension sends font metadata to their API to identify fonts and return information about them (similar to WhatFont or other font identification tools). URL is sent for context (some sites license fonts per-domain).

---

### 5. Checked Attack Patterns

| Pattern | Found | Verdict | Details |
|---------|-------|---------|---------|
| XHR/Fetch Hooking | ❌ No | CLEAN | No `XMLHttpRequest.prototype` or `window.fetch` modifications |
| Extension Enumeration | ❌ No | CLEAN | No `chrome.management` calls |
| Extension Disabling | ❌ No | CLEAN | No extension killing behavior |
| Residential Proxy | ❌ No | CLEAN | Proxy objects found are MobX-like (see False Positives) |
| Remote Config/Killswitch | ❌ No | CLEAN | No remote behavior control |
| Sensor Tower/Pathmatics | ❌ No | CLEAN | No market intelligence SDKs |
| AI Conversation Scraping | ❌ No | CLEAN | No ChatGPT/Claude/Gemini targeting |
| Ad/Coupon Injection | ❌ No | CLEAN | No ad injection code |
| Keylogging | ❌ No | CLEAN | Keyboard listeners are benign (see False Positives) |
| Cookie Harvesting | ❌ No | CLEAN | No `document.cookie` access |
| Social Media Scraping | ❌ No | CLEAN | No platform-specific data collection |

---

## False Positives

| Pattern | File | Line(s) | Reason |
|---------|------|---------|--------|
| Hardcoded Secret | background.bundle.js | 2393 | AES key for error report encryption - client-side visible anyway, not a secret leak |
| Proxy Objects | fonts-ninja-helpers/index.js | Various | Font rendering Proxy objects, not residential proxy infrastructure |
| React Copyright | iframe.bundle.js, extension.bundle.js | Various | Standard React library copyright notices mentioning "affiliate" |
| innerHTML Usage | iframe.bundle.js, extension.bundle.js | Various | React SVG rendering with proper namespace checks |
| Storage Access | contentScript.bundle.js | 56-72 | Legacy machineId migration, not data theft |

---

## API Endpoints

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| api-v2.fonts.ninja | Font identification API | Page URL, font metadata, MD5 hashes | LOW - Core functionality |
| api-v2-preprod.fonts.ninja | Staging environment | Same as prod | LOW - Development testing |
| report.extension.k8s-hz.fontradar.com | Error reporting | Failed URLs, user agent, errors (encrypted) | LOW - Diagnostics only |
| fontsninja.typeform.com | Uninstall survey | None (redirect on uninstall) | NONE - Standard practice |

---

## Data Flow Summary

### What Data is Collected?

1. **Font Metadata** (sent to api-v2.fonts.ninja):
   - Font families, weights, styles detected on page
   - Computed CSS styles
   - Font file MD5 hashes
   - Current page URL and domain
   - **Purpose**: Identify fonts and provide designer information

2. **Error Telemetry** (sent to fontradar.com - only on errors):
   - Failed resource URLs
   - Page URL where error occurred
   - User agent
   - Error messages
   - Extension version
   - **Purpose**: Debug font loading failures

3. **User Preferences** (stored locally in chrome.storage.sync):
   - UI settings (icon choice, theme, etc.)
   - Launch count
   - Machine ID (legacy, being phased out)

### What is NOT Collected?

- ✅ No browsing history
- ✅ No keyboard input
- ✅ No form data
- ✅ No cookies
- ✅ No authentication tokens (except legacy migration cleanup)
- ✅ No third-party analytics
- ✅ No ad network integration
- ✅ No social media scraping

---

## Privacy Considerations

### Legitimate Privacy Concerns (Disclosed Behavior)

1. **URL Sharing**: The extension sends current page URLs to fonts.ninja API when identifying fonts. This is necessary for:
   - Font licensing verification (some fonts are licensed per-domain)
   - Context for font identification
   - Similar to how any font identification service works

2. **Error Reporting**: Failed resource URLs and page contexts are sent for debugging. This could reveal:
   - Internal URLs if fonts fail to load on private networks
   - Page structure if font paths are revealing

   **Mitigation**: Data is encrypted, used only for debugging, sent only on actual errors.

### Not Privacy Concerns

- Font metadata extraction is on-device analysis
- No persistent user tracking
- No cross-site tracking
- No data selling to third parties (based on code analysis)

---

## Code Quality Observations

**Positive**:
- Modern Manifest V3
- Proper CSP implementation
- Clean separation of concerns (background, content, injected scripts)
- React-based UI (iframe.bundle.js, extension.bundle.js)
- Error handling in API calls
- Legacy code cleanup (machineId migration)

**Neutral**:
- Large bundle sizes (fonts-ninja-helpers/index.js is 1.7MB - contains font parsing libraries)
- Hardcoded AES key (not security-critical in this context)
- Some minified code patterns

---

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
1. **No Malicious Patterns**: Extension contains zero indicators of malware, data theft, or user harm
2. **Legitimate Functionality**: All code serves the stated purpose (font identification for designers)
3. **Appropriate Permissions**: Host permissions necessary for core function
4. **Transparent Data Flows**: API calls align with expected behavior of font ID tool
5. **No Third-Party Trackers**: No Sensor Tower, analytics SDKs, or ad networks
6. **Good Security Practices**: CSP, Manifest V3, encrypted error reports

**Privacy Rating**: **MEDIUM-LOW**
- URLs are shared with fonts.ninja API (expected for this tool type)
- Error telemetry is privacy-sensitive but reasonable
- No unexpected data collection

**Recommendation**:
- ✅ **SAFE TO USE** for general users
- ✅ Appropriate for its stated purpose
- ⚠️ Users on sensitive/internal networks should be aware URLs are shared with fonts.ninja API during font identification
- ⚠️ Consider reviewing Privacy Policy for data retention and usage disclosures

---

## Files Analyzed

### Primary Files
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/manifest.json`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/background.bundle.js` (2,418 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/contentScript.bundle.js` (131 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/extension.bundle.js` (2,199 lines - React UI)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/iframe.bundle.js` (7,192 lines - React iframe UI)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/fonts-ninja-helpers/index.js` (Large - font parsing library)

### Supporting Files
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/eljapbgkmlngdpckoiiibecpemleclhh/deobfuscated/frame.html`
- Custom fonts in `/fonts/` directory (Aeonik variable fonts)

---

## Comparison to Known Malicious Extensions

Unlike the malicious VPN extensions analyzed previously (StayFree, StayFocusd, Urban VPN, YouBoost, VeePN):

| Feature | Fonts Ninja | Malicious Extensions |
|---------|-------------|---------------------|
| XHR/Fetch Hooking | ❌ None | ✅ Global interception |
| Extension Killing | ❌ None | ✅ Disables competitors |
| Hidden SDKs | ❌ None | ✅ Sensor Tower Pathmatics |
| AI Scraping | ❌ None | ✅ ChatGPT/Claude/Gemini |
| Ad Injection | ❌ None | ✅ Search/video manipulation |
| Residential Proxy | ❌ None | ✅ Troywell infrastructure |
| Remote Killswitch | ❌ None | ✅ Server-controlled behavior |
| User Tracking | Minimal (URL for font ID) | ✅ Comprehensive profiling |

---

## Conclusion

**Fonts Ninja is a CLEAN extension** that functions as advertised - a professional font identification and inspection tool for web designers. While it sends page URLs to its API for font identification (expected behavior for this category of tool), it contains no malicious code, no hidden trackers, and no user-hostile behaviors.

The extension represents a legitimate commercial product with reasonable data practices for its use case.

**Final Verdict: CLEAN** ✅
