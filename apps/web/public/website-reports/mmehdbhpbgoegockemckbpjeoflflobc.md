# Security Analysis: Ad Library Cloud (mmehdbhpbgoegockemckbpjeoflflobc)

## Extension Metadata
- **Name**: Ad Library Cloud
- **Extension ID**: mmehdbhpbgoegockemckbpjeoflflobc
- **Version**: 3.0.40
- **Manifest Version**: 3
- **Estimated Users**: ~40,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary
Ad Library Cloud is a tool designed to help users save and download ads from the Facebook Ad Library in HD quality. The extension intercepts Facebook GraphQL responses to extract ad metadata and enables one-click downloading of ad creative (images/videos). While the core functionality appears legitimate for its stated purpose, the extension employs several concerning techniques including **XHR hooking**, **postMessage handlers without origin validation**, and **code obfuscation**. These patterns create security vulnerabilities that could be exploited by malicious websites or used to inject untrusted data into Facebook pages. However, no evidence of malicious data exfiltration, credential theft, or third-party tracking was found.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. XMLHttpRequest Hooking (XHR Interception)
**Severity**: MEDIUM
**Files**: `/static/js/inject.js` (lines 6-58)

**Analysis**:
The extension injects a script into the main world context that hooks `XMLHttpRequest.prototype.open`, `.send`, and `.setRequestHeader` to intercept all HTTP requests and responses made by Facebook's web application.

**Code Evidence** (`inject.js`):
```javascript
var t = atob("TDJGd2FTOW5jbUZ3YUhGc0x3PT0="),  // Decodes to: /api/graphql/
    o = atob("VTFCUFRsTlBVa1ZF");              // Decodes to: SPONSORED
t = atob(t), o = atob(o);

var a = Object.getPrototypeOf(new XMLHttpRequest),
    s = Object.getPrototypeOf(new XMLHttpRequest).open,
    n = Object.getPrototypeOf(new XMLHttpRequest).send,
    d = Object.getPrototypeOf(new XMLHttpRequest).setRequestHeader;

a.open = function(e, t) {
  return this._method = e, this._url = t,
         this._requestHeaders = {},
         this._startTime = (new Date).toISOString(),
         s.apply(this, arguments)
};

a.send = function(e) {
  try {
    return this.addEventListener("load", (function() {
      var o = this._url ? this._url.toLowerCase() : this._url;
      if (o && o === t) {  // If URL is /api/graphql/
        if (this.responseText) {
          this.responseText.split("\n").forEach(((e, t) => {
            // Parse each line as JSON
            // Check for ad_library_main or SPONSORED data
            window.postMessage({
              type: "LIBRARY_AD_DATA",
              data: e
            }, "*");  // NO ORIGIN RESTRICTION
          }))
        }
      }
    })), n.apply(this, arguments)
  } catch (o) {}
}
```

**Attack Surface**:
1. **Global XHR hooking**: Every XMLHttpRequest made by Facebook's application is monitored
2. **Response interception**: The extension reads raw response bodies from Facebook's GraphQL API
3. **Base64 obfuscation**: Target URL `/api/graphql/` is double-base64 encoded to evade detection
4. **postMessage broadcast**: Intercepted data is sent via `postMessage(*, "*")` with wildcard origin

**Why This is Concerning**:
- Hooks into native browser APIs affect ALL JavaScript code on the page (including Facebook's own code)
- Creates a man-in-the-middle attack vector within the browser
- Could be modified to steal authentication tokens or session data from GraphQL responses
- Pattern commonly used by malware for credential theft

**Legitimate Use Case**:
The extension needs to extract ad data from Facebook's internal API responses because Facebook doesn't provide a public API for accessing Ad Library creative assets in high resolution.

**Verdict**: **MEDIUM RISK** - The hooking is limited to Facebook domains and used for legitimate data extraction, but the technique itself is intrusive and could be weaponized with minor modifications.

---

### 2. postMessage Handlers Without Origin Validation
**Severity**: MEDIUM
**Files**:
- `/static/js/content.js` (line 1298)
- `/static/js/ads.js` (line 238)

**Analysis**:
The extension's content scripts listen for `window.postMessage` events without validating the message origin, creating a cross-site scripting (XSS) vulnerability where malicious websites could inject arbitrary data.

**Code Evidence** (`content.js`, line 1298):
```javascript
window.addEventListener("message", (async e => {
  if ("LIBRARY_AD_DATA" === e.data.type) {
    m.processGraphQLResponse(e.data.data, N, z);
    await Z(z).then((e => {
      $()
    })).catch((e => {
      console.log("message listener: ", e)
    }))
  }
}))
```

**Code Evidence** (`ads.js`, line 238):
```javascript
window.addEventListener("message", (async function(o) {
  try {
    if (o?.data?.type &&
        (o.data.type === "ADS" || o.data.type === "ADS SPONSORED")) {
      const n = o?.data?.payload || {},
            l = e(n);  // Processes ad data
      if (!l) return;
      t(l);  // Calls function to render/save ad
    }
  } catch (n) {
    console.error(n)
  }
}))
```

**Attack Vector**:
1. A malicious website in another tab (or iframe on Facebook) could send:
   ```javascript
   window.postMessage({
     type: "LIBRARY_AD_DATA",
     data: { /* crafted payload */ }
   }, "*");
   ```
2. The extension would process this untrusted data via `processGraphQLResponse()`
3. Depending on the processing logic, this could lead to:
   - DOM-based XSS (if data is rendered to the page)
   - Logic bugs (if data structure is unexpected)
   - Resource exhaustion (if large payloads are sent repeatedly)

**Missing Security Check**:
The handlers should validate `event.origin` before processing:
```javascript
window.addEventListener("message", (e) => {
  // SHOULD CHECK:
  if (e.origin !== "https://www.facebook.com" &&
      e.origin !== "https://web.facebook.com") {
    return;  // Reject messages from other origins
  }
  // Process message...
});
```

**Real-World Impact**:
- **Moderate**: The extension only runs on Facebook domains (`.matches` in manifest)
- **Limited attack surface**: An attacker would need to inject scripts into Facebook pages OR trick users into visiting a malicious page while logged into Facebook
- **Data injection risk**: Crafted ad data could potentially inject malicious HTML/URLs into the extension's UI

**Verdict**: **MEDIUM RISK** - Missing origin validation is a security flaw but exploitation requires specific conditions.

---

### 3. Code Obfuscation and Minification
**Severity**: LOW (Informational)
**Files**:
- `/static/js/inject.js` (base64-encoded strings)
- `/static/js/content.js` (heavily minified)
- `/static/js/ads.js` (heavily minified)

**Analysis**:
The extension uses multiple obfuscation techniques that reduce transparency and make security auditing difficult:

1. **Double base64 encoding** in `inject.js`:
   ```javascript
   var t = atob("TDJGd2FTOW5jbUZ3YUhGc0x3PT0=");
   // First decode: L2FwaS9ncmFwaHFsLw==
   // Second decode: /api/graphql/
   ```

2. **Minified variable names**: All files use single-letter variables (e, t, n, o, a, etc.)

3. **Inline source maps**: Files include `.map` references but source maps are not accessible

**Why This Matters**:
- Makes manual code review extremely difficult
- Hides the true purpose of functions at first glance
- Common technique used by malware to evade detection
- Violates Chrome Web Store policies on code transparency (when obfuscation is not build-tool minification)

**Legitimate Justification**:
- Modern JavaScript build tools (Webpack, Rollup, Terser) automatically minify production code
- The base64 encoding could be an attempt to avoid static analysis scanners

**Verdict**: **LOW RISK** - Obfuscation itself is not malicious but reduces trustworthiness.

---

## Network Analysis

### External Endpoints
The extension exclusively communicates with Facebook domains:
- `www.facebook.com` (primary)
- `web.facebook.com` (mobile web)

### Request Types
1. **GraphQL API Requests** (`/api/graphql/`):
   - **Method**: POST
   - **Purpose**: Fetches ad metadata (impressions, reach, creative assets)
   - **Data Sent**: Facebook account ID, session tokens (DTSG, LSD), ad archive IDs
   - **Example** (from `content.js`, line 302):
     ```javascript
     await fetch("/api/graphql/", {
       method: "POST",
       headers: {
         accept: "*/*",
         "content-type": "application/x-www-form-urlencoded"
       },
       body: {
         av: accountId,
         __user: accountId,
         fb_dtsg: dtsgToken,
         lsd: lsdToken,
         variables: '{"adArchiveID":"' + adId + '","pageID":"","country":"ALL",...}',
         doc_id: "6635716889819821"
       },
       mode: "same-origin",
       credentials: "include"
     })
     ```

2. **Media Downloads** (images/videos):
   - **Method**: GET
   - **Purpose**: Downloads ad creative in HD quality
   - **URLs**: Facebook CDN URLs (extracted from GraphQL responses)
   - **Credentials**: `omit` (no cookies sent)

### Privacy Assessment
- **No third-party tracking**: All requests stay within Facebook's infrastructure
- **No data leakage**: Extension does not send user data to external servers
- **Session token usage**: Uses user's Facebook session (fb_dtsg, lsd) to authenticate API requests
  - This is necessary because the Ad Library API is not public
  - Tokens are extracted from Facebook's own page scripts

**Verdict**: **Network behavior is consistent with stated functionality** - No evidence of data exfiltration.

---

## Permission Analysis

### Declared Permissions
```json
"permissions": ["storage"],
"host_permissions": ["<all_urls>"]
```

### Permission Usage

1. **`storage`** (chrome.storage.local):
   - **Used for**: Storing download settings (noise amount, video format, quality)
   - **Files**: `content.js`, `adsList.js`
   - **Example**:
     ```javascript
     const videoOptions = await t.get("videoOptions");
     await t.set("imgOptions", {
       addNoise: true,
       noiseAmount: 8,
       quality: 0.92
     });
     ```
   - **Privacy Impact**: LOW - Only stores user preferences locally

2. **`<all_urls>`** (host permissions):
   - **Declared scope**: All URLs
   - **Actual usage**: Only Facebook domains via `content_scripts.matches`:
     ```json
     "matches": [
       "https://www.facebook.com/ads/library/*",
       "https://web.facebook.com/ads/library/*",
       "https://www.facebook.com/",
       "https://web.facebook.com/"
     ]
     ```
   - **Privacy Impact**: MEDIUM - Overly broad permission declaration

**Concern**: The `<all_urls>` permission grants access to all websites but content scripts are restricted to Facebook. The extension could silently update to run on other sites.

**Verdict**: Permissions are mostly appropriate but `<all_urls>` is over-privileged.

---

## Functionality Review

### Core Features
1. **Ad Metadata Extraction**:
   - Parses Facebook's GraphQL responses to extract ad details
   - Supports IMAGE, VIDEO, CAROUSEL, DCO, DPA display formats
   - Extracts: page name, ad text, CTA button, impressions/reach, engagement metrics

2. **High-Quality Media Download**:
   - Downloads images/videos from ad creative in original quality
   - Applies optional noise to images (anti-fingerprinting)
   - Converts videos with optional frame rate/bitrate adjustments

3. **Ad Library Enhancements**:
   - Shows impression count and estimated cost (`$0.012 * impressions`)
   - Adds download buttons to ad cards
   - Saves ads to local storage for later access

### User Experience
- **Target audience**: Marketers, ad researchers, competitive analysts
- **Value proposition**: Facebook's Ad Library UI doesn't allow easy downloading of ad creative
- **Monetization**: Unknown (no payment/subscription code detected)

---

## Data Flow Analysis

### Source-to-Sink Tracing (from ext-analyzer)
The static analyzer identified 6 exfiltration flows where sensitive data reaches network sinks. Upon manual review, these are **FALSE POSITIVES** for malicious behavior:

1. **`document.querySelectorAll` → `fetch(www.facebook.com)`**:
   - **Purpose**: Extracts DTSG/LSD tokens from Facebook's own scripts
   - **Destination**: Facebook's own GraphQL API (same-origin)
   - **Verdict**: LEGITIMATE - Required for API authentication

2. **`chrome.storage.local.get` → `fetch(www.facebook.com)`**:
   - **Purpose**: Sends ad archive IDs (from storage) to fetch impression data
   - **Data sent**: Ad IDs only (public data)
   - **Verdict**: LEGITIMATE - Fetching public ad metrics

3. **Message data → `innerHTML` / `src`**:
   - **Source**: postMessage events from inject.js
   - **Destination**: DOM manipulation to render ad cards
   - **Risk**: Could inject untrusted HTML if origin not validated (see Vuln #2)

---

## Attack Surface Summary

### High-Risk Components
1. ❌ **XHR hooking in main world** - Could be modified to steal credentials
2. ❌ **Unchecked postMessage handlers** - Vulnerable to data injection attacks

### Medium-Risk Components
1. ⚠️ **Overly broad host permissions** - Extension could expand scope via update

### Low-Risk Components
1. ✅ **Network requests** - All same-origin to Facebook
2. ✅ **Storage usage** - Only user preferences, no PII
3. ✅ **No eval() or remote code execution**

---

## Comparison to Malware Patterns

| Pattern | Present? | Malicious Intent? |
|---------|----------|-------------------|
| XHR/Fetch hooking | ✅ Yes | ❌ No - Used for ad data extraction |
| postMessage without origin check | ✅ Yes | ⚠️ Security flaw but not exploited |
| Data exfiltration to third parties | ❌ No | N/A |
| Credential theft | ❌ No | N/A |
| Cookie stealing | ❌ No | N/A |
| Remote code execution | ❌ No | N/A |
| Hidden iframe injection | ❌ No | N/A |
| Cryptocurrency mining | ❌ No | N/A |
| Click fraud | ❌ No | N/A |

---

## Recommendations

### For Users
1. **Risk tolerance**: If you need to download Facebook ads at scale, this extension works as advertised
2. **Privacy**: Your Facebook session tokens are used to access internal APIs but not sent elsewhere
3. **Trust requirement**: You must trust the developer not to push malicious updates (extension has broad permissions)

### For Developers
1. **FIX CRITICAL**: Add origin validation to postMessage handlers:
   ```javascript
   window.addEventListener("message", (e) => {
     if (!/^https:\/\/(www|web)\.facebook\.com$/.test(e.origin)) {
       return;
     }
     // Process message
   });
   ```

2. **IMPROVE**: Reduce host_permissions from `<all_urls>` to specific Facebook domains:
   ```json
   "host_permissions": [
     "https://www.facebook.com/*",
     "https://web.facebook.com/*"
   ]
   ```

3. **TRANSPARENCY**: Provide non-minified source code or detailed documentation explaining XHR hooking necessity

---

## Final Verdict

**Risk Level: MEDIUM**

**Rationale**:
- ✅ **Legitimate functionality**: The extension does what it claims (downloading Facebook ads)
- ✅ **No malicious exfiltration**: All network traffic stays within Facebook
- ❌ **Security vulnerabilities**: postMessage handlers lack origin validation
- ⚠️ **Intrusive techniques**: XHR hooking creates trust concerns
- ⚠️ **Overly broad permissions**: `<all_urls>` is unnecessary

**Recommended Action**:
- **For general users**: Avoid unless you specifically need this functionality
- **For marketers/researchers**: Acceptable with understanding of security trade-offs
- **For security-conscious users**: Wait for developer to fix postMessage origin validation

**Vulnerability Summary**:
- **Critical**: 0
- **High**: 0
- **Medium**: 2 (XHR hooking, postMessage without origin check)
- **Low**: 0

---

## Technical Appendix

### Deobfuscated Base64 Strings
```javascript
// inject.js, lines 3-5
"TDJGd2FTOW5jbUZ3YUhGc0x3PT0=" → "L2FwaS9ncmFwaHFsLw==" → "/api/graphql/"
"VTFCUFRsTlBVa1ZF" → "SPONSORED"
```

### GraphQL Document ID
```
doc_id: "6635716889819821"
```
This is Facebook's internal identifier for the `AdLibraryAdDetailsQuery` operation.

### Content Script Injection Points
1. **Isolated world** (`content.js`, `ads.js`):
   - Runs in extension context with access to Chrome APIs
   - Can read/modify DOM but not access page JavaScript

2. **Main world** (`inject.js`):
   - Runs in page context with access to native prototypes
   - Can hook XMLHttpRequest but cannot use Chrome APIs
   - Communicates with isolated world via postMessage

---

**Analysis completed**: 2026-02-15
**Analyzer**: ext-analyzer v3.0 + manual code review
