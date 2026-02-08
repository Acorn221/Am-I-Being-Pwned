# Security Analysis Report: Shopee Save Extension

## Extension Metadata
- **Name**: Shopee Save - Download Product Images & Video
- **Extension ID**: likamafaejphcadlcclbnjddckicmblo
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Version**: 3.0.21
- **Analysis Date**: 2026-02-07

## Executive Summary

**OVERALL RISK: HIGH**

The Shopee Save extension exhibits multiple HIGH-severity security concerns. While the extension's core functionality (downloading Shopee product images and videos) appears legitimate, it implements sophisticated URL redirection mechanisms, intercepts web requests on all URLs, and communicates with an external server (`imgvidcfig.com`) in ways that significantly expand its attack surface beyond its stated purpose. The extension uses request interception to redirect user navigation through external servers, which could enable traffic monitoring, phishing, or affiliate fraud.

**Key Findings:**
1. **HIGH**: URL Redirection Through External Server - All Shopee product page visits are redirected through `imgvidcfig.com` with encoded original URLs
2. **HIGH**: Overly Broad Permissions - `<all_urls>` host permissions and webRequest interception on ALL websites
3. **MEDIUM**: HTTP Header Interception - Monitors and extracts specific Shopee anti-bot headers
4. **MEDIUM**: Encrypted Storage Configuration - Uses AES-256 encryption for configuration data with hardcoded keys

## Vulnerability Details

### 1. URL Redirection and Traffic Hijacking
**Severity**: HIGH
**Files**: `assets/js/background.js` (lines 5703-5793)
**CWE**: CWE-601 (URL Redirection to Untrusted Site)

**Description**:
The extension implements a sophisticated URL redirection mechanism that intercepts all Shopee product page navigations and routes them through an external server at `imgvidcfig.com`. When a user visits a Shopee product page, the extension:

1. Intercepts the navigation via `chrome.webRequest.onBeforeRequest`
2. Makes a POST request to `https://imgvidcfig.com/api/shopy` with the pathname and origin
3. Receives a "keepurl" response containing a redirect URL
4. Redirects the user's tab to the external URL with the original Shopee URL encoded in an `ikuc` parameter
5. The external server then redirects back to Shopee, allowing it to monitor/log all product visits

**Code Evidence**:
```javascript
// Line 5703: External API endpoint
ge = "https://imgvidcfig.com/api";

// Lines 5719-5730: POST request to external server
o = "".concat(ge, "/shopy"), e.next = 8, h()({
  method: "POST",
  url: o,
  adapter: w,
  headers: {
    "content-type": "application/json",
    source: n,
    uuid: t
  }
});
s = e.sent, u = null == s || null === (r = s.headers) || void 0 === r ? void 0 : r.get("keepurl")

// Lines 5772-5774: URL redirection with original URL encoded
o.searchParams.set("ikuc", encodeURIComponent(s.href)),
delete ye[i], null != e && e.tabId && e.tabId >= 0 && q(e.url) && H(e.tabId, {
  url: o.href
})

// Lines 5780-5793: Redirect back from external server
chrome.webRequest.onHeadersReceived.addListener((function(e) {
  try {
    var t = new URL(e.url).searchParams.get("ikuc");
    if (t) {
      var n = new URL(decodeURIComponent(t));
      H(e.tabId, {
        url: n.href
      })
    }
  } catch (e) {}
}), {
  urls: ["<all_urls>"],
  types: ["main_frame"]
})
```

**Risk Assessment**:
- **Attack Vector**: Every Shopee product page visit is routed through `imgvidcfig.com`, allowing complete tracking of user browsing behavior
- **Data Exposure**: Product URLs, timestamps, user shopping interests exposed to third-party server
- **Potential Abuse**: Could be used for affiliate fraud, price manipulation, phishing attacks, or user profiling
- **User Transparency**: No disclosure in extension description or privacy policy about traffic redirection

**Verdict**: MALICIOUS BEHAVIOR - This URL redirection serves no legitimate purpose for the extension's stated functionality (downloading images). All download operations could be performed client-side without routing traffic through external servers.

---

### 2. Overly Broad Web Request Permissions
**Severity**: HIGH
**Files**: `manifest.json` (line 40), `assets/js/background.js` (lines 5655-5700, 5743-5793)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests `<all_urls>` host permissions and implements webRequest listeners that monitor ALL web traffic, not just Shopee domains. This grants the extension capability to:

- Monitor all HTTP headers on every website visited
- Intercept and modify navigation requests across the entire web
- Access content from any domain

**Code Evidence**:
```javascript
// manifest.json line 40
"host_permissions": ["<all_urls>"]

// background.js lines 5698-5700: Monitors ALL URLs
}, {
  urls: ["<all_urls>"]
}, ["requestHeaders"]);

// Lines 5777-5779: Intercepts ALL main_frame requests
}), {
  urls: ["<all_urls>"],
  types: ["main_frame"]
})
```

**Risk Assessment**:
- **Principle of Least Privilege Violation**: Extension only needs access to `*.shopee.*` domains for its stated purpose
- **Privacy Risk**: Can monitor user's complete browsing history and all web requests
- **Attack Surface**: If compromised, attacker gains universal web monitoring capability

**Verdict**: EXCESSIVE PERMISSIONS - The `<all_urls>` permission is unjustified. Extension should be restricted to `*://*.shopee.*/*` patterns.

---

### 3. HTTP Header Interception and Extraction
**Severity**: MEDIUM
**Files**: `assets/js/background.js` (lines 5655-5700)
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**:
The extension intercepts Shopee API requests specifically to extract anti-bot and security headers (`AF-AC-ENC-DAT`, `AF-AC-ENC-SZ-TOKEN`). These headers are designed by Shopee to prevent automated scraping and bot activity. The extension:

1. Monitors all webRequest headers via `onBeforeSendHeaders`
2. Filters for Shopee API URLs (matching `/api/` pattern)
3. Extracts specific anti-bot security tokens
4. Stores and reuses these headers for subsequent requests

**Code Evidence**:
```javascript
// Lines 5655-5687: Header interception logic
chrome.webRequest.onBeforeSendHeaders.addListener(function() {
  var e = o()(i.a.mark((function e(t) {
    var n, r, a, o, s, c, u;
    return i.a.wrap((function(e) {
      for (;;) switch (e.prev = e.next) {
        case 0:
          if (!V(t.url)) {  // V() checks for Shopee API URLs
            e.next = 20;
            break
          }
          // Extracts AF-AC-ENC headers
          return n = ["AF-AC-ENC-DAT", "AF-AC-ENC-SZ-TOKEN"], e.prev = 2, e.next = 5, A("__AG_");
        case 5:
          // ... processes and stores headers
          for (a = (null == t ? void 0 : t.requestHeaders) || [], o = n.length, s = 0; s < a.length; s++)
            c = a[s].name.toUpperCase(), n.includes(c) && o--;
          0 === o && (u = a.map((function(e) {
            return [e.name, e.value]
          })), he({
            url: t.url,
            options: {
              headers: u
            }
          }));
```

**Risk Assessment**:
- **Security Bypass**: Extracts and potentially reuses Shopee's anti-bot protection headers
- **Terms of Service Violation**: Likely violates Shopee's anti-scraping policies
- **Scalability Risk**: If 100K users are all bypassing rate limits, could facilitate large-scale data harvesting

**Verdict**: SUSPICIOUS - While potentially used for legitimate data fetching, intercepting anti-bot headers raises concerns about terms of service compliance and potential abuse for large-scale scraping operations.

---

### 4. Encrypted Configuration with Hardcoded Key
**Severity**: MEDIUM
**Files**: `assets/js/background.js` (lines 5383-5450)
**CWE**: CWE-321 (Use of Hard-coded Cryptographic Key)

**Description**:
The extension implements AES-256-CBC encryption for configuration data but stores the encryption key hardcoded in the JavaScript code. The key is obfuscated as an array of character codes:

**Code Evidence**:
```javascript
// Lines 5383-5384: Hardcoded encryption key
ne = [100, 106, 40, 78, 114, 114, 41, 97, 44, 121, 99, 37, 41, 104, 42, 75, 35, 86, 118, 33, 46, 68, 75, 64, 103, 106, 66, 66, 90, 115, 41, 100, 102, 122, 103, 40, 89, 85, 83, 106, 98, 41],

// Lines 5407-5424: Decryption implementation
decrypt: function(e) {
  var t = JSON.parse(te.a.enc.Utf8.stringify(te.a.enc.Base64.parse(e))),
    n = te.a.enc.Hex.parse(t.salt),
    r = te.a.enc.Hex.parse(t.iv),
    i = t.ciphertext,
    a = parseInt(t.iterations);
  a <= 0 && (a = 999);
  var o = this.encryptMethodLength / 4,
    s = te.a.PBKDF2(W(ne), n, {  // W(ne) converts character codes to key
      hasher: te.a.algo.SHA512,
      keySize: o / 8,
      iterations: a
    });
  return te.a.AES.decrypt(i, s, {
    mode: te.a.mode.CBC,
    iv: r
  }).toString(te.a.enc.Utf8)
}

// Lines 5476-5480: Decrypts storage key "__AG_HEHE"
return n = ["itemid", "item_id"], e.next = 3, A("__AG_HEHE");
case 3:
  return (r = e.sent) && (s = ie.decrypt("ey" + r), s = JSON.parse(s)
```

**Risk Assessment**:
- **Cryptography Misuse**: Hardcoded keys provide no real security - any analyst can extract the key
- **False Sense of Security**: Encryption suggests sensitive data, but offers no protection
- **Configuration Tampering**: Attackers can decrypt, modify, and re-encrypt configuration
- **Remote Config Risk**: Encrypted data appears to come from `imgvidcfig.com`, suggesting remote configuration capability

**Verdict**: WEAK SECURITY - Hardcoded encryption keys are cryptographically worthless. The encryption appears designed to obfuscate configuration rather than provide genuine security, raising questions about what is being hidden.

---

### 5. Content Script Injection on All URLs
**Severity**: MEDIUM
**Files**: `manifest.json` (lines 17-24)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
Content scripts are injected into every webpage (`<all_urls>`), including the 20KB vendors.js library. This grants the extension access to DOM manipulation, form data, and page content across all websites.

**Code Evidence**:
```javascript
// manifest.json lines 17-24
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": ["assets/js/vendors.js", "assets/js/content_scripts.js"],
    "css": ["assets/css/app.css"],
    "run_at": "document_end"
  }
]
```

**Risk Assessment**:
- **Universal DOM Access**: Can read and modify content on every website visited
- **Performance Impact**: 20KB+ of code loaded on every page
- **Data Collection Potential**: Could monitor form inputs, authentication tokens, personal data across all sites
- **Cross-Site Leakage**: Data from one site could be exfiltrated via requests to Shopee or imgvidcfig.com

**Verdict**: EXCESSIVE SCOPE - Content scripts should only run on `*://*.shopee.*/*` domains. There is no legitimate reason to inject code into banking sites, email, social media, etc.

---

## False Positive Analysis

| Pattern | Location | Assessment | Reason |
|---------|----------|------------|---------|
| CryptoJS library | background.js:77-251 | FALSE POSITIVE | Standard CryptoJS implementation for encryption |
| Axios HTTP client | background.js:2766 | FALSE POSITIVE | Standard XMLHttpRequest wrapper for API calls |
| React/JSX code | vendors.js | FALSE POSITIVE | Standard React framework for popup UI |
| Webpack loader | background.js:1-45 | FALSE POSITIVE | Standard module bundler boilerplate |
| `eval()` in webpack | browser_scripts.js:289+ | FALSE POSITIVE | Webpack's dynamic CSS loading mechanism |
| Regenerator runtime | background.js:3335 | FALSE POSITIVE | Babel async/await polyfill |
| `Function()` constructor | background.js:3728 | FALSE POSITIVE | Polyfill fallback for global object detection |

---

## API Endpoints and External Communications

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `https://imgvidcfig.com/api/shopy` | URL redirection | Product pathname, origin, UUID | HIGH |
| `https://*.shopee.*/api/*` | Product data fetching | Request headers, anti-bot tokens | MEDIUM |
| Shopee CDN (cf.shopee.*) | Image/video downloads | Standard HTTP requests | LOW |

**Traffic Analysis**:
- All Shopee product page navigations trigger POST to `imgvidcfig.com`
- External server responds with redirect URLs
- User's browser is redirected through external domain before reaching Shopee
- This creates a complete log of user shopping behavior at the external server

---

## Data Flow Summary

```
User visits Shopee product page
         ↓
Extension intercepts navigation (webRequest.onBeforeRequest)
         ↓
POST to imgvidcfig.com/api/shopy
    - Sends: pathname, origin, uuid
    - Receives: "keepurl" redirect URL
         ↓
Extension redirects tab to imgvidcfig.com URL
    - Original Shopee URL encoded in "ikuc" parameter
         ↓
External server logs visit, redirects back to Shopee
         ↓
Extension intercepts redirect (webRequest.onHeadersReceived)
         ↓
Final navigation to actual Shopee product page
```

**Privacy Impact**: Every product viewed is logged by third-party server before user reaches Shopee.

---

## Manifest Analysis

**Permissions Requested**:
- ✓ `storage` - Legitimate for settings
- ✓ `downloads` - Legitimate for core functionality
- ✓ `contextMenus` - Legitimate for download shortcuts
- ⚠️ `webRequest` - Excessive scope (all URLs)
- ❌ `host_permissions: ["<all_urls>"]` - Unjustified and dangerous

**Content Security Policy**:
```javascript
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```
- Allows WASM (not found in code, likely unused)
- No external script sources (good)
- Standard CSP configuration

---

## Security Recommendations

### Critical (Must Fix):
1. **Remove URL Redirection**: Eliminate all traffic routing through `imgvidcfig.com`
2. **Restrict Host Permissions**: Change from `<all_urls>` to `*://*.shopee.*/*`
3. **Scope Content Scripts**: Only inject on Shopee domains
4. **Limit WebRequest Listeners**: Remove `<all_urls>` from webRequest listeners

### High Priority:
5. **Remove Header Interception**: Stop extracting anti-bot headers
6. **Transparent Data Practices**: Disclose any external communications in privacy policy
7. **Remove Hardcoded Encryption**: Either use proper key management or remove obfuscation

### Medium Priority:
8. **Minimize Permissions**: Remove unused `wasm-unsafe-eval` from CSP
9. **Code Audit**: Review all external communications for necessity
10. **User Consent**: Implement opt-in for any analytics or tracking

---

## Compliance Issues

**Chrome Web Store Policy Violations**:
- ✗ Use of Deceptive Installation Tactics (potential affiliate fraud via redirects)
- ✗ Collecting or Transmitting User Data without Disclosure
- ✗ Single Purpose Policy (webRequest on all URLs exceeds stated purpose)

**Privacy Concerns**:
- No privacy policy disclosed in extension listing
- Undisclosed third-party data sharing with `imgvidcfig.com`
- Complete shopping behavior tracking without user consent

---

## OVERALL RISK ASSESSMENT: HIGH

**Severity Breakdown**:
- CRITICAL: 0
- HIGH: 2 vulnerabilities
- MEDIUM: 3 vulnerabilities
- LOW: 0 vulnerabilities

**Risk Factors**:
- 100,000+ users affected
- Sophisticated traffic hijacking mechanism
- Undisclosed external data collection
- Potential for affiliate fraud or phishing attacks
- Excessive permissions enabling future malicious updates

**Recommendation**:
❌ **NOT RECOMMENDED FOR INSTALLATION**

While the core image download functionality may be legitimate, the extension's traffic redirection mechanisms, overly broad permissions, and undisclosed external communications present significant privacy and security risks. Users should seek alternative Shopee download tools that operate transparently without routing traffic through third-party servers.

**Triage Priority**: HIGH - Should be reviewed for Chrome Web Store compliance and potential removal.
