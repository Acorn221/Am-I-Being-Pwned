# Vulnerability Report: Privacy Test

## Metadata
- **Extension ID**: pdabfienifkbhoihedcgeogidfmibmhp
- **Extension Name**: Privacy Test
- **Version**: 10.7
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Privacy Test is a browser extension by Mixesoft (hotcleaner.com) that checks privacy settings and identifies sideloaded extensions. The extension primarily monitors Safe Browsing status, enumerates installed extensions, and provides basic security information about the current tab. While the extension contains several privacy-concerning behaviors including extension enumeration and third-party service integration, these are disclosed in its stated functionality. The extension communicates with external services (scan32.com, api64.com, dns.google) for malware scanning and IP detection features. The most significant concern is the `externally_connectable` configuration allowing communication from hotcleaner.com and a companion extension, which enables external control of extension management operations.

## Vulnerability Details

### 1. HIGH: External Website Control via externally_connectable
**Severity**: HIGH
**Files**: manifest.json, SW_JS_ID.js
**CWE**: CWE-749 (Exposed Dangerous Method or Function)
**Description**: The manifest declares `externally_connectable` with `https://www.hotcleaner.com/*` and extension ID `ghgabhipcejejjmhhchfonmamedcbeod`. This allows the external website and companion extension to send messages that trigger privileged operations including extension enumeration, extension enabling/disabling, and integrity checking.

**Evidence**:
```json
"externally_connectable": {
  "ids": ["ghgabhipcejejjmhhchfonmamedcbeod"],
  "matches": ["https://www.hotcleaner.com/*"]
}
```

```javascript
f.onMessageExternal.addListener((a,d,b)=>{
  "function"===typeof b&&(
    34===a?.i?v().then(b).catch(b):  // getAll extensions
    55===a?.i?(m=d.tab&&d.tab.id,h=1,k({url:"APPS_HTML_ID.html",...})):
    144===a?.i?u(a.r).then(b).catch(b):  // get extension by ID
    233===a?.i?p(a.r,!0).then(b).catch(b):  // enable extension
    377===a?.i?(self.checkIntegrity||self.importScripts("DIR_JS/INTEGRITY_JS_ID.js"),
                self.checkIntegrity(a.r,g=>{g?b("prohibited"):p(a.r,!1).then(b).catch(b)}))  // disable after integrity check
```

**Verdict**: The external website can remotely control extension management functions. While this appears to be for ecosystem integration with other HotCleaner products, it creates a significant attack surface if the website is compromised or the message protocol is reverse-engineered by malicious actors.

### 2. MEDIUM: Extension Enumeration with Detailed Metadata
**Severity**: MEDIUM
**Files**: SW_JS_ID.js, MENU_JS_ID.js, APPS_JS_ID.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension uses `chrome.management.getAll()` to enumerate all installed extensions and collect detailed metadata including names, versions, IDs, installation types, icons, and enabled status. This information is collected both for local display and can be transmitted to the external website via the external messaging interface.

**Evidence**:
```javascript
// APPS_JS_ID.js - Collects extension icons as byte arrays
chrome.management.getAll().then(d=>{
  // ... processes each extension
  h.ico=Array.from(new Uint8Array(a));  // Stores icon as byte array
  chrome.runtime.sendMessage({i:89,r:d}, ...)
})

// SW_JS_ID.js - Responds to external requests for extension list
f.onMessageExternal.addListener((a,d,b)=>{
  34===a?.i?v().then(b).catch(b):  // Returns all extensions to external caller
```

**Verdict**: While extension enumeration is part of the stated functionality (checking for sideloaded extensions), the detailed metadata collection and external API exposure exceeds typical privacy checker needs. This creates fingerprinting risks.

### 3. MEDIUM: Unencrypted External Service Communication
**Severity**: MEDIUM
**Files**: MENU_JS_ID.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension communicates with multiple third-party services (scan32.com, api64.com, dns.google) for malware scanning and IP detection. While most use HTTPS, there's a fallback mechanism that could potentially expose data.

**Evidence**:
```javascript
x("https://scan32.com/scan","https://api64.com/sb3",{
  method:"POST",
  credentials:"omit",
  body:c.origin+c.pathname  // Sends current URL to external service
},"text",...)

x("https://scan32.com/cip","https://api64.com/cip",{
  method:"POST",
  credentials:"omit"
},"text",b)  // Detects user's IP address
```

**Verdict**: The extension transmits browsing context (current page URLs) to third-party malware scanning services. While this is necessary for the stated malware scanning functionality, users may not fully understand that their browsing activity is being shared with these external services.

### 4. LOW: Hardcoded Extension ID Allowlist
**Severity**: LOW
**Files**: INTEGRITY_JS_ID.js
**CWE**: CWE-798 (Use of Hard-coded Credentials)
**Description**: The extension maintains a hardcoded SHA-256 hash allowlist of "known good" extension IDs. This integrity checking mechanism is used to prevent disabling certain extensions.

**Evidence**:
```javascript
const e="9a42ee1af01ec0451057571887781d29d9c1fb5afe8d4d1593ffbb88722fe537 03700647745892f9bcfe30d98e3894b0a205174c55050ed91cdf560a39cf6411 ...".split(" ")
```

**Verdict**: This creates a privileged class of extensions that cannot be disabled through this extension's external API. While likely intended to protect legitimate software, it reduces user control and transparency.

## False Positives Analysis

1. **Extension Enumeration**: While flagged as a privacy concern, this is core functionality for detecting sideloaded extensions (malware vector). This is expected behavior for a privacy checker tool.

2. **Management Permission**: The `management` permission is necessary for the extension's stated purpose of identifying unusual extension installations.

3. **Privacy API**: The `privacy` permission is used to check Safe Browsing status, which is appropriate for a privacy monitoring tool.

4. **Google Closure Compiler Minification**: The code is minified but NOT obfuscated. Variable names like `a`, `b`, `c` are standard Closure Compiler output, not malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| scan32.com/scan | Malware scanning | Current page origin+pathname | MEDIUM - Browsing activity shared |
| api64.com/sb3 | Malware scanning (fallback) | Current page origin+pathname | MEDIUM - Browsing activity shared |
| scan32.com/cip | IP detection | None (detects client IP) | LOW - Standard IP detection |
| api64.com/cip | IP detection (fallback) | None (detects client IP) | LOW - Fallback endpoint |
| dns.google/resolve | DNS lookup | Current page hostname | LOW - Public DNS service |
| hotcleaner.com/* | Documentation/support | None (navigation only) | LOW - First-party domain |
| clients2.google.com/service/update2/crx | Extension updates | Standard CWS updates | CLEAN - Google infrastructure |
| appn.center/apiv1/csp | CSP reporting | CSP violations | LOW - Standard CSP reporting |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Privacy Test is a legitimate privacy monitoring extension with disclosed functionality, but contains several privacy and security concerns that warrant a MEDIUM risk rating:

**Concerns:**
1. External website control via `externally_connectable` creates significant attack surface if hotcleaner.com is compromised
2. Detailed extension enumeration with metadata collection exceeds typical privacy checker needs
3. Current page URLs are transmitted to third-party malware scanning services (scan32.com, api64.com)
4. External message API allows remote extension management operations (enable/disable extensions)
5. Hardcoded extension allowlist reduces user control transparency

**Mitigating Factors:**
1. All network requests use HTTPS
2. Extension enumeration is disclosed as core functionality
3. No evidence of data exfiltration beyond stated features
4. No credential harvesting or keylogging
5. Permissions are appropriate for stated functionality
6. Published by established developer (Mixesoft/HotCleaner)
7. 400,000 users suggest legitimate product

**Recommendation**: The extension is functional as advertised but users should be aware that their current browsing context is shared with third-party malware scanning services and that the hotcleaner.com website has significant control over extension management operations. The privacy concerns are moderate and disclosed, but the external control mechanism represents an elevated security risk if the partner website is compromised.
