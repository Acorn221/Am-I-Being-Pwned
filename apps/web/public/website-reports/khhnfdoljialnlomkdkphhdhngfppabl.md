# Security Analysis Report: Speed Test for Chrome - WiFi speedtest

## Extension Metadata
- **Extension ID**: khhnfdoljialnlomkdkphhdhngfppabl
- **Extension Name**: Speed Test for Chrome - WiFi speedtest
- **Version**: 1.0.3
- **User Count**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Speed Test for Chrome is a **MEDIUM-LOW risk** extension that provides internet speed testing functionality through a browser action popup. The extension has several security concerns including overly broad host permissions, insecure HTTP usage, third-party upload endpoint, and active tab URL harvesting, but the actual malicious behavior is limited. The extension appears to be a legitimate speed test tool with poor security practices rather than intentionally malicious software.

**Key Findings**:
1. Active tab URL harvesting via `chrome.tabs.query` (displayed in UI, no evidence of exfiltration)
2. Overly broad `*://*/*` host permissions with no content scripts
3. Insecure HTTP (not HTTPS) for download speed tests
4. Third-party upload endpoint (vishnu.pro) - unknown infrastructure
5. No background scripts, no content scripts, no SDK injections
6. No evidence of XHR/fetch hooking, extension enumeration, or data exfiltration

## Vulnerability Details

### 1. Active Tab URL Harvesting
**Severity**: MEDIUM
**Files**: `/app/app.js` (lines 9-14)
**Category**: Privacy Violation

**Code**:
```javascript
chrome.tabs.query({
  active: !0,
  lastFocusedWindow: !0
}, function(e) {
  var t = e[0];
  console.log(t, "tab"), console.log(t.url, this.jitterDesk.el, "URL"), n = t.url
})
```

**Analysis**:
- Queries the active tab to obtain its URL when the popup opens
- Stores URL in variable `n` and logs to console
- The URL is passed to `jitterResult()` function (line 166, 176) which displays it in the UI
- The `jitterResult` function extracts the third segment after splitting by "/" and truncates to 15 characters: `this.truncate(e.split("/")[2], 15) || "--"`
- This appears to be displaying the domain/hostname in the "Site" field of the speed test UI
- **No evidence found** of the URL being sent to remote servers in network requests
- Upload requests only send empty ArrayBuffer blobs for speed testing purposes

**Verdict**: The tab URL harvesting appears to be used for UI display purposes (showing which site is being tested), but the `tabs` permission is excessive for this use case. The extension could achieve the same result without the permission. However, there is no evidence of the URL being exfiltrated.

### 2. Overly Broad Host Permissions
**Severity**: MEDIUM
**Files**: `/manifest.json` (lines 20-22)
**Category**: Permission Over-reach

**Code**:
```json
"host_permissions": [
  "*://*/*"
]
```

**Analysis**:
- Requests access to ALL websites with the wildcard `*://*/*` pattern
- Extension has NO content scripts and NO background service worker
- The only JavaScript runs in the popup (browser action)
- Host permissions appear completely unnecessary for the extension's functionality
- Legitimate speed test functionality only requires network access to test servers (cachefly.net, vishnu.pro)

**Verdict**: Grossly excessive permissions that violate the principle of least privilege. The extension does not inject content scripts or intercept web traffic, making these permissions completely unjustified. This is a major red flag even if not actively exploited.

### 3. Insecure HTTP Usage
**Severity**: MEDIUM
**Files**: `/app/settings.js` (lines 3, 5, 7, 15)
**Category**: Security Misconfiguration

**Code**:
```javascript
var comopenspeedtesturl = {
  serverList: [{
    hostName: "http://cachefly.cachefly.net/100mb.test"
  }, {
    hostName: "http://cachefly.cachefly.net/100mb.test"
  }, {
    hostName: "http://cachefly.cachefly.net/100mb.test"
  }]
},
comopenspeedtestcdn = "http://cachefly.cachefly.net/100mb.test",
```

**Analysis**:
- Download speed tests use unencrypted HTTP connections to cachefly.net
- HEAD requests for ping tests also use HTTP
- Opens users to potential man-in-the-middle attacks during speed testing
- Upload endpoint uses HTTPS (vishnu.pro), which is inconsistent
- CacheFly CDN does support HTTPS but extension hardcodes HTTP URLs

**Verdict**: Legitimate speed test services should use HTTPS. While the data being transferred is benign (random test data), insecure transport is a security anti-pattern that could be exploited for traffic analysis or MITM attacks.

### 4. Third-Party Upload Endpoint
**Severity**: MEDIUM
**Files**: `/app/settings.js` (lines 11-13)
**Category**: Infrastructure Trust / Data Flow

**Code**:
```javascript
comopenspeedtestuurl = {
  serverList: [{
    hostName: "https://vishnu.pro/upload"
  }]
}
```

**Analysis**:
- Upload speed tests send data to `https://vishnu.pro/upload`
- Domain vishnu.pro is a third-party endpoint, not affiliated with official OpenSpeedTest
- Upload data consists of empty ArrayBuffer blobs (1MB each, 30 copies = 30MB total)
- Data sent is benign: `new Blob([ArrayBuffer(1048576)], {type: "application/octet-stream"})`
- No user data, cookies, or browsing history included in upload payload
- Single upload server (no redundancy) raises availability concerns
- Domain ownership/trustworthiness unknown

**Verdict**: While the data being uploaded is harmless (empty buffers for bandwidth testing), relying on an unknown third-party endpoint (vishnu.pro) is questionable. If this domain were compromised or malicious, it could potentially serve JavaScript to the extension or track IP addresses of users performing speed tests.

### 5. Conditional Test Execution Based on Hostname Length
**Severity**: LOW
**Files**: `/app/app.js` (line 151)
**Category**: Obfuscation / Hidden Behavior

**Code**:
```javascript
function t() {
  h.LiveSpeed(0), clearInterval(G), 17 == location.hostname.length && s()
}
```

**Analysis**:
- Checks if `location.hostname.length == 17` before executing function `s()` (which starts the speed test)
- Chrome extension IDs are 32 characters, but `chrome-extension://` protocol prefix is 19 characters
- The condition appears to check if running in a web context vs extension context
- Function `s()` initiates the actual speed test loop
- This is likely a debugging/development artifact rather than malicious obfuscation

**Verdict**: Appears to be legacy code or environment detection rather than intentional malicious logic. The condition seems incorrect for its intended purpose (extension vs web detection).

### 6. Missing Content Security Policy
**Severity**: LOW
**Files**: `/manifest.json`
**Category**: Security Hardening

**Analysis**:
- No `content_security_policy` defined in manifest.json
- Manifest V3 has stricter default CSP, but custom CSP would improve security
- No inline scripts detected in HTML files
- No use of `eval()`, `Function()`, or other dynamic code execution

**Verdict**: While not critical due to manifest V3 defaults and clean code, explicit CSP would follow security best practices.

## False Positives

| Pattern | Occurrences | Context | Verdict |
|---------|-------------|---------|---------|
| `XMLHttpRequest` usage | 3 instances | Legitimate speed test functionality (HEAD for ping, GET for download, POST for upload) | FALSE POSITIVE - Standard speed test implementation |
| `chrome.tabs.query` | 1 instance | Gets active tab URL for display in jitter/site field | BORDERLINE - Excessive permission but likely benign intent |
| Third-party domain | vishnu.pro | Upload endpoint for speed test | SUSPICIOUS - Unknown infrastructure but benign payload |
| HTTP (not HTTPS) | 4 instances | CacheFly CDN test files | SECURITY ISSUE - Should use HTTPS |
| `host_permissions: *://*/*` | 1 instance | Excessive permission with no content scripts | SECURITY ISSUE - Unjustified permission scope |

## API Endpoints and Data Flows

| Endpoint | Method | Purpose | Data Sent | Data Received | Protocol |
|----------|--------|---------|-----------|---------------|----------|
| `cachefly.cachefly.net/100mb.test` | HEAD | Ping/latency test | None | Response time | HTTP (insecure) |
| `cachefly.cachefly.net/100mb.test` | GET | Download speed test | None | 100MB test file (arraybuffer) | HTTP (insecure) |
| `vishnu.pro/upload` | POST | Upload speed test | 30MB empty blob (ArrayBuffer) | Server response | HTTPS |
| `openspeedtest.com/results/widget.php` | N/A | Results widget URL (unused) | N/A | N/A | Protocol-relative |

### Data Flow Summary

1. **Ping Test Flow**:
   - HEAD request to cachefly.net
   - Measures round-trip time via `window.performance.now()`
   - Calculates jitter from consecutive ping samples
   - No user data transmitted

2. **Download Test Flow**:
   - GET request to cachefly.net/100mb.test (arraybuffer)
   - Tracks bytes received via `XMLHttpRequest.onprogress`
   - Calculates speed from bytes/time
   - No user data transmitted

3. **Upload Test Flow**:
   - Generates 30MB blob of empty ArrayBuffers
   - POST to vishnu.pro/upload with `Content-Type: application/octet-stream`
   - Tracks bytes sent via `XMLHttpRequest.upload.onprogress`
   - Calculates speed from bytes/time
   - No user data transmitted (only empty buffers)

4. **Tab URL Collection**:
   - `chrome.tabs.query` retrieves active tab URL on popup open
   - URL stored in variable `n`
   - URL displayed in UI via `jitterResult(n)` which shows domain segment
   - **No network transmission of URL detected**

## Attack Surface Analysis

### What the Extension CAN Do
- Access any website content via `*://*/*` host permissions (permission available but unused)
- Read active tab URL via `tabs` permission
- Make network requests to any domain
- Display UI in browser action popup

### What the Extension ACTUALLY Does
- Opens browser action popup with speed test UI
- Queries active tab URL for display purposes only
- Performs HTTP speed tests to cachefly.net
- Performs HTTPS upload tests to vishnu.pro
- Displays speed test results in popup

### What the Extension Does NOT Do
- No content script injection
- No background service worker
- No XHR/fetch hooking or interception
- No extension enumeration or disabling
- No cookie harvesting
- No localStorage/sessionStorage access
- No DOM manipulation on web pages
- No ad injection or search hijacking
- No use of eval/Function/dynamic code execution
- No data exfiltration detected

## Privacy Implications

1. **Tab URL Harvesting**: Active tab URL is collected when popup opens, but only used for display. No evidence of exfiltration.

2. **IP Address Exposure**: Speed tests necessarily expose user's IP address to:
   - CacheFly CDN (cachefly.net) - reputable CDN
   - vishnu.pro - unknown third-party

3. **Timing Data**: Speed test results remain local; no results upload endpoint is actively used.

4. **No Tracking SDKs**: No analytics, telemetry, or tracking libraries detected.

## Risk Assessment

### Overall Risk Level: MEDIUM-LOW

**Risk Breakdown**:
- **Malicious Intent**: LOW - No evidence of deliberate malware behavior
- **Privacy Risk**: MEDIUM - Tab URL harvesting and IP exposure to third-party
- **Security Risk**: MEDIUM - Overly broad permissions, insecure HTTP, third-party endpoint
- **User Impact**: LOW - Limited to speed test functionality
- **Data Exfiltration**: NONE DETECTED

### Justification

This extension appears to be a poorly implemented but fundamentally legitimate speed testing tool. The primary concerns are:

1. **Excessive Permissions**: The `*://*/*` host_permissions and `tabs` permission are completely unjustified for a popup-only speed test tool
2. **Insecure HTTP**: Using HTTP instead of HTTPS for speed tests is a security anti-pattern
3. **Third-Party Infrastructure**: Reliance on unknown domain (vishnu.pro) for uploads introduces trust issues
4. **Tab URL Collection**: While seemingly benign (for display), this is unnecessary and privacy-invasive

However, the extension does NOT exhibit:
- XHR/fetch hooking for data harvesting
- Content script injection for ad injection or data scraping
- Extension enumeration or disabling
- Market intelligence SDKs
- Data exfiltration mechanisms
- Remote code execution or kill switches

The extension's behavior aligns with its stated purpose (speed testing) but fails to follow security best practices.

## Recommendations

### For Users
1. **Consider alternatives**: More established speed test extensions with better security practices
2. **Be aware**: Your active tab URL and IP address are exposed when using this extension
3. **Risk tolerance**: If you only use this extension occasionally and don't browse sensitive sites, risk is low

### For Developers (if legitimate)
1. **Remove excessive permissions**: Drop `host_permissions: *://*/*` completely
2. **Remove tabs permission**: Use `window.location` within popup instead of querying active tab
3. **Use HTTPS**: Update all CacheFly URLs to use HTTPS protocol
4. **Document vishnu.pro**: Clarify ownership and purpose of upload endpoint
5. **Add CSP**: Implement explicit Content Security Policy
6. **Add privacy policy**: Disclose what data is collected and how it's used

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present in Extension | Evidence |
|-------------------|---------------------|----------|
| Sensor Tower / Pathmatics SDK | NO | No ad-finder, no AI scraping, no browsing history upload |
| XHR/fetch hooking | NO | XMLHttpRequest used directly, not hooked/patched |
| Extension enumeration/killing | NO | No chrome.management API usage |
| Remote config / kill switch | NO | No remote JavaScript loading, static config only |
| Market intelligence data harvesting | NO | No SDK injection, no data collection beyond speed test |
| AI conversation scraping | NO | No content scripts targeting ChatGPT/Claude/etc |
| Ad injection | NO | No content scripts, no DOM manipulation |
| Cookie harvesting | NO | No cookie access detected |
| Residential proxy infrastructure | NO | No proxy configuration or VPN functionality |

## Technical Architecture

**Extension Type**: Browser Action (Popup Only)
- **Background Scripts**: NONE
- **Content Scripts**: NONE
- **Popup**: `app/index.html` with `app.js` and `settings.js`
- **Permissions**: `tabs`, `host_permissions: *://*/*`
- **Network**: Direct XMLHttpRequest to speed test endpoints
- **Total Code**: 322 lines of JavaScript

**Code Quality**: Minified/obfuscated JavaScript with short variable names (likely from webpack/rollup bundler)

## Conclusion

**Final Verdict**: MEDIUM-LOW RISK - POORLY SECURED BUT LIKELY LEGITIMATE

Speed Test for Chrome is a functional speed testing extension with significant security and privacy shortcomings but no evidence of active malicious behavior. The excessive permissions (`*://*/*` host access and `tabs` permission) are major red flags that could be exploited in future updates, but the current version (1.0.3) appears to be a legitimate tool with poor security practices.

**Primary Concerns**:
1. Overly broad permissions create attack surface
2. Active tab URL harvesting is unnecessary and privacy-invasive
3. Insecure HTTP usage exposes users to MITM attacks
4. Third-party upload endpoint (vishnu.pro) introduces trust issues

**Mitigating Factors**:
1. No content scripts or background workers
2. No data exfiltration mechanisms detected
3. No tracking SDKs or analytics
4. Simple, transparent functionality
5. Upload payload is benign (empty buffers)

**Recommendation**: Users concerned about privacy should seek alternatives. Users comfortable with the risk profile can continue using the extension while being aware that their active tab URL and IP address are exposed to CacheFly and vishnu.pro during speed tests.
