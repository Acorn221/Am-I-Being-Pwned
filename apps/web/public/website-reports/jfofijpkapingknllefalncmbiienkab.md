# Vulnerability Report: Emsisoft Browser Security

## Metadata
- **Extension Name**: Emsisoft Browser Security
- **Extension ID**: jfofijpkapingknllefalncmbiienkab
- **Version**: 2023.8.0.56
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Author**: Emsisoft Ltd
- **Analysis Date**: 2026-02-07

## Executive Summary

Emsisoft Browser Security is a legitimate security extension from a well-known anti-malware vendor. The extension provides URL filtering and malware protection by checking URLs against Emsisoft's cloud service and local anti-virus client. The analysis reveals **no malicious behavior** - the extension operates as a transparent web filter with appropriate security architecture. All network communications are to legitimate Emsisoft endpoints, and the extension includes proper WebSocket integration with local Emsisoft AV software.

The extension uses cryptographic techniques (RC4 encryption, MD5 hashing) to process server-provided URL filtering rules, which is a legitimate privacy-preserving approach to distribute malware/phishing signatures without exposing the actual URL patterns.

**Overall Risk**: CLEAN

## Vulnerability Details

### 1. No Malicious Behavior Detected
**Severity**: N/A
**Verdict**: CLEAN

**Analysis**:
The extension implements a legitimate URL filtering service with the following architecture:

1. **Cloud Service Integration**:
   - Checks URLs against `https://alomar.emsisoft.com/api/v1/url/get/` endpoint
   - Reports malicious/false positive URLs to `https://alomar.emsisoft.com/api/v1/url/report`
   - All communications are HTTPS to official Emsisoft domain

2. **Local AV Integration**:
   - WebSocket connection to `ws://127.0.0.1:42357` (local Emsisoft AV)
   - Receives host blocking rules and extension state from desktop AV software
   - Enables unified policy management across browser and desktop protection

3. **URL Blocking Workflow**:
   ```javascript
   // From background.js lines 84-255
   async function checkUrl(url) {
     // 1. Check if extension is disabled
     // 2. Check excluded domain list (user whitelist)
     // 3. Query local AV via localhost WebSocket
     // 4. Check host rules from AV
     // 5. Query local cache (15-minute TTL)
     // 6. Query cloud service if no local cache
     // 7. Decrypt and evaluate URL patterns
     // 8. Block or allow based on results
   }
   ```

4. **Encrypted Signature Distribution**:
   - Server returns RC4-encrypted regex patterns (lines 224-243 in background.js)
   - Patterns are decrypted client-side using MD5-derived keys with per-URL salt
   - This prevents exposing malware/phishing URL patterns in transit
   - Legitimate privacy-preserving architecture

**Code Evidence**:
```javascript
// background.js:224-243 - Legitimate encrypted signature processing
var decoded = atob(match.regex);
var per_url_salt = decoded.slice(0, 8);
var encrypted_regex = decoded.slice(8);
var subdomain = findSubdomainByHash(hostname, match.hash);
var key = md5(hostname_salt + per_url_salt + subdomain, null, true);
var result = rc4(key, encrypted_regex);
var should_block_url = result.split("\t").some(function(value) {
  if (value !== "") {
    var regex = newRegExp(value, true);
    return (regex && regex.test(blocked_url));
  }
});
```

### 2. Permissions Analysis
**Severity**: N/A
**Verdict**: APPROPRIATE

**Permissions Requested**:
- `storage` - Store cached URL verdicts, exclusion lists, extension state
- `tabs` - Monitor tab URL changes for protection
- `downloads` - Check download URLs before completion
- `*://*/*` - All URLs (required for URL filtering)
- `https://alomar.emsisoft.com/*` - Emsisoft cloud service

**Assessment**: All permissions are appropriate and necessary for URL filtering functionality. No excessive permissions detected.

### 3. Content Security Policy
**Severity**: N/A
**Verdict**: DEFAULT CSP (Manifest v3)

Manifest v3 extensions have strict CSP by default. No custom CSP weakening detected.

### 4. User Privacy Protections
**Severity**: N/A
**Verdict**: STRONG

**Privacy Features**:
1. **15-minute local cache** (eapi_storage.js:76-100) - Reduces server queries
2. **Hash-based lookups** - Only MD5 hashes sent to server, not full URLs
3. **User exclusion list** - Allows bypassing protection for trusted domains
4. **No tracking/analytics** - No third-party SDKs detected
5. **Transparent blocking** - Block pages explain why URLs were blocked

**Evidence**:
```javascript
// bg_common.js:131-167 - Hash-based URL lookup
function createHash(domain) {
  var encrypted = md5(hostname_salt + domain.toLowerCase());
  return encrypted.toString().toUpperCase();
}
// Only hashes sent to server, preserving privacy
var cloudURI = `https://alomar.emsisoft.com/api/v1/url/get/${hashes_string}`;
```

### 5. Download Protection
**Severity**: N/A
**Verdict**: LEGITIMATE FEATURE

**Analysis**:
The extension monitors downloads and cancels malicious file downloads (background.js:23-45):

```javascript
async function checkDownloadStatus(downloadItem) {
  var answer = await checkUrl(downloadItem.finalUrl);
  if (answer.redirectUrl) {
    browser.downloads.cancel(id);
    browser.downloads.removeFile(id);
    browser.downloads.erase({id: id});
    updateTabURL(tabid, answer.redirectUrl); // Redirect to block page
  }
}
```

This is standard security extension behavior - canceling malicious downloads and informing the user.

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `.innerHTML =` | block_page_script.js:27, options.js:7, js:73, js:97 | Localized message display, date formatting | **FALSE POSITIVE** - Safe DOM updates with controlled content |
| `function(` callbacks | Multiple files | Standard JavaScript callbacks/closures | **FALSE POSITIVE** - Not dynamic code execution |
| RC4 encryption | lib/rc4.js, background.js | Decrypting server-provided URL filtering rules | **LEGITIMATE** - Privacy-preserving signature distribution |
| MD5 hashing | bg_common.js | Hashing domains before server lookup | **LEGITIMATE** - Privacy protection |
| WebSocket `ws://127.0.0.1:42357` | bg_common.js:318 | Local Emsisoft AV communication | **LEGITIMATE** - Desktop integration |
| jQuery | lib/jquery.min.js | UI framework for popup/options pages | **LEGITIMATE** - Standard library (3242 lines) |

## API Endpoints

| Endpoint | Purpose | Method | Data Sent | Legitimate |
|----------|---------|--------|-----------|------------|
| `https://alomar.emsisoft.com/api/v1/url/get/{hashes}` | Check URL reputation | GET | MD5 hashes of hostname components | ✅ Yes |
| `https://alomar.emsisoft.com/api/v1/url/report` | Report malicious/FP URLs | POST | `{url: string, type: "malicious"\|"falsepositive"}` | ✅ Yes |
| `ws://127.0.0.1:42357` | Local AV WebSocket | WS | Extension version, settings requests | ✅ Yes |
| `http://127.0.0.1:42357/checkhost/{hostname}` | Local AV URL check | GET | Hostname to check | ✅ Yes |
| `https://scamadviser.com/check-website/{hostname}` | Third-party reference (UI only) | N/A | Link in block page (user-initiated) | ✅ Yes |
| `https://help.emsisoft.com` | Help documentation | N/A | Link in popup (user-initiated) | ✅ Yes |
| `https://www.emsisoft.com` | Vendor website | N/A | Link in UI (user-initiated) | ✅ Yes |

**Assessment**: All endpoints are legitimate Emsisoft services or user-initiated links. No suspicious third-party data collection.

## Data Flow Summary

1. **User navigates to URL** → Extension monitors via `tabs.onUpdated`
2. **URL checked locally**: Extension state, exclusion list, local cache (15-min TTL)
3. **WebSocket check**: Query local Emsisoft AV at `ws://127.0.0.1:42357/checkhost/{hostname}`
4. **Cloud check** (if no local verdict): Hash hostname → Query `https://alomar.emsisoft.com/api/v1/url/get/{hashes}`
5. **Server response**: Returns encrypted regex patterns + verdict
6. **Client-side decryption**: RC4 decrypt using MD5-derived key → Test URL against patterns
7. **Action**: Allow navigation OR redirect to block page with explanation
8. **User feedback**: Block page allows reporting false positives or excluding domain

**Privacy Protections**:
- Only MD5 hashes sent to cloud (not full URLs)
- 15-minute local cache reduces server queries
- Local AV takes precedence over cloud
- User controls via exclusion list

## Security Assessment

### Strengths
1. ✅ **Legitimate vendor** - Emsisoft is established anti-malware company
2. ✅ **Transparent operation** - Block pages explain reasons, allow exclusions
3. ✅ **Privacy-preserving** - Hash-based lookups, local caching, no tracking
4. ✅ **Proper architecture** - MV3, appropriate permissions, secure endpoints
5. ✅ **Desktop integration** - Unified policy with local AV software
6. ✅ **User control** - Toggle protection, manage exclusions, report FPs
7. ✅ **No obfuscation** - Clean, readable code (aside from standard library minification)

### Weaknesses
None identified. Standard security extension functionality.

### Risk Factors
None. Extension operates exactly as described by vendor.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
- Legitimate security extension from reputable anti-malware vendor (Emsisoft Ltd)
- All network communications are to official Emsisoft endpoints
- Privacy-preserving architecture (hash-based URL lookups, local caching)
- Appropriate permissions for URL filtering functionality
- Transparent operation with user control and feedback mechanisms
- Local AV integration via localhost WebSocket (standard desktop integration pattern)
- No tracking, analytics, or third-party data sharing
- No malicious code patterns detected
- Cryptographic operations (RC4, MD5) serve legitimate security purposes

**Recommendation**: SAFE TO USE

This extension provides legitimate malware/phishing protection and operates transparently. The use of encryption for signature distribution is a privacy-preserving best practice. Users of Emsisoft antivirus products would benefit from this browser extension as part of unified threat protection.
