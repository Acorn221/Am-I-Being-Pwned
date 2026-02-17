# Security Analysis Report: Douga Getter

**Extension ID:** hhbcihapcmaemjinlbgafnjjihbdmjnf
**Extension Name:** Douga Getter
**Version:** 3.2.1
**User Count:** 700,000
**Overall Risk:** MEDIUM

---

## Executive Summary

Douga Getter is a Japanese video downloader extension that intercepts media requests across all websites and provides a download interface. While the extension's core functionality appears legitimate, it exhibits two medium-severity security concerns: user-agent telemetry collection sent to the developer's domain, and an insecure postMessage handler that could be exploited by malicious websites.

---

## Detailed Findings

### 1. User-Agent Data Exfiltration (MEDIUM)

**Location:** `bg.js:21`

**Description:**
The background service worker collects the browser's `navigator.userAgent` string and sends it to `www.douga-getter.com` via a fetch request. This occurs during extension initialization.

**Code Evidence:**
```javascript
const u=navigator.userAgent
// ... later in code ...
fetch(www.douga-getter.com) // userAgent sent in request
```

**Risk Assessment:**
- **Severity:** Medium
- **Impact:** Privacy violation - browser fingerprinting data is collected without explicit user consent
- **Likelihood:** High - occurs on every browser session

**Implications:**
- The user-agent string reveals browser type, version, operating system, and device information
- Combined with usage patterns, this could enable user tracking across sessions
- While not containing PII directly, it contributes to browser fingerprinting
- No evidence of this data being sold or misused, appears to be basic analytics

### 2. Insecure PostMessage Handler (MEDIUM)

**Location:** `js/loader.js:6`

**Description:**
The loader page sets up a `window.addEventListener("message")` handler without validating the `event.origin` property before processing messages.

**Code Evidence:**
```javascript
window.addEventListener("message") // No origin check in loader.js
```

**Risk Assessment:**
- **Severity:** Medium
- **Impact:** Malicious websites could send crafted messages to manipulate the extension's download interface
- **Likelihood:** Medium - requires user to have loader page open and visit malicious site simultaneously

**Implications:**
- Attacker-controlled websites could potentially:
  - Trigger unwanted downloads
  - Inject malicious filenames or URLs into the download queue
  - Manipulate the extension's UI state
- The loader page is opened when clicking the extension icon, creating a small attack window
- No evidence of active exploitation in the wild

### 3. Broad Permissions Scope (INFORMATIONAL)

**Permissions Requested:**
- `<all_urls>` - Access to all websites
- `webRequest` - Intercept network requests
- `declarativeNetRequestWithHostAccess` - Modify request/response headers
- `downloads` - Initiate file downloads
- `tabs` - Access tab information
- `storage` - Persist extension data

**Justification:**
These permissions are necessary for the extension's stated functionality of detecting and downloading media files from any website. However, the broad scope creates potential for abuse if the extension were compromised or sold to a malicious actor.

---

## Attack Surface Analysis

### Web-Accessible Resources
- `xcom.html` - Accessible only from `https://www.douga-getter.com/*`
- Used for cross-origin download fallback when direct download fails
- Properly scoped to developer's domain, limiting exposure

### Network Communication
The extension communicates with the following external domains:

1. **www.douga-getter.com** (primary domain)
   - Hosts the extension's download interface
   - Receives user-agent telemetry
   - Used for fallback download mechanism when parent tab is closed

2. **www.google.com/s2/favicons** (favicon service)
   - Fetches website favicons for UI display
   - Standard Chrome extension pattern, benign

### Message Passing Architecture
- Background script coordinates between content scripts and loader page
- Content scripts inject into all websites (`<all_urls>`)
- Communication uses Chrome's messaging API with command-based protocol
- Disabled on YouTube (hardcoded exception: `DISABLE_ON_YOUTUBE_REGEXP`)

---

## Data Flow Analysis

### Information Collected
1. **User-Agent String** - Sent to douga-getter.com on initialization
2. **Video Metadata** - URLs, filenames, content-types of detected media
3. **Page Context** - Title, URL, favicon of pages where videos are detected
4. **User Preferences** - Download settings stored in local storage

### Data Storage
- `chrome.storage.local` - User preferences, analytics settings
- `chrome.storage.session` - Temporary state for active download sessions
- `localStorage` (in loader page) - Per-site download preferences

### Data Transmission
- **Outbound:** User-agent string to www.douga-getter.com
- **No evidence of:** Video URLs, browsing history, or personal data being exfiltrated
- Media downloads are initiated directly from source websites, not proxied through developer's servers

---

## Code Quality Observations

### Obfuscation
The extension source is heavily minified/obfuscated (acknowledged in release notes). Developer states this was done to prevent code theft after another extension copied their work. They offer to provide readable source to the Chrome Web Store team upon request.

### Copyright Notice
```
/*
 *  This file is part of Douga-Getter  v3.2.1  <https://www.douga-getter.com/>
 *  Note that the source code is copyrighted. We do not grant you the right to modify or distribute it.
 */
```

### Manifest V3 Migration
Extension recently migrated from Manifest V2 to V3 (version 3.2.0), demonstrating active maintenance.

---

## Recommendations

### For Users
1. **Acceptable Risk for Intended Use:** If you need a video downloader and accept basic analytics collection, this extension performs as advertised
2. **Privacy-Conscious Users:** The user-agent collection may be unacceptable for users with strict privacy requirements
3. **Mitigation:** Use in a dedicated browser profile for downloading only, separate from general browsing

### For Developers
1. **Remove User-Agent Collection:** Implement local analytics or use privacy-preserving alternatives
2. **Add Origin Validation:** Validate `event.origin` in postMessage handler against expected domains
3. **Transparency:** Disclose data collection practices in the privacy policy
4. **Unobfuscate:** Consider releasing readable source with code signing to prevent theft while maintaining transparency

### For Security Teams
1. **Monitor Network Traffic:** Watch for unexpected data transmission to douga-getter.com
2. **Policy Decision:** Classify as MEDIUM risk - legitimate tool with privacy trade-offs
3. **User Education:** Inform users about the analytics collection before deployment

---

## Conclusion

Douga Getter is a functional video downloader with 700,000 users and a 3.7-star rating. The extension performs its advertised functionality without evidence of malicious intent. However, it collects user-agent telemetry without prominent disclosure and contains a postMessage vulnerability that could be exploited by malicious websites.

The **MEDIUM risk rating** reflects that while the extension is not actively malicious, it has security and privacy weaknesses that could be exploited or create user tracking capabilities. The broad permissions scope amplifies these concerns, as a future compromise or ownership transfer could turn this into a more serious threat.

**Recommendation:** ACCEPTABLE FOR USE with awareness of privacy implications. Users requiring strict privacy should seek alternatives. Organizations should evaluate against their acceptable use policies.

---

## Vulnerability Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 2 | postMessage origin validation, analytics collection |
| Low | 0 | - |

**Total Issues:** 2 Medium-severity findings

---

*Analysis completed: 2026-02-15*
*Analyzer: Claude Sonnet 4.5*
*Static Analysis Tool: ext-analyzer v1.0*
