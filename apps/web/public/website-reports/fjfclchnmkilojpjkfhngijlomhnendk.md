# Vulnerability Report: Download All PDFs

## Metadata
- **Extension ID**: fjfclchnmkilojpjkfhngijlomhnendk
- **Extension Name**: Download All PDFs
- **Version**: 2.0.0
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Download All PDFs" is a Chrome extension that purports to help users find and download PDF files from websites. While the core functionality is legitimate, the extension engages in extensive undisclosed data collection that goes far beyond what is necessary for its stated purpose. The extension collects URLs, referrers, content types, PDF links, and a persistent user identifier from every website the user visits, and transmits this data to `service.download-all-pdfs.com`. This surveillance behavior occurs continuously on all HTTP/HTTPS sites via a content script that runs every 800ms, making it a high-privacy risk.

The extension uses webpack-bundled (not obfuscated) code and was flagged by static analysis for exfiltration flows from chrome.storage.local to the remote endpoint. With 60,000 users, this represents significant surveillance infrastructure.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing Data Collection and Exfiltration

**Severity**: HIGH
**Files**: content.js, background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**:

The extension injects a content script on all HTTP/HTTPS websites that continuously collects browsing data and sends it to a remote server. The data collection occurs:
- On initial page load (300ms delay)
- Every 800ms via setInterval
- On URL changes (popstate, hashchange events)

**Data Collected and Transmitted**:
1. Current page URL (`location.href`)
2. Previous page referrer (`document.referrer`)
3. Content type of the page
4. List of PDF links found on the page (up to 500)
5. Persistent user identifier (`dapClientId` stored in chrome.storage.local)
6. Extension version
7. Timestamp
8. Navigation type (whether URL was rewritten)

**Evidence**:

content.js sends the data:
```javascript
chrome.runtime.sendMessage({
  action:"dap-collect",
  u:location.href,
  ct:document.contentType||"text/html",
  r:e||document.referrer||"",
  links:o,
  isDynamic:n
})
```

background.js processes and forwards to remote server:
```javascript
a={
  m:"do-ch",
  uid:t.t0,                    // persistent user ID
  ev:t.t1,                     // extension version
  ct:t.t2,                     // content type
  t:t.t3,                      // timestamp
  nm:t.t4,                     // navigation method
  nt:"foreground",
  u:t.t5,                      // current URL
  r:t.t6,                      // referrer
  links:t.t7                   // PDF links array
}

fetch("https://service.download-all-pdfs.com/check_links",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify(e),
  signal:r
})
```

**Verdict**: This constitutes excessive data collection that is not adequately disclosed to users. While checking PDF links for validity might be a legitimate feature, the extension also collects and transmits:
- Complete browsing history (every URL visited)
- Referrer chains (tracking user navigation paths)
- Persistent user tracking (via `dapClientId`)
- Continuous surveillance (every 800ms polling)

This data collection pattern allows the operator to build detailed profiles of user browsing behavior across all websites, far exceeding what is necessary for the stated functionality of "downloading PDFs."

### 2. HIGH: Persistent User Tracking with Unique Identifier

**Severity**: HIGH
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**:

The extension generates and stores a persistent unique identifier (`dapClientId`) for each user, which is transmitted with every data collection event. This enables cross-session tracking and user profiling.

**Evidence**:

```javascript
function B(){
  return U.apply(this,arguments)
}

function U(){
  return(U=d(h().mark((function t(){
    var e,r,n,o;
    return h().wrap((function(t){
      for(;;)switch(t.prev=t.next){
        case 0:
          return t.prev=0,e="dapClientId",t.next=4,chrome.storage.local.get([e]);
        case 4:
          if(r=t.sent,!(n=r[e])||"string"!=typeof n){t.next=8;break}
          return t.abrupt("return",n);
        case 8:
          // Generate 16-char hex ID from timestamp + random
          return o=(Date.now().toString(16)+Math.random().toString(16).substring(2)).substring(0,16),
          t.next=11,chrome.storage.local.set(f({},e,o));
        case 11:
          return t.abrupt("return",o);
```

This identifier:
- Is generated once and persists across browser sessions
- Is transmitted with every "dap-collect" event (continuously on all sites)
- Allows the remote server to track individual users across time
- Is not disclosed in the privacy policy or permissions

**Verdict**: Combined with the browsing history collection, this creates a comprehensive surveillance system that can track individual users' browsing patterns over extended periods.

## False Positives Analysis

**Legitimate PDF Detection**: The extension's core functionality of finding PDF links on pages is legitimate. The content script scans for:
- Links with `.pdf` extensions
- Iframes/embeds pointing to PDFs
- PDF content-type headers via webRequest listener

This scanning behavior is expected for a PDF download utility.

**Link Validation Service**: It's arguable that checking PDF links for validity (dead links, etc.) could provide user value. However, this doesn't require transmitting full URLs, referrers, and persistent user IDs.

**Not Obfuscated**: The code is webpack-bundled but not intentionally obfuscated. The minification is standard build tooling, not an attempt to hide malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| service.download-all-pdfs.com/check_links | Ostensibly validates PDF links; actually collects browsing data | User ID, extension version, current URL, referrer, content type, timestamp, navigation type, PDF links array | HIGH - Creates comprehensive browsing surveillance database |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

This extension engages in undisclosed surveillance-style data collection that far exceeds its stated purpose. While the core PDF download functionality is legitimate, the extension:

1. **Collects extensive browsing data** - Every URL, referrer, and page visited across all HTTP/HTTPS sites
2. **Persistent tracking** - Assigns unique IDs to users for cross-session tracking
3. **Continuous surveillance** - Polls every 800ms on every page
4. **Inadequate disclosure** - Users have no clear indication that their browsing history is being transmitted to a remote server
5. **Broad scope** - Operates on all websites via `<all_urls>` permissions
6. **Significant user base** - 60,000 users affected

The extension has legitimate functionality but uses it as a vehicle for comprehensive browsing surveillance. This represents a clear privacy violation and is classified as HIGH risk due to:
- Undisclosed data collection (users believe they're just downloading PDFs)
- Scale of collection (all browsing activity, not just PDF-related)
- Persistence (unique user tracking across sessions)
- User base size (60K users = significant surveillance infrastructure)

This does not rise to CRITICAL because:
- No evidence of credential theft or injection attacks
- Data appears to go to the stated service domain (not hidden C2)
- No evidence of cookie harvesting or session hijacking
- Surveillance is extensive but appears to be analytics/tracking rather than active malware

**Recommendation**: Users should be warned about the extensive data collection. The extension should either:
1. Remove all browsing history collection, or
2. Provide clear, prominent disclosure and obtain explicit user consent
