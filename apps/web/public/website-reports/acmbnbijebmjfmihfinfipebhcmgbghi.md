# Security Analysis Report: Video Downloader Web

## Extension Metadata
- **Extension ID**: acmbnbijebmjfmihfinfipebhcmgbghi
- **Extension Name**: Video Downloader Web
- **Version**: 1.0.7
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Video Downloader Web is a browser extension that detects and downloads videos from various social media platforms including Facebook, Instagram, Twitter/X, and Dailymotion. The extension shows **MEDIUM risk** due to several concerning privacy and security issues:

1. **Hardcoded Twitter API Bearer Token** - Uses a static bearer token to access Twitter's internal API
2. **X-Frame-Options Header Manipulation** - Removes security headers on Facebook
3. **Cookie Harvesting** - Reads and exfiltrates Facebook DTSG tokens and Twitter CSRF tokens
4. **Internal React Internals Access** - Deeply accesses Instagram/Facebook internal React properties via DOM manipulation
5. **Broad Permissions** - Requests `<all_urls>` host permissions and webRequest access

The extension appears to be functionally legitimate (video downloading) but uses several invasive techniques that bypass platform security measures. There is no evidence of remote command & control, malware, or data exfiltration beyond what's needed for its stated functionality.

## Vulnerability Details

### 1. Hardcoded Twitter API Bearer Token (HIGH)

**Severity**: HIGH
**File**: `js/background.js`
**Lines**: 164-169

**Description**: The extension contains a hardcoded Twitter API bearer token used to make authenticated requests to Twitter's internal API endpoints.

**Code Evidence**:
```javascript
fetch(`https://api.x.com/2/timeline/conversation/${e}.json?...`, {
  method: "GET",
  headers: {
    Authorization: "Bearer AAAAAAAAAAAAAAAAAAAAAPYXBAAAAAAACLXUNDekMxqa8h%2F40K4moUkGsoc%3DTYfbDKbT3jJPCEVnMYqilB28NHfOPqkca3qaAxGfsyKCs0wRbw",
    "x-csrf-token": t
  }
})
```

**Impact**:
- Uses Twitter's internal API without proper authorization
- Token could be rate-limited or revoked by Twitter
- Violates Twitter's Terms of Service
- If token is compromised, could be used by attackers

**Verdict**: VIOLATION - Uses hardcoded API credentials to bypass platform restrictions

---

### 2. X-Frame-Options Security Header Removal (MEDIUM)

**Severity**: MEDIUM
**File**: `js/background.js`
**Lines**: 36-43

**Description**: The extension actively removes the `X-Frame-Options` security header from all Facebook responses, weakening security protections.

**Code Evidence**:
```javascript
chrome.webRequest.onHeadersReceived.addListener((e => {
  for (let t = 0; t < e.responseHeaders.length; t++)
    "x-frame-options" === e.responseHeaders[t].name.toLowerCase() &&
      e.responseHeaders.splice(t, 1);
  return {
    responseHeaders: e.responseHeaders
  }
}), {
  urls: ["*://*.facebook.com/*"]
}, ["responseHeaders", "extraHeaders"])
```

**Impact**:
- Removes clickjacking protection on Facebook
- Enables Facebook pages to be embedded in iframes (normally blocked)
- Could facilitate social engineering or clickjacking attacks
- Modifies security posture of user's Facebook sessions

**Verdict**: SECURITY_WEAKENING - Actively removes browser security protections

---

### 3. Facebook DTSG Token Harvesting (MEDIUM)

**Severity**: MEDIUM
**File**: `js/background.js`, `js/contentscript.js`
**Lines**: background.js:26-33, contentscript.js:208-220

**Description**: The extension intercepts and stores Facebook's `fb_dtsg_ag` authentication token from network requests, then uses it to make authenticated API calls.

**Code Evidence**:
```javascript
// Token capture in background.js
chrome.webRequest.onSendHeaders.addListener((e => {
  const t = new URL(e.url).searchParams.get("fb_dtsg_ag");
  if (t) {
    if (vd.dtsgToken === t) return;
    vd.dtsgToken = t, chrome.storage.local.set({
      currentFb_dtsgToken: t
    }, (() => {}))
  }
}), {
  urls: ["*://*.facebook.com/video/video_data_async/*", "*://*.facebook.com/ajax/*"]
}, ["requestHeaders"])

// Token usage in contentscript.js
fetch(`https://www.facebook.com/video/video_data_async/?video_id=${e}&fb_dtsg_ag=${t}&__user=${n}&__a=1`)
```

**Impact**:
- Captures authentication tokens from Facebook
- Could be used for session hijacking if exfiltrated
- Makes authenticated requests on behalf of the user
- Stores tokens in chrome.storage (persistence)

**Verdict**: PRIVACY_CONCERN - Harvests and stores sensitive authentication tokens

---

### 4. Twitter CSRF Token Extraction (MEDIUM)

**Severity**: MEDIUM
**File**: `js/contentscript.js`
**Lines**: 138, 149-151

**Description**: Reads Twitter's CSRF token (`ct0`) from cookies and includes it in API requests.

**Code Evidence**:
```javascript
i.x_csrf_token = vd.getCookie("ct0")

vd.getCookie = function(e) {
  var t = ("; " + document.cookie).split("; " + e + "=");
  if (2 === t.length) return t.pop().split(";").shift()
}
```

**Impact**:
- Reads CSRF protection tokens
- Combined with hardcoded bearer token, allows API access
- Bypasses Twitter's security measures

**Verdict**: PRIVACY_CONCERN - Harvests CSRF tokens for API abuse

---

### 5. Instagram React Internal Access (MEDIUM)

**Severity**: MEDIUM
**File**: `js/contentscript.js`, `js/instaStory.js`
**Lines**: contentscript.js:95-103, instaStory.js:entire file

**Description**: Uses deep DOM traversal to access Instagram's internal React component props and state, extracting video URLs from private implementation details.

**Code Evidence**:
```javascript
fetch(`https://www.instagram.com/graphql/query/?query_hash=55a3c4bad29e4e20c20ff4cdfd80f5b4&variables={%22shortcode%22:%22${t}%22}`)

// React internals access
storyVideoUrl = storyVideos[i].parentElement.parentElement.parentElement.parentElement['__reactProps'+reactKey].children.props.children.props.implementations[0].data.hdSrc;
```

**Impact**:
- Accesses private React internals (brittle, implementation-dependent)
- Uses hardcoded Instagram GraphQL query hash
- Bypasses Instagram's intended API usage
- Could break with any Instagram update

**Verdict**: PLATFORM_ABUSE - Reverse-engineers internal APIs

---

### 6. Dailymotion M3U8 Playlist Parsing (LOW)

**Severity**: LOW
**File**: `js/contentscript.js`
**Lines**: 56-80, 180-191

**Description**: Fetches Dailymotion metadata and parses M3U8 video playlists using synchronous XMLHttpRequest.

**Code Evidence**:
```javascript
fetch(`https://www.dailymotion.com/player/metadata/video/${t}`)

var n = new XMLHttpRequest;
n.open("GET", e, !1), n.send()  // Synchronous request
```

**Impact**:
- Uses synchronous XHR (blocks main thread - deprecated)
- Fetches video metadata from Dailymotion
- Low security impact, mostly a performance issue

**Verdict**: MINOR - Uses deprecated synchronous XHR

---

### 7. Overly Broad Permissions (MEDIUM)

**Severity**: MEDIUM
**File**: `manifest.json`
**Lines**: 21-28

**Description**: Requests extremely broad permissions that exceed functional requirements.

**Code Evidence**:
```json
"permissions": [
  "webRequest",
  "downloads",
  "storage"
],
"host_permissions": [
  "<all_urls>"
],
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": ["js/jquery-3.1.1.js", "js/contentscript.js"],
  "all_frames": true
}]
```

**Impact**:
- Content scripts run on ALL websites (not just video platforms)
- webRequest access on all URLs (excessive surveillance capability)
- Could monitor all user browsing activity
- No CSP defined in manifest

**Verdict**: EXCESSIVE_PERMISSIONS - Far broader than necessary

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| jQuery Function checks | jquery-3.1.1.js | Standard jQuery 3.1.1 library |
| XMLHttpRequest usage | jquery-3.1.1.js | Part of jQuery AJAX implementation |
| localStorage usage | background.js:145-146 | Only tracking download count locally |

## API Endpoints & Network Traffic

| Endpoint | Purpose | Authentication | Risk |
|----------|---------|----------------|------|
| `https://api.x.com/2/timeline/conversation/{id}.json` | Fetch Twitter video metadata | Hardcoded bearer token + CSRF | HIGH |
| `https://www.facebook.com/video/video_data_async/` | Fetch Facebook video URLs | Captured DTSG token | MEDIUM |
| `https://www.instagram.com/graphql/query/` | Fetch Instagram video metadata | GraphQL query hash | MEDIUM |
| `https://www.dailymotion.com/player/metadata/video/{id}` | Fetch Dailymotion video info | None | LOW |

**No evidence of**: Remote C2, tracking pixels, analytics SDKs, ad injection, or data exfiltration servers.

## Data Flow Summary

### Data Collection:
1. **Facebook DTSG tokens** - Captured from webRequest, stored in chrome.storage.local
2. **Twitter CSRF tokens** - Read from cookies
3. **Video metadata** - URLs, titles, file sizes from various platforms
4. **Download statistics** - Total download count in localStorage

### Data Storage:
- Local storage only (chrome.storage.local, localStorage)
- No evidence of remote transmission
- Tokens persist across sessions

### Data Usage:
- Tokens used exclusively for making API requests to fetch video URLs
- No evidence of exfiltration to third parties
- Downloads handled via native chrome.downloads API

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

### Risk Factors:
1. **Security Weakening**: Removes X-Frame-Options headers on Facebook
2. **Token Harvesting**: Captures and stores authentication tokens (Facebook, Twitter)
3. **Platform Abuse**: Uses hardcoded API credentials and bypasses intended APIs
4. **Excessive Permissions**: Requests access to all websites despite targeting only 4 platforms
5. **ToS Violations**: Violates Facebook, Instagram, and Twitter Terms of Service

### Mitigating Factors:
1. No evidence of malware or remote C2 infrastructure
2. No data exfiltration to third parties
3. Functionality matches stated purpose (video downloading)
4. No ad injection, cookie theft, or credential phishing
5. Open source libraries (jQuery 3.1.1)
6. No code obfuscation (beyond standard minification)

### Recommendations:
1. **For Users**: This extension violates platform Terms of Service and could result in account restrictions. Consider using official download features or platform-approved tools instead.
2. **For Developers**: Reduce permissions to only required domains, remove security header manipulation, use official APIs where available, implement proper CSP.
3. **For Reviewers**: Extension should be flagged for ToS violations and excessive permission requests.

## Verdict

**MEDIUM RISK** - The extension appears functionally legitimate but employs invasive techniques that:
- Violate multiple platform Terms of Service
- Harvest authentication tokens
- Remove security protections
- Request excessive permissions

While there is no evidence of malicious intent or data exfiltration, the security weakening behaviors and platform abuse present meaningful risks to users.
