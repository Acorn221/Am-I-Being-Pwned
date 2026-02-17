# Security Analysis: Video Downloader Plus (hkdmdpdhfaamhgaojpelccmeehpfljgf)

## Extension Metadata
- **Name**: Video Downloader Plus
- **Extension ID**: hkdmdpdhfaamhgaojpelccmeehpfljgf
- **Version**: 3.0.2
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: vidow.io
- **Analysis Date**: 2026-02-14

## Executive Summary
Video Downloader Plus is a video download extension with **MEDIUM** risk status. The extension provides legitimate video downloading functionality but transmits user authentication tokens to remote servers, reads authentication cookies, and implements a freemium model with server-side validation. While no direct malicious behavior was detected, the login token transmission pattern combined with extensive permissions (cookies, webRequest, all_urls) creates potential privacy and security concerns.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Login Token Transmission (Data Exfiltration)
**Severity**: MEDIUM
**Files**:
- `/js/common.js` (lines 107-127)
- `/js/background.js` (lines 545-579)

**Analysis**:
The extension retrieves user login tokens from `chrome.storage.sync` and transmits them to remote servers for authentication validation.

**Code Evidence** (`common.js`, line 107):
```javascript
vd.autoLogin = function(callback) {
    chrome.storage.sync.get({
        login_token: false
    }, function(items) {
        if(!items.login_token) {
            callback({status: 0});
            return;
        }
        fetch(vd.serverUrl+"autoLogin/"+ items.login_token)
            .then(response=>response.json())
            .then(response=>{
                if(!response.status) {
                    callback({status: 0});
                    return;
                }
                callback({status: 1});
            });
    });
};
```

**Data Flow**:
1. Extension reads `login_token` from `chrome.storage.sync`
2. Token transmitted to `https://vidow.io/autoLogin/[TOKEN]` via GET request
3. Response determines if user is authenticated
4. Called periodically (every 30 seconds) via background script

**Endpoints**:
- Primary: `https://vidow.io/autoLogin/[login_token]`
- Secondary: `https://vidow.io/status/[timestamp]`

**Risk Factors**:
- Login tokens transmitted over network (potential interception)
- Token sent as URL parameter (logged in server logs)
- Automatic periodic transmission without user interaction
- Token stored in sync storage (accessible across devices)

**Verdict**: **MEDIUM RISK** - While HTTPS provides transport security, transmitting authentication tokens as URL parameters is poor security practice. Tokens should be sent in request headers or POST body.

---

### 2. Cookie Access for Authentication
**Severity**: MEDIUM
**Files**: `/js/background.js` (lines 507-524)

**Analysis**:
The extension reads authentication cookies from the developer's domain to sync login status.

**Code Evidence** (`background.js`, line 507):
```javascript
vd.getLoginStatus = async function (callback) {
    let data = await chrome.cookies.get({url: vd.serverUrl, "name": "auth"});
    let loginStatus = {
        logged_in: false,
        upgraded: 'false'
    };
    try {
        loginStatus = JSON.parse(decodeURIComponent(data.value));
        await chrome.storage.sync.set({
            logged_in: loginStatus.logged_in,
            upgraded: loginStatus.upgraded ? 'true' : 'false'
        });
        return loginStatus;
    } catch (e) {
        return null;
    }
};
```

**Purpose**:
- Reads "auth" cookie from `vidow.io` domain
- Cookie contains JSON with `logged_in` and `upgraded` status
- Synced to `chrome.storage.sync` for cross-device availability

**Risk Factors**:
- Cookie permission requested for authentication, not video functionality
- Authentication state synced across all user devices via sync storage
- No clear user consent mechanism for cookie reading

**Verdict**: **MEDIUM RISK** - Cookie access is limited to developer's domain and used for legitimate authentication, but this justification for the cookies permission is not transparent to users who expect video download functionality.

---

### 3. Overly Broad Web Accessible Resources
**Severity**: LOW
**Files**: `manifest.json` (lines 36-41)

**Analysis**:
The manifest declares all extension resources as web accessible to all websites.

**Code Evidence**:
```json
"web_accessible_resources": [
    {
        "resources": ["*"],
        "matches": ["<all_urls>"]
    }
]
```

**Risk**:
- Any website can probe extension files
- Extension fingerprinting vulnerability
- Potential for extension detection by malicious sites
- Enables web pages to load extension resources

**Justification**: None apparent - no evidence of extension resources being loaded by web pages in the code.

**Verdict**: **LOW RISK** - While overly permissive, no evidence of active exploitation vector. Should be narrowed to specific resources if needed.

---

### 4. Network Request Monitoring
**Severity**: LOW
**Files**: `/js/background.js` (lines 174-201, 635)

**Analysis**:
The extension monitors all network requests via `webRequest` API to detect video downloads.

**Code Evidence** (`background.js`, line 635):
```javascript
chrome.webRequest.onHeadersReceived.addListener(
    vd.inspectNetworkResponseHeaders,
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
);
```

**Inspection Logic** (line 174):
```javascript
vd.inspectNetworkResponseHeaders = function (details) {
    let root_domain = vd.extractRootDomain(details.url);
    let videoType = vd.getVideoType(details.responseHeaders);

    if (root_domain !== 'vimeo.com' && videoType) {
        chrome.tabs.query({active: true}, function (tabs) {
            let tab = tabs[0];
            let tabId = tabs[0].id;
            vd.addVideoLinkToTab({
                url: details.url,
                webpage_url: tab.url,
                size: vd.getVideoSize(details.responseHeaders),
                fileName: vd.getFileName(tab.title),
                title: vd.getFileName(tab.title),
                extension: "." + videoType
            }, tabId, tab.url);
        });
    }
    return {responseHeaders: details.responseHeaders};
};
```

**Data Captured**:
- Video file URLs (detected via Content-Type headers)
- Video file sizes (from Content-Length headers)
- Page titles (from active tab)
- Page URLs (from active tab)

**Storage**: All data stored locally in `chrome.storage.local` (not transmitted to server)

**Verdict**: **LOW RISK** - Network monitoring is legitimate for video detection functionality. Data stored locally, not exfiltrated. Core feature requires this permission.

---

### 5. Third-Party Video Processing Servers
**Severity**: MEDIUM
**Files**:
- `/js/common.js` (lines 175-189)
- `/js/background.js` (lines 358-370, 428-467)

**Analysis**:
The extension sends video page URLs to remote servers for processing and metadata extraction.

**Code Evidence** (`common.js`, line 175):
```javascript
vd.get4KData = function (videoUrl, callback) {
    fetch(vd.serverUrl2 + "getinfo.php?" + new URLSearchParams({
        videourl: encodeURIComponent(videoUrl)
    }), {
        method: "GET",
        headers: {
            'Content-Type': 'application/json'
        }
    }).then(result => result.json()).then(data => {
        callback(data);
    }).catch((e) => {
        console.error(e);
        callback(false);
    });
};
```

**Data Transmitted**:
- Current page URLs (e.g., YouTube video URLs)
- Sent to `https://vidow.me/chrome/getinfo.php?videourl=[URL]`

**Purpose**:
- Server-side video metadata extraction
- Enables 4K/HD video download options
- Returns: title, thumbnail, available formats, file sizes

**Frequency**:
- Triggered on every page load (if user is premium)
- Cached locally for 1 hour (free users) or 5 minutes (premium users)

**Privacy Concern**:
- User's browsing activity (video URLs) sent to third-party server
- Server can build profile of user's viewing habits
- No opt-out mechanism mentioned

**Verdict**: **MEDIUM RISK** - While the server processing is required for advanced features, transmitting browsing URLs to third-party servers without explicit user consent is a privacy concern.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `vidow.io/autoLogin/[token]` | Auto-login validation | Login token (GET param) | Every 30 seconds |
| `vidow.io/status/[timestamp]` | Login status sync | Timestamp | Every 30 minutes |
| `vidow.io/video_list/get_all_video_data` | Fetch saved videos | None (cookie auth) | Every 30 seconds |
| `vidow.io/video_list/add_video` | Save video for later | Video title, URL, thumbnail, MD5 | User-initiated |
| `vidow.io/video_list/delete_video` | Delete saved video | Video ID, login token | User-initiated |
| `vidow.me/chrome/getinfo.php` | Video metadata extraction | Video page URL | Per-page (if premium) |
| `chrome.vidow.io/installed/` | Install notification | None | Once per install |
| `chrome.vidow.io/disabled/` | YouTube redirect page | None | When popup opened on YouTube |

### Data Flow Summary

**Data Collection**:
- Video URLs visited (transmitted to vidow.me)
- Page titles of video pages (stored locally)
- Saved videos list (title, URL, thumbnail)
- Login/premium status
- Authentication cookies from vidow.io domain

**User Data Transmitted**:
- Login tokens (every 30 seconds)
- Video page URLs (on page load if premium)
- Saved video metadata (user-initiated)

**Tracking/Analytics**:
- Server-side logs likely capture all video URLs processed
- Login token transmissions allow user activity correlation

**Third-Party Services**:
- vidow.io (authentication, saved videos)
- vidow.me (video metadata extraction)

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required to access tab URLs/titles for video detection | Low (core feature) |
| `webRequest` | Monitor network responses for video file detection | Medium (passive monitoring) |
| `declarativeNetRequest` | Set Content-Disposition headers for downloads | Low (download functionality) |
| `cookies` | Read authentication cookies from vidow.io | Medium (authentication, not video-related) |
| `storage` | Store settings, cached video data, login tokens | Low (necessary) |
| `host_permissions: <all_urls>` | Detect videos on any website | Medium (broad but functional) |

**Assessment**: Most permissions are justified for core functionality, but the `cookies` permission is used solely for authentication (not video downloading), which may not be transparent to users.

---

## Content Security Policy
```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self';"
}
```
**Assessment**: Standard Manifest V3 CSP. Prevents inline scripts and external script loading. Good security posture.

---

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No obfuscated variable names beyond standard minification
3. Uses modern Fetch API instead of XMLHttpRequest
4. Manifest V3 adoption (security improvements)
5. CSP prevents external script injection
6. No extension enumeration or interference with other extensions
7. No residential proxy infrastructure
8. No ad injection or DOM manipulation for monetization

### Negative Indicators
1. Login tokens transmitted as GET URL parameters (should use POST body/headers)
2. Frequent polling (every 30 seconds for login status)
3. Browsing URLs transmitted to third-party servers
4. No clear opt-in for data transmission
5. Web accessible resources overly broad (`*`)
6. Authentication state synced via chrome.storage.sync (accessible across devices)

### Obfuscation Level
**Low** - Standard minification from build tools. Logic is readable. No deliberate obfuscation.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✓ Limited | Only reads auth cookie from own domain (vidow.io) |
| Hidden data exfiltration | ✓ Partial | Video URLs transmitted to vidow.me server |

---

## Freemium Model Analysis

**Free Tier**:
- Basic video detection from network requests
- Download videos detected in network traffic
- File format filtering (.mp4, .mov, .flv, .webm, .3gp, .ogg, .m4a, .wav, .bin)
- Minimum file size filtering (100KB, 1MB, 2MB)

**Premium Tier** (requires login + subscription):
- 4K/HD video downloads via server-side processing
- MP3 audio extraction
- Save videos for later (cloud storage)
- Chromecast support
- Advanced format options

**Monetization**:
- Freemium subscription model
- Account creation at vidow.io
- Upgrade prompts in popup
- Install notification redirects

**Server-Side Processing**: Premium features require server infrastructure for video transcoding/extraction, which necessitates transmitting video URLs to servers.

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Data Exfiltration Present**: Login tokens and video URLs transmitted to remote servers
2. **Privacy Concerns**: User browsing activity (video URLs) sent to third-party without explicit opt-in
3. **Authentication Pattern**: Login token in URL parameters is poor security practice
4. **Excessive Polling**: Every 30 seconds creates unnecessary network traffic and server load
5. **Cookie Access**: Used for authentication, not core video functionality
6. **Legitimate Core Functionality**: Video detection and download features work as advertised
7. **No Active Malware**: No extension killing, proxy injection, or ad fraud detected

### Key Risk Factors
- **Medium Risk**: Login token transmission (poor security practice but HTTPS encrypted)
- **Medium Risk**: Video URL transmission (privacy concern, user activity tracking)
- **Medium Risk**: Cookie access (authentication purposes, limited scope)
- **Low Risk**: Network monitoring (legitimate video detection)
- **Low Risk**: Web accessible resources (overly broad but no active exploitation)

### Recommendations
**For Users**:
- Be aware that video URLs you visit are transmitted to vidow.me servers (if using premium features)
- Understand that login tokens are transmitted periodically for authentication
- Consider privacy implications of server-side video processing

**For Developers**:
- Transmit login tokens in POST body or Authorization headers, not URL parameters
- Implement clear user consent for transmitting browsing URLs to servers
- Reduce polling frequency (30 seconds is excessive)
- Narrow web_accessible_resources to specific files if needed
- Add privacy policy disclosure about data transmission

### User Privacy Impact
**MEDIUM** - The extension transmits:
- Login authentication tokens (every 30 seconds)
- Video page URLs (for premium users on every page load)
- Saved video metadata (user-initiated)
- Authentication cookies from vidow.io

**Data Retention**: Unknown - no privacy policy visible in extension code.

---

## Technical Summary

**Lines of Code**: ~700 (excluding minified libraries)
**External Dependencies**: jQuery 3.1.1, Bootstrap (UI only), MD5 library
**Third-Party Libraries**: Standard libraries, no suspicious SDKs
**Remote Code Loading**: None
**Dynamic Code Execution**: None

---

## Conclusion

Video Downloader Plus is a **legitimate video download extension with medium privacy/security concerns**. The core functionality (detecting and downloading videos from network traffic) works as advertised and requires the broad permissions requested. However, the extension transmits user login tokens and browsing activity (video URLs) to remote servers for premium features without transparent user consent.

**Key Concerns**:
1. Login tokens transmitted as URL parameters (security anti-pattern)
2. Video URLs sent to third-party servers (privacy concern)
3. Frequent polling (every 30 seconds) for authentication status
4. Cookie access used for authentication, not core functionality

**Positive Aspects**:
1. No malware, ad injection, or extension interference
2. Manifest V3 with proper CSP
3. No code obfuscation or remote code loading
4. Video detection functionality is legitimate and transparent

**Final Verdict: MEDIUM RISK** - The extension is not malicious, but the data transmission patterns (login tokens, video URLs) and authentication implementation create privacy and security concerns. Users should be aware that their video browsing activity is shared with the developer's servers when using premium features.

**Recommended for**: Users comfortable with server-side video processing and willing to share browsing activity for premium features.

**Not recommended for**: Privacy-conscious users or those seeking purely client-side video downloading.
