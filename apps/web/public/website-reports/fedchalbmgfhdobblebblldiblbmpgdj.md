# Security Analysis: Video Downloader (fedchalbmgfhdobblebblldiblbmpgdj)

## Extension Metadata
- **Name**: Video Downloader (display name: "__MSG_name__")
- **Extension ID**: fedchalbmgfhdobblebblldiblbmpgdj
- **Version**: 1.8.1
- **Manifest Version**: 3
- **Estimated Users**: ~70,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary
Video Downloader is a browser extension that enables users to download videos from Facebook, Instagram, Twitter, Vimeo, and Dailymotion. While its core functionality is legitimate, the extension employs **invasive techniques to intercept authentication tokens, session cookies, and authorization headers** from these platforms to access video content on behalf of the user. This raises significant privacy and security concerns, as the extension has programmatic access to sensitive credentials that could be misused for account hijacking or data exfiltration.

The extension intercepts:
- Facebook DTSG tokens and c_user cookies
- Twitter API request headers (all headers)
- Vimeo Authorization headers

Additionally, the extension opens a remote URL (`saverchrome.com/install`) on installation, which could be used for tracking or analytics.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Facebook Token and Cookie Interception (HIGH SEVERITY)
**Severity**: HIGH
**Files**:
- `/src/js/serviceWorker.js` (lines 3733-3737, 3898-3902)
- `/src/js/contentScript.js` (lines 12797-12801, 12853-12854)

**Analysis**:
The extension intercepts Facebook's DTSG (Dynamic Token Secure Guard) tokens and c_user cookies to authenticate video download requests. This allows the extension to make authenticated API calls on behalf of the user.

**Code Evidence** (`serviceWorker.js`, lines 3733-3737):
```javascript
chrome.webRequest.onBeforeSendHeaders.addListener((n => {
  const t = new URL(n.url).searchParams.get("fb_dtsg_ag");
  t && ie.tokens.set(lt.Facebook, t)
}), {
  urls: ["*://*.facebook.com/video/video_data_async/*", "*://*.facebook.com/ajax/*"]
}, ["requestHeaders"])
```

**Code Evidence** (`contentScript.js`, lines 12797-12801):
```javascript
const Jy = e => {
  var t;
  const n = ("; " + document.cookie).split("; " + e + "=");
  if (2 === n.length) return null == (t = n.pop()) ? void 0 : t.split(";").shift()
};
```

**Usage** (`contentScript.js`, line 12853):
```javascript
const r = Jy("c_user");
fetch(`https://www.facebook.com/video/video_data_async/?video_id=${t}&fb_dtsg_ag=${e}&__user=${r}&__a=1`)
```

**Privacy Concerns**:
- DTSG tokens are anti-CSRF tokens that authenticate user actions
- c_user cookies contain the user's Facebook ID
- Extension stores tokens in `chrome.storage.local` (persistent storage)
- Tokens could be exfiltrated if the extension is compromised
- No evidence of encryption for stored tokens

**Risk**: An attacker who compromises the extension (e.g., via update hijacking) could steal these tokens and cookies to:
- Perform actions on behalf of the user on Facebook
- Access private video content
- Potentially hijack the user's session

**Verdict**: **HIGH RISK** - Unnecessary credential interception and storage.

---

### 2. Twitter Request Header Interception (MEDIUM SEVERITY)
**Severity**: MEDIUM
**Files**:
- `/src/js/serviceWorker.js` (lines 3750-3754, 3819-3823)

**Analysis**:
The extension intercepts ALL request headers from Twitter API calls and stores them in local storage. This includes authentication tokens, cookies, and potentially sensitive metadata.

**Code Evidence** (`serviceWorker.js`, lines 3750-3754):
```javascript
chrome.webRequest.onBeforeSendHeaders.addListener((n => {
  n.requestHeaders && ie.tokens.set(lt.Twitter, n.requestHeaders)
}), {
  urls: ["*://*.twitter.com/i/api/*"]
}, ["requestHeaders"])
```

**Usage** (`serviceWorker.js`, line 3820):
```javascript
e = (await ie.tokens.get(lt.Twitter)).reduce(((n, {
  name: t,
  value: r
}) => ({
  ...n,
  [t]: r
})), {})
```

**Privacy Concerns**:
- Intercepts entire header array (not just specific authentication headers)
- Headers may include:
  - OAuth tokens
  - CSRF tokens
  - Session cookies
  - User-Agent strings
  - Referer URLs
- No filtering of sensitive headers
- Stored persistently in `chrome.storage.local`

**Verdict**: **MEDIUM RISK** - Broad credential interception with potential for misuse.

---

### 3. Vimeo Authorization Header Interception (MEDIUM SEVERITY)
**Severity**: MEDIUM
**Files**:
- `/src/js/serviceWorker.js` (lines 3848-3858)
- `/src/js/contentScript.js` (lines 12933-12936)

**Analysis**:
The extension intercepts Vimeo's Authorization headers from API requests and reuses them to download videos.

**Code Evidence** (`serviceWorker.js`, lines 3848-3858):
```javascript
const t = n.requestHeaders ?? [];
let r = null;
for (let n = 0; n < t.length; ++n)
  if ("Authorization" === t[n].name) {
    r = t[n].value;
    break
  }
r && ie.tokens.set(lt.Vimeo, r)
}), {
  urls: ["*://api.vimeo.com/*"]
}, ["requestHeaders"])
```

**Usage** (`contentScript.js`, lines 12933-12936):
```javascript
fetch(`https://api.vimeo.com/videos/${n}`, {
  headers: {
    Authorization: r,
    "Content-Type": "application/json"
  }
})
```

**Privacy Concerns**:
- Authorization headers typically contain OAuth bearer tokens
- Tokens grant programmatic access to the user's Vimeo account
- Stored persistently without expiration management
- Could be used to access private videos or user data

**Verdict**: **MEDIUM RISK** - OAuth token interception for API access.

---

### 4. Remote URL Opening on Installation (LOW SEVERITY)
**Severity**: LOW
**Files**:
- `/src/js/serviceWorker.js` (lines 3859, 3888-3897)

**Analysis**:
The extension opens a remote URL (`saverchrome.com/install`) when the extension is installed or updated.

**Code Evidence** (`serviceWorker.js`, lines 3888-3897):
```javascript
const vp = "https://saverchrome.com/install";
// ...
chrome.runtime.onInstalled.addListener((({
  reason: n
}) => {
  fetch(`${vp}?r=${n}`).then((n => n.json())).then((async ({
    url: n
  }) => {
    _o.isNull(n) || await chrome.tabs.create({
      url: n
    })
  }))
}))
```

**Analysis**:
- The extension makes a network request to `saverchrome.com/install?r=[reason]` where `reason` is "install" or "update"
- The server response contains a URL that is automatically opened in a new tab
- This allows the developer to:
  - Track installation/update events
  - Redirect users to arbitrary URLs (landing pages, ads, etc.)
  - Potentially collect user data via URL parameters or browser fingerprinting

**Privacy Concerns**:
- Installation tracking without explicit user consent
- Server-controlled URL redirection (could be weaponized)
- Potential for browser fingerprinting via the opened page

**Verdict**: **LOW RISK** - Tracking mechanism with limited immediate harm but potential for abuse.

---

### 5. Instagram Story Injection (FALSE POSITIVE)
**Severity**: N/A (Not a Vulnerability)
**Files**:
- `/src/js/instagramStory.js` (lines 1-47)

**Analysis**:
The extension injects a script on Instagram to extract video URLs from React internal properties (`__reactProps`, `__reactFiber`). This is a common technique for extracting data from React-based SPAs and does not pose a security risk.

**Code Evidence** (`instagramStory.js`, lines 14-20):
```javascript
if (!e || document.location.pathname.split("/")[2] ===
    t[n].parentElement.parentElement.parentElement.parentElement.parentElement
        .parentElement.parentElement.parentElement.parentElement.parentElement
        ["__reactProps" + p].children[n].props.children.props.children
        .props.queryReference.code) {
  // Extract video URL from React internals
}
```

**Purpose**: Extracts Instagram Story video URLs by traversing React's internal DOM structure.

**Verdict**: **NOT MALICIOUS** - Standard technique for accessing data in React applications.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Privacy Impact |
|--------|---------|------------------|----------------|
| `saverchrome.com/install` | Installation tracking | Install/update reason | LOW - Basic analytics |
| `www.dailymotion.com/player/metadata` | Video metadata retrieval | URL pathname | NONE - Public API |
| `www.facebook.com/video/video_data_async` | Video download URL retrieval | Video ID, DTSG token, c_user cookie | HIGH - Sends user credentials |
| `api.vimeo.com/videos/*` | Video metadata retrieval | Authorization header | MEDIUM - Sends OAuth token |
| `www.instagram.com/graphql/query` | Video URL retrieval | Shortcode (public post ID) | NONE - Public API |

### Data Storage Analysis

**chrome.storage.local Contents**:
- `service` - Extension settings (sidebar, dark mode, etc.)
- `videos` - List of detected videos per tab
- `tokens` - **Stored authentication credentials**:
  - `facebook` - DTSG token
  - `twitter` - Full request header array
  - `vimeo` - Authorization header

**Security Concerns**:
- Tokens are stored in plaintext (no encryption observed)
- No token expiration or rotation mechanisms
- Persistent storage survives browser restarts
- Accessible to extension context (vulnerable to XSS if extension has bugs)

---

## Permission Analysis

### Declared Permissions
- `storage` - Used to store settings, video lists, and **authentication tokens** (CONCERNING)
- `activeTab` - Used to inject content scripts on active tabs
- `downloads` - Used to trigger video downloads
- `webRequest` - Used to intercept authentication tokens and headers (CONCERNING)

### Host Permissions
- `<all_urls>` - Required for video detection on all websites (overly broad but justified for functionality)

### Concerning Permission Combinations
1. **webRequest + storage**: Allows interception and persistent storage of credentials
2. **<all_urls> + webRequest**: Can intercept requests from any website

**Verdict**: Permissions are consistent with stated functionality but enable privacy-invasive behavior.

---

## Content Security Policy (CSP)
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Analysis**: Standard CSP that prevents inline scripts and external script loading. No issues identified.

---

## Web Accessible Resources
```json
{
  "matches": ["<all_urls>"],
  "resources": [
    "assets/*.png",
    "src/js/instagramStory.js"
  ]
}
```

**Analysis**:
- PNG assets are benign (likely UI icons)
- `instagramStory.js` is injected into Instagram pages to extract React data
- No security concerns with exposed resources

---

## Code Quality and Obfuscation
- **Obfuscated**: YES (flagged by ext-analyzer)
- **Obfuscation Level**: Medium (variable renaming, minification)
- **Libraries Detected**: React, Lodash (bundled)
- **Code Size**: ~426KB (contentScript.js)

**Analysis**: Code is minified but not heavily obfuscated. The large bundle size is typical for React-based extensions.

---

## Comparison to Advertised Functionality

**Advertised Purpose**: Download videos from social media platforms

**Actual Behavior**:
✅ Downloads videos from Facebook, Instagram, Twitter, Vimeo, Dailymotion
❌ Intercepts and stores user authentication tokens
❌ Reads Facebook cookies
❌ Stores credentials persistently without encryption
❌ Opens tracking URL on installation

**Verdict**: The extension performs its advertised function but uses **privacy-invasive techniques** that are not disclosed to users.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| Obfuscated code | `contentScript.js` | Could be mistaken for malware | Minified React bundle |
| React internal access | `instagramStory.js` | Could be mistaken for DOM hijacking | Instagram video extraction |
| Password references | `contentScript.js` (line 2159) | Could be mistaken for credential theft | React input type definitions |

---

## Risk Mitigation Recommendations

For Users:
1. **Revoke and rotate credentials** for Facebook, Twitter, and Vimeo after using this extension
2. **Monitor account activity** for unauthorized actions
3. Consider alternative video download tools that don't intercept tokens
4. Be aware that the extension has access to your authentication credentials

For Extension Developer:
1. **Minimize credential storage** - delete tokens immediately after use
2. **Encrypt stored tokens** using Web Crypto API
3. **Implement token expiration** and refresh mechanisms
4. **Request only necessary headers** (don't store entire Twitter header array)
5. **Disclose credential interception** in privacy policy
6. **Remove or make optional** the saverchrome.com tracking beacon

---

## Final Verdict

**Risk Level: MEDIUM**

**Rationale**:
The extension performs its advertised function (video downloading) but employs **privacy-invasive techniques** to intercept and store user authentication credentials. While there is no evidence of malicious intent or active credential exfiltration, the design pattern creates significant risk:

1. **Token interception is unnecessary** - Many video platforms provide public APIs or download URLs that don't require user credentials
2. **Persistent credential storage** creates a honeypot for attackers
3. **No encryption** means credentials are vulnerable to local attacks
4. **Broad permission scope** (webRequest + <all_urls>) enables credential theft at scale

**Key Concerns**:
- Intercepts Facebook DTSG tokens and cookies
- Stores Twitter request headers (all of them)
- Intercepts Vimeo OAuth tokens
- No evidence of encryption or secure handling
- Opens remote tracking URL on install

**Mitigating Factors**:
- No evidence of actual credential exfiltration in current version
- Tokens appear to be used only for stated video download functionality
- Extension is published on Chrome Web Store (subject to review)

**Recommendation**: Users should exercise caution and consider the privacy tradeoffs. The extension should be redesigned to avoid credential interception where possible.

---

## Vulnerability Summary

| Category | Count | Details |
|----------|-------|---------|
| Critical | 0 | None |
| High | 1 | Facebook token/cookie interception |
| Medium | 2 | Twitter header interception, Vimeo OAuth interception |
| Low | 1 | Remote URL tracking beacon |
| **Total** | **4** | - |

---

## Appendix: Dataflow Traces (from ext-analyzer)

**EXFILTRATION Flows (3 detected, all benign):**
1. `chrome.storage.local.get → fetch(www.w3.org)` - FALSE POSITIVE (React bundler artifact)
2. `document.querySelectorAll → fetch(www.w3.org)` - FALSE POSITIVE (React bundler artifact)
3. `document.getElementById → fetch(www.w3.org)` - FALSE POSITIVE (React bundler artifact)

**Analysis**: The ext-analyzer flagged three exfiltration flows, but all three are false positives. The `www.w3.org` references are likely from React bundler comments or type definitions, not actual network requests. Manual code review confirms no exfiltration of DOM data or storage contents.

**Real Network Flows** (not flagged by analyzer):
- `chrome.storage.local.get("tokens") → fetch(api.vimeo.com)` - Sends stored Vimeo OAuth token
- `chrome.storage.local.get("tokens") → fetch(facebook.com/video_data_async)` - Sends stored Facebook DTSG token
- `document.cookie → fetch(facebook.com/video_data_async)` - Sends Facebook c_user cookie

These flows represent the actual privacy concerns but were not detected by the static analyzer (likely due to complex async flows and storage abstraction).

---

**Analysis completed on**: 2026-02-15
**Analyzer version**: ext-analyzer 1.0 + manual review
