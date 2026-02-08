# Vulnerability Report: Atomic Video Downloader

## Extension Metadata
- **Extension ID**: agipnmmjnjcfgkhmlgifikmibgngblop
- **Extension Name**: Atomic Video Downloader
- **Version**: 1.1.43
- **User Count**: N/A
- **Manifest Version**: 3

## Executive Summary

Atomic Video Downloader is a legitimate video downloading extension with **MEDIUM** risk. The extension requires communication with localhost services for advanced features (video stream downloading) and implements a freemium licensing model. While the extension exhibits several concerning patterns including localhost connections and obfuscated configuration delivery, these are integral to its video downloading functionality rather than malicious behavior. The primary concerns are security weaknesses in localhost authentication and potential privacy implications of telemetry tracking.

## Vulnerability Details

### 1. MEDIUM - Localhost WebSocket Connection for Video Stream Processing
**Severity**: MEDIUM
**File**: `popup.js` (line 1)
**Code**:
```javascript
o=new WebSocket(l("77733a2f2f6c6f63616c686f73743a39303330"))
// Decodes to: ws://localhost:9030
```

**Description**: The extension connects to a localhost WebSocket server on port 9030 to handle video stream downloads (m3u8, mpd formats). This requires a companion desktop application called "Atomic Video Plus."

**Verdict**: MEDIUM RISK - This is part of intended functionality for streaming video downloads but creates a local attack surface. The WebSocket communication lacks apparent authentication, allowing any website to potentially interact with the localhost service if the port is open.

**Recommendation**: Implement WebSocket authentication tokens or origin validation.

---

### 2. MEDIUM - Localhost HTTP API with Weak Authentication
**Severity**: MEDIUM
**File**: `background.js` (line 68)
**Code**:
```javascript
o = (e, t, n) => fetch(`http://${(e=>{let t="";const{length:n}=e;for(let o=0;o<n;){const n=e.slice(o,o+=2);t+=String.fromCharCode(parseInt(n,16))}return t})("6c6f63616c686f73743a33353937")}/${e}`, {
  method: "get",
  headers: {
    "Content-Type": "application/json",
    "Av-Vs": t
  }
}).then((e => e.json()))
// Decodes to: http://localhost:3597
```

**Description**: The extension communicates with a localhost HTTP server on port 3597 with a custom header "Av-Vs" for pseudo-authentication. This is used for video download requests to the companion application.

**Verdict**: MEDIUM RISK - The authentication mechanism relies on a simple header value that can be easily replicated by malicious local applications or websites.

**Recommendation**: Implement proper authentication tokens or mutual TLS.

---

### 3. LOW - Freemium Licensing with Remote Configuration
**Severity**: LOW
**File**: `popup.js` (line 1)
**Code**:
```javascript
const Q=async()=>{
  const e=await storageCache.get("cc");
  if(e)return e;
  const t=(e=>{/*random string generator*/})(14),
  n={days:5},
  r=await S("gc",{k:t},!1),
  o=t.split("").sort().join("");
  let a=!1;
  return"yes"===r.success&&(a=((e,t)=>{/*Vigenere cipher decrypt*/})(l(r.c),o),
  storageCache.set("cc",a,n)),
  a||(a=JSON.parse(l("7b2022667663223a2031302c202273746e6e223a2022332c362c3130222c2022656f7464223a2034352c202272616473223a20312c20226165223a2031207d"))),
  a
}
// Fallback config decodes to: {"fvc": 10, "stnn": "3,6,10", "eotd": 45, "rads": 1, "ae": 1}
```

**Description**: The extension fetches trial/licensing configuration from `atomicvideo.io/api/gcs?ck=<random>`, which returns encrypted limits (free video count: 10, trial period: 45 days). The configuration is cached for 5 days and controls download quota enforcement.

**Verdict**: LOW RISK - This is a legitimate licensing mechanism. The encryption (Vigenere cipher) is weak but only used for trial limit obfuscation, not security.

---

### 4. LOW - Telemetry and Analytics via Plausible
**Severity**: LOW
**File**: `popup.js` (line 1)
**Code**:
```javascript
const d=(e,t=!1)=>{
  if(t){
    const n=t,r=window.localStorage;
    let o=r.getItem("os");
    return o||(o=(()=>{/*OS detection*/})(),r.setItem("os",o)),
    n.os=o,
    void plausible(e,{props:n})
  }
  plausible(e)
}
```

**Description**: The extension tracks user actions (Downloads, PayForm views, TrialPage views, etc.) via Plausible analytics with OS information. No PII is collected.

**Verdict**: LOW RISK - Anonymous analytics tracking for product improvement. No sensitive data is transmitted.

---

### 5. LOW - Cookie Access for License Activation
**Severity**: LOW
**File**: `popup.js` (line 1)
**Code**:
```javascript
chrome.cookies.get({url:e,name:t},n);
var e="https://atomicvideo.io/",t="lkey"
```

**Description**: The extension reads a `lkey` cookie from `atomicvideo.io` to auto-activate licenses purchased through their website.

**Verdict**: LOW RISK - Limited to reading a single cookie from the vendor's domain for license synchronization. No cookie harvesting.

---

### 6. LOW - Script Injection into Main World Context
**Severity**: LOW
**File**: `popup.js` (line 1)
**Code**:
```javascript
chrome.scripting.executeScript({
  target:{tabId:a},
  function:te,
  world:"MAIN",
  args:[l]
})
```

**Description**: The extension injects scripts into the main world to access page-specific video players (jwplayer, Vue.js data, etc.) for video discovery.

**Verdict**: LOW RISK - Necessary for detecting embedded videos in frameworks. The injected code only extracts video URLs and does not modify page behavior.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| Localhost connections | `background.js:68`, `popup.js:1` | Required for desktop companion app integration (Atomic Video Plus) to handle stream downloads |
| Hex-encoded strings | `background.js:68`, `popup.js:1` | Obfuscation to prevent simple string scanning, not malicious intent |
| Rollbar error tracking | `rb.cf.js`, `rb.min.js` | Standard error monitoring SDK (Rollbar) for crash reporting |
| WebSocket usage | `popup.js:1` | Communication channel for real-time download progress from companion app |
| Remote config fetch | `popup.js:1` | Trial/licensing configuration to prevent abuse, not remote code execution |
| Chrome cookie access | `popup.js:1` | Limited to reading vendor domain cookie for license activation |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://atomicvideo.io/api/public-key` | Fetch RSA public key for license validation | None | LOW |
| `https://atomicvideo.io/api/rdm` | License redemption | Registration code | LOW |
| `https://atomicvideo.io/?edd_action=check_license&...` | License validation | License key, email, URL | LOW |
| `https://atomicvideo.io/api/report-site` | Report non-working sites | URL | LOW |
| `https://atomicvideo.io/api/send-feedback` | User feedback | Feedback message | LOW |
| `http://worldclockapi.com/api/json/utc/now` | Get current UTC time for trial expiration | None | LOW |
| `https://atomicvideo.io/api/gcs?ck=<key>` | Fetch trial configuration | Random cache key | LOW |
| `https://tools.codeslice.io/ytdl/u.php?k=POIQAD&u=<url>` | Twitter video extraction (3rd party) | Tweet URL | MEDIUM |
| `http://localhost:3597/*` | Companion app video download API | Video URLs, filenames | MEDIUM |
| `ws://localhost:9030` | Companion app WebSocket for stream downloads | Download progress | MEDIUM |

## Data Flow Summary

### Video Discovery Flow:
1. Content script (`in-content.js`) scans page for video elements (`<video>`, `<source>`)
2. Extracts video URLs from platform-specific sources (Vimeo config, Facebook page, Twitter API, etc.)
3. Sends video list to popup via `chrome.runtime.sendMessage`
4. Popup displays videos with download buttons

### Direct Download Flow:
1. User clicks download button → `chrome.downloads.download()` API
2. Download count incremented in `chrome.storage.sync`
3. Trial limits enforced based on cached configuration

### Stream Download Flow (requires Atomic Video Plus):
1. User clicks download for streaming format (m3u8/mpd)
2. Extension connects to `ws://localhost:9030` WebSocket
3. Sends download command to localhost HTTP API (`http://localhost:3597`)
4. Desktop app (yt-dlp wrapper) downloads and merges streams
5. Progress updates sent via WebSocket
6. Extension displays progress bar in popup

### Licensing Flow:
1. Extension checks `chrome.storage.sync` for license key
2. If not found, fetches trial configuration from `atomicvideo.io/api/gcs`
3. Validates license via `atomicvideo.io/api/rdm` endpoint
4. Stores validation result in storage cache (7 days)

## Overall Risk Assessment

**RISK LEVEL**: MEDIUM

**Justification**:
- **Intended Functionality**: The extension serves its stated purpose as a video downloader
- **Localhost Dependencies**: Requires companion desktop application for advanced features, creating local attack surface
- **Authentication Weaknesses**: Localhost services lack strong authentication
- **No Clear Malware**: No evidence of data exfiltration, cryptocurrency mining, ad injection, or user tracking beyond analytics
- **Privacy Concerns**: Minimal - only collects video URLs and anonymous usage analytics
- **Permissions**: Extensive permissions (`<all_urls>`, `cookies`, `downloads`) are justified for video downloading functionality

**Concerns**:
1. Localhost WebSocket/HTTP services could be exploited by malicious websites if ports are accessible
2. Third-party API dependency (`tools.codeslice.io`) for Twitter video extraction introduces external trust requirement
3. Weak obfuscation suggests intent to hide implementation details from casual inspection
4. Freemium model with remote configuration could theoretically be abused for feature gating changes

**Mitigations Present**:
- Content Security Policy restricts extension page script sources
- No dynamic code execution (`eval`, `new Function`)
- No remote script loading
- Downloads require user interaction (popup button click)
- Trial limits prevent abuse of service

## Recommendations

1. **For Extension Developer**:
   - Implement proper authentication for localhost WebSocket/HTTP services (e.g., rotating tokens)
   - Add origin validation to prevent cross-site WebSocket connections
   - Consider publishing companion app source code for transparency
   - Remove unnecessary obfuscation to improve auditability

2. **For Users**:
   - Only install if you need the companion desktop application features
   - Be aware that any website can potentially interact with localhost services if installed
   - Review privacy policy at https://atomicvideo.io for data collection practices

3. **For Researchers**:
   - Monitor for changes to remote configuration endpoints
   - Audit companion desktop application for security vulnerabilities
   - Check for unauthorized localhost port scanning behavior
