# Vulnerability Report: Video Downloader Pro

## Metadata
- **Extension ID**: penndbmahnpapepljikkjmakcobdahne
- **Extension Name**: Video Downloader Pro
- **Version**: 1.1.11
- **User Count**: ~100,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

Video Downloader Pro is a Vimeo video downloading extension with legitimate functionality but contains **concerning privacy and security practices**. The extension intercepts video traffic, communicates with a third-party API server (vimego.io), and modifies security headers across multiple social media platforms. While the core functionality appears legitimate (video downloading with FFmpeg), the extension's behavior raises significant privacy concerns around data exfiltration and weakened security controls.

**Risk Level: MEDIUM-HIGH**

## Vulnerability Details

### 1. Third-Party API Data Exfiltration [HIGH]

**Severity**: HIGH
**Files**: `js/merge.js` (lines 196-202)
**Code**:
```javascript
let response = await fetch("https://vimego.io/ffmpeg/vimeo-config/", {
    method: "POST",
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(msg.config_body)
});
```

**Verdict**: CONFIRMED VULNERABILITY
The extension sends video configuration data to vimego.io, including video URLs, titles, and CDN information. This constitutes data exfiltration to a third-party server not controlled by the user or Vimeo. The server returns video/audio URLs for download.

**Privacy Impact**:
- User viewing habits tracked by third-party (vimego.io)
- Video access patterns monitored
- Potential for surveillance of private/restricted video access
- No visible privacy policy explaining this data sharing

---

### 2. XMLHttpRequest Hooking [MEDIUM-HIGH]

**Severity**: MEDIUM-HIGH
**Files**: `js/ajax-listener.js` (lines 5-72)
**Code**:
```javascript
if (typeof XMLHttpRequest.prototype._origOpen === "undefined") {
  XMLHttpRequest.prototype._origOpen = XMLHttpRequest.prototype.open;
}
XMLHttpRequest.prototype.open = function () {
  this.addEventListener("load", function (e) {
    try {
      let responseText = JSON.parse(this.responseText);
      if (responseText.request && responseText.request.files &&
          responseText.cdn_url && responseText.cdn_url.indexOf("vimeo") != -1) {
        // Intercepts Vimeo API responses
        document.body.insertAdjacentHTML(
          "beforeend",
          `<div class="vtConfigUrl" url=${e.currentTarget.responseURL}></div>`
        );
      }
    } catch (e) {}
  });
  XMLHttpRequest.prototype._origOpen.apply(this, arguments);
};
```

**Verdict**: CONFIRMED VULNERABILITY
The extension globally hooks XMLHttpRequest on all Vimeo pages to intercept API responses containing video configuration data. This is injected into the page context via `content-inject.js`, allowing it to bypass normal content script restrictions.

**Security Impact**:
- Intercepts all AJAX traffic on Vimeo domains
- Operates in page context (outside normal CSP restrictions)
- Could be exploited by malicious websites to access intercepted data
- Violates principle of least privilege

---

### 3. Security Header Stripping [CRITICAL]

**Severity**: CRITICAL
**Files**: `rule.json` (lines 1-28)
**Code**:
```json
{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      { "header": "x-frame-options", "operation": "remove" },
      { "header": "content-security-policy", "operation": "remove" }
    ]
  },
  "condition": { "urlFilter": "||m.facebook.com", "resourceTypes": ["main_frame", ...] }
},
{
  "id": 2,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      { "header": "x-frame-options", "operation": "remove" },
      { "header": "content-security-policy", "operation": "remove" },
      { "header": "cross-origin-opener-policy", "operation": "remove" },
      { "header": "cross-origin-embedder-policy", "operation": "remove" }
    ]
  },
  "condition": { "urlFilter": "||mobile.twitter.com", "resourceTypes": ["main_frame", ...] }
}
```

**Verdict**: CONFIRMED VULNERABILITY
The extension strips critical security headers (CSP, X-Frame-Options, COOP, COEP) from Facebook and Twitter mobile sites. This is unrelated to the stated video downloading functionality.

**Security Impact**:
- **Clickjacking attacks enabled** (removal of X-Frame-Options)
- **XSS attacks enabled** (removal of CSP)
- **Cross-origin attacks enabled** (removal of COOP/COEP)
- Exposes users to attacks on major social media platforms
- No legitimate reason for a video downloader to modify these headers

---

### 4. Excessive Permissions [MEDIUM]

**Severity**: MEDIUM
**Files**: `manifest.json` (lines 86-96)
**Code**:
```json
"permissions": [
  "tabs",
  "storage",
  "downloads",
  "*://*.aliyuncs.com/*",
  "declarativeNetRequest",
  "alarms"
],
"host_permissions": [
  "<all_urls>"
]
```

**Verdict**: EXCESSIVE PERMISSIONS
The extension requests `<all_urls>` host permissions and includes specific permission for Alibaba Cloud CDN (aliyuncs.com), which is not explained or apparently used.

**Security Impact**:
- Can access all websites, not just video platforms
- Can modify headers on any domain (via declarativeNetRequest)
- Alibaba Cloud permission suggests Chinese infrastructure involvement
- Violates principle of least privilege

---

### 5. Content Script Injection on All URLs [MEDIUM]

**Severity**: MEDIUM
**Files**: `manifest.json` (lines 10-23)
**Code**:
```json
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": ["js/content-script-vimeo.js"],
    "css": ["css/insert-vimeo.css"],
    "all_frames": true,
    "run_at": "document_end"
  }
]
```

**Verdict**: OVERLY BROAD INJECTION
Content script runs on every website, including sensitive domains (banking, email, etc.), despite only needing to operate on Vimeo.

**Security Impact**:
- 451KB content script injected into all pages (performance impact)
- Access to DOM of all websites user visits
- Increased attack surface
- Potential for data leakage from non-video sites

---

### 6. WASM Binary (FFmpeg) [LOW-MEDIUM]

**Severity**: LOW-MEDIUM
**Files**: `js/lib/ffmpeg-core.wasm` (24MB)
**Code**: Binary WASM file (SHA256: 68b094c2dd90d813d5c0894c991499e297479e6c2dcd7e9b4940b5a22eb62701)

**Verdict**: LEGITIMATE USE (with caveats)
WASM analysis identified this as FFmpeg (opus library variant), which is legitimately used for video merging. However, the large binary size and WASM execution capabilities pose theoretical risks.

**Security Impact**:
- 24MB binary blob difficult to audit
- WASM can execute arbitrary code
- FFmpeg has had security vulnerabilities in the past
- Appears legitimate based on string analysis

---

## False Positives

| Pattern | Context | Reason for FP |
|---------|---------|---------------|
| `Proxy` objects | `chunk-common.js`, jQuery | MobX/Vue reactivity, not residential proxy |
| `eval` (2 instances) | `background.js` | Part of core-js polyfills, not dynamic code execution |
| ExtensionPay SDK | `background.js` | Legitimate payment processing library (extensionpay.com) |
| jQuery hooks | Multiple files | Standard jQuery AJAX/event handling, not malicious hooking |

---

## API Endpoints & External Communications

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://vimego.io/ffmpeg/vimeo-config/` | Video config processing | Vimeo video URLs, titles, CDN info | HIGH |
| `https://extensionpay.com` | Payment processing | User payment status | LOW |
| `*.aliyuncs.com/*` | Unknown (permission declared but not used) | N/A | MEDIUM |
| `https://player.vimeo.com/video/*/config` | Vimeo API (intercepted) | None (read-only) | LOW |

---

## Data Flow Summary

1. **User visits Vimeo** → Content script injected on all pages
2. **User plays video** → ajax-listener.js hooks XMLHttpRequest in page context
3. **Vimeo API responds** → Intercepted response extracts video CDN URLs
4. **User clicks download** → Video config sent to vimego.io API
5. **vimego.io returns URLs** → FFmpeg WASM downloads and merges video segments
6. **Download triggered** → File saved to user's system

**Privacy Concern**: Step 4 sends user's viewing activity to third-party server not disclosed in Chrome Web Store listing.

---

## Additional Concerns

### Undocumented Chinese Comments
Chinese language comments found in `ajax-listener.js`:
```javascript
//2025年3月5日处理
//单独处理带review路径无法注入configUrl的问题
```
Translation: "Processing on March 5, 2025 / Separately handle the problem of being unable to inject configUrl with review path"

This suggests Chinese-language development team, which combined with Alibaba Cloud permissions raises questions about data jurisdiction.

### Security Header Stripping Rationale
The extension strips security headers from Facebook/Twitter mobile sites with no explanation. Possible (but unconfirmed) reasons:
- Allowing video embedding/downloading from social media
- Malicious intent to enable attacks
- Leftover code from different functionality

No legitimate video downloader needs to weaken security on social media platforms.

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM-HIGH**

### Risk Factors:
- ✅ Data exfiltration to third-party server (vimego.io)
- ✅ Security header stripping on major social platforms
- ✅ XMLHttpRequest hooking in page context
- ✅ Excessive permissions (<all_urls>)
- ✅ Chinese infrastructure involvement (Alibaba Cloud)
- ✅ No privacy policy explaining data sharing

### Mitigating Factors:
- ✅ Core functionality (FFmpeg video merging) appears legitimate
- ✅ Uses established payment processor (ExtensionPay)
- ✅ No evidence of keylogging, cookie harvesting, or credential theft
- ✅ No obvious malware/botnet infrastructure

### Verdict:
**The extension provides legitimate video downloading functionality but employs invasive techniques and shares user data with third parties without adequate disclosure. The security header stripping is particularly concerning as it actively weakens user security on unrelated websites.**

### Recommendation:
**TRIAGE REQUIRED** - Extension should be flagged for:
1. Privacy policy review (disclosure of vimego.io data sharing)
2. Justification for security header modification on social media
3. Explanation of Alibaba Cloud (aliyuncs.com) permission
4. Scope reduction of content script injection

The extension walks the line between aggressive but legitimate functionality and privacy-invasive practices. Users should be informed of the data sharing with vimego.io before installation.
