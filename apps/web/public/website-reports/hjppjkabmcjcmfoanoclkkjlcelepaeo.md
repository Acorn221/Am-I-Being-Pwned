# Vulnerability Report: OK.ru Downloader (IDL Helper)

## Metadata
- **Extension ID**: hjppjkabmcjcmfoanoclkkjlcelepaeo
- **Extension Name**: OK.ru Downloader (IDL Helper)
- **Version**: 0.7.67.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

OK.ru Downloader (IDL Helper) is a video downloader extension for OK.ru and Instagram platforms that uses FFmpeg WASM for media conversion. The extension implements opt-in analytics tracking that collects browsing activity data (URLs where the extension is active, installation IDs) and technical telemetry, sending this information to third-party API endpoints at `api.videodlservice.com`. While the extension requests user consent during onboarding via a welcome page, it employs potentially privacy-invasive monitoring techniques including XHR/fetch hooking and has multiple postMessage handlers without origin validation. The extension bundles a 24MB FFmpeg WASM binary that executes in the content script context on all websites.

The extension's stated purpose is legitimate (downloading videos from OK.ru and Instagram), and the analytics collection is disclosed and opt-in. However, the technical implementation includes several security concerns including unsafe message handlers, fetch/XHR interception capabilities, and execution of WASM in content scripts.

## Vulnerability Details

### 1. HIGH: Browsing Activity Data Collection with Opt-In Analytics

**Severity**: HIGH
**Files**: background_script.js, welcome.html, welcome.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects browsing activity data (URLs of online video players where the extension is active, installation IDs) and sends telemetry to `https://api.videodlservice.com/stat/` and `https://api.videodlservice.com/logs`.

**Evidence**:
```javascript
// background_script.js:160-161
analyticsUrl: "https://api.videodlservice.com/stat/",
logsUrl: "https://api.videodlservice.com/logs",
```

```html
<!-- welcome.html:52-56 -->
<p>We are <a href="https://extensionworkshop.com/documentation/publish/add-on-policies/#data-disclosure-collection-and-management" target="blank">required</a> to get your permission to collect analytics. The following information is needed to maintain and develop OK.ru Downloader:</p>
<ul>
  <li>browsing activity data (URLs of online video players where OK.ru Downloader is active, installation IDs - large random numbers)</li>
  <li>technical data (event type, browser family and version, extension version)</li>
</ul>
```

**Verdict**: This is disclosed analytics with opt-in consent. The welcome page clearly explains what data is collected (browsing activity URLs, installation IDs, technical data) and provides three options: "Do not share anything", "Share technical data only", or "Share technical and browsing activity data". While the data collection is potentially privacy-invasive, it appears to be disclosed and consensual. This is rated HIGH due to the breadth of data collected (all URLs where extension is active on `<all_urls>`), but is mitigated by the opt-in mechanism.

### 2. MEDIUM: postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: content_script.js (lines 34809, 34902, 37103)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The extension registers multiple `window.addEventListener("message")` handlers without origin validation, creating potential attack surface for malicious websites to send crafted messages.

**Evidence**:
```javascript
// content_script.js:34809
window.addEventListener("message", onMessage, false);

// content_script.js:34902
window.addEventListener("message", onMessage, false);

// content_script.js:37103-37117
window.addEventListener("message", (event) => {
  if (event?.data?.receiver !== default_service_sign) return;
  const {
    file, // ArrayBuffer
    fileName,
    url, // direct url
  } = event.data;
  if (fileName) {
    if (file) { // save by ObjectURL to Blob(ArrayBuffer)
      save_file(file, fileName);
    } else if (url) { // save by direct url
      save_file(url, fileName);
    }
  }
});
```

**Verdict**: While there is some filtering based on `receiver` field matching (`default_service_sign = "idl-downloader-ok-chrome:0.7.67.0"`), the handlers do not validate `event.origin`. The third handler at line 37103 accepts file download commands from any origin that knows the receiver signature. This creates a moderate risk where a malicious website could trigger file downloads if it can guess or obtain the signature string. However, the risk is partially mitigated by the signature check.

### 3. MEDIUM: XHR and Fetch Hooking/Interception

**Severity**: MEDIUM
**Files**: inject-scripts/patch-xhr.js, inject-scripts/patch-fetch.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension injects scripts that monkey-patch `window.fetch` and `XMLHttpRequest.prototype.open` to intercept network requests and responses from web pages.

**Evidence**:
```javascript
// patch-xhr.js:38-52
const { open } = xhr;
xhr.open = function () {
  const openArguments = arguments;
  const { setRequestHeader, send } = this;

  this.setRequestHeader = function (...args) {
    if (args[0].toLowerCase() === "x-ig-app-id") {
      window["X-IG-App-ID"] = args[1];
    }
    setRequestHeader.apply(this, args);
  };
  // ... intercepts onload to capture responses
}

// patch-fetch.js:5-24
window.fetch = (...rest) => {
  const request = x.apply(this, rest);
  try {
    const { pattern } = JSON.parse(container.getAttribute("data-params"));
    const re = new RegExp(pattern);
    if (re.test(rest[0].url)) {
      window.lastResponse = {
        request,
      };
      // ... stores response clone
    }
  }
  return request;
};
```

**Verdict**: The extension hooks XHR and fetch to extract data from Instagram API responses (collecting JSON responses and extracting `X-IG-App-ID` headers). This is consistent with the extension's stated purpose of downloading Instagram content, as it needs to extract media URLs from API responses. The hooking appears targeted (Instagram-specific patterns) rather than broad data harvesting. However, this creates attack surface and could potentially expose sensitive data from third-party APIs to the extension's context.

### 4. MEDIUM: WASM Execution in Content Script Context

**Severity**: MEDIUM
**Files**: ffmpeg-core.wasm (24MB), content_script.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension loads a 24MB FFmpeg WASM binary (`ffmpeg-core.wasm`) and executes it within the content script context on all websites via CSP `'wasm-unsafe-eval'`.

**Evidence**:
```json
// manifest.json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
},
"web_accessible_resources": [
  {
    "resources": [
      "/inject-scripts/*",
      "/ffmpeg-core.wasm"
    ],
    "matches": [
      "<all_urls>"
    ]
  }
]
```

```json
// wasm_analysis.json
{
  "wasm_files": [{
    "path": "ffmpeg-core.wasm",
    "size_bytes": 24355249,
    "known_library": "opus",
    "execution_context": "content_script",
    "risk": "high",
    "risk_reason": "WASM in content script"
  }]
}
```

**Verdict**: Loading and executing large WASM binaries in content scripts increases attack surface and resource consumption. FFmpeg is a legitimate media processing library required for the extension's video conversion functionality. However, running it in content script context on `<all_urls>` means it loads on every webpage visited, creating potential performance impact and security risks. The WASM binary is identified as FFmpeg with opus codec support, which is appropriate for a media downloader. This is rated MEDIUM due to the legitimate use case but concerning execution context.

### 5. LOW: Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `http://*/*` and `https://*/*` host permissions, granting access to all websites.

**Evidence**:
```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Verdict**: While broad, this is appropriate for a video downloader that needs to detect and download media from various video platforms. The extension's description mentions OK.ru and Instagram, but users may expect it to work on other video platforms as well. The content script is injected on `<all_urls>` with `run_at: "document_start"`, which is necessary to intercept network requests before page scripts execute.

## False Positives Analysis

1. **Webpack Bundling**: The extension uses standard webpack bundling (visible in the deobfuscated code with `/******/` webpack comments and module system). This is not obfuscation, just normal build tooling.

2. **FFmpeg WASM**: The large WASM binary is FFmpeg, a well-known open-source media processing library. The extension's purpose (video downloading and conversion) legitimately requires media processing capabilities.

3. **XHR/Fetch Hooking**: While potentially concerning, the hooking is targeted at extracting media URLs from Instagram's API responses, which is necessary for the extension's download functionality. The patterns being monitored are specific to Instagram/social media platforms.

4. **Content Script on All URLs**: Required for the extension to detect video players across different websites and enable download functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.videodlservice.com/stat/ | Analytics telemetry | Browsing activity URLs, installation ID, technical data | Medium - Opt-in but collects extensive browsing data |
| api.videodlservice.com/logs | Error/diagnostic logging | Error logs, extension state | Low - Standard telemetry |
| api.videodlservice.com/country | Geolocation detection | IP address (implicit) | Low - Standard geo-detection |
| api.videodlservice.com/banned-videos-urls | Blacklist of prohibited content | None sent | None - Receives data only |
| api.videodlservice.com/api/storage/findOrCreate | Unknown storage API | Unknown | Medium - Purpose unclear |
| instaloader.net/* | Extension's web portal | Various (user interactions, UTM params) | Low - First-party service |
| r.clckgo.online/r/* | URL shortener/redirect | Click tracking data | Medium - Third-party tracking |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension implements legitimate video downloading functionality with appropriate technical mechanisms (FFmpeg WASM, fetch/XHR interception for media URL extraction). The primary privacy concern is the opt-in analytics system that collects browsing activity data (URLs where the extension is active) and sends it to third-party servers at `api.videodlservice.com`.

**Positive factors**:
- Analytics collection is disclosed in the welcome page with clear consent mechanism
- Users can opt-out or choose technical-only telemetry
- Core functionality (video downloading) is legitimate and properly implemented
- No evidence of credential theft, hidden exfiltration, or malicious behavior

**Negative factors**:
- Collects potentially extensive browsing data (all URLs where extension is active on any website)
- postMessage handlers lack origin validation, creating attack surface
- XHR/fetch hooking could potentially expose third-party API data
- WASM execution in content script context increases attack surface
- Third-party analytics endpoint receives browsing activity data

The extension is rated MEDIUM rather than HIGH because the data collection is disclosed and opt-in, and the core functionality appears legitimate. However, users who enable analytics should be aware that their browsing activity on video platforms will be shared with `api.videodlservice.com`.
