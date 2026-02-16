# Vulnerability Report: bilibili哔哩哔哩下载助手

## Metadata
- **Extension ID**: bfcbfobhcjbkilcbehlnlchiinokiijp
- **Extension Name**: bilibili哔哩哔哩下载助手 (Bilibili Download Helper)
- **Version**: 3.0.4
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a video download helper for Bilibili (a Chinese video platform). The extension provides legitimate functionality allowing users to download videos from bilibili.com, including copyright-restricted content. While the core functionality appears legitimate for its stated purpose, the extension exhibits several security concerns related to external dependencies and unsafe communication patterns.

The primary concerns include loading critical WASM-based FFmpeg libraries from the unpkg.com CDN without subresource integrity checks, embedding an iframe from csser.top for notices/updates, and insecure postMessage communication without origin validation. These issues create supply chain attack vectors and potential for cross-site scripting scenarios.

## Vulnerability Details

### 1. MEDIUM: Unverified Third-Party CDN Dependencies

**Severity**: MEDIUM
**Files**: bilibili-helper-content-script.js (line 1), ffmpeg.worker.js (line 1)
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension dynamically loads FFmpeg WASM libraries from unpkg.com CDN without any integrity verification.

**Evidence**:
```javascript
var u0="0.12.1",I0=`https://unpkg.com/@ffmpeg/core@${u0}/dist/umd/ffmpeg-core.js`

// In ffmpeg.worker.js
var i="0.12.1",f=`https://unpkg.com/@ffmpeg/core@${i}/dist/umd/ffmpeg-core.js`
```

The extension fetches ffmpeg-core.js, ffmpeg-core.wasm, and ffmpeg-core.worker.js from unpkg.com at runtime. These files are loaded using dynamic imports and Workers without any integrity verification (no SRI hashes, no signature validation).

**Verdict**: This creates a supply chain attack vector. If unpkg.com is compromised or serves malicious content (via DNS hijacking, CDN compromise, or malicious package update), the extension would execute arbitrary code with the same privileges as the content script. Given that the extension runs on bilibili.com pages, attackers could potentially intercept video data, user credentials, or inject malicious content.

### 2. MEDIUM: Insecure postMessage Communication with Third-Party Domain

**Severity**: MEDIUM
**Files**: bilibili-helper-content-script.js (line 188)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension embeds an iframe from csser.top and communicates with it using postMessage. While the extension validates the origin when receiving messages, the iframe could be serving malicious content that exploits the communication channel.

**Evidence**:
```javascript
J0=e=>{
  let i=e.getElementById("notice-frame");
  i.onload=()=>{
    i.contentWindow.postMessage({action:"getHeight"},"https://csser.top");
    let d=F();
    i.contentWindow.postMessage({action:"setVersion",version:{name:d.version,code:parseInt(d.version.replace(/\./g,""),10)}},"https://csser.top"),
    i.contentWindow.postMessage({action:"setTheme",theme:"null"},"https://csser.top")
  },
  window.addEventListener("message",d=>{
    if(d.origin==="https://csser.top"&&d.data&&d.data.action==="reportHeight"&&(i.style.height=d.data.height+10+"px"),
    d.origin==="https://csser.top"&&d.data&&d.data.action==="showBilibilihelperindooorsmanNoticeDialog"){
      let o=d.data.notices;
      o&&o.length>0&&o.forEach(a=>{})
    }
  }),
  i.src=`https://csser.top/bilibili/notice.html?t=${Date.now()}`
}
```

The extension sends version information to csser.top and accepts height adjustments. While origin validation exists (`d.origin==="https://csser.top"`), the pattern allows:
1. Information disclosure (extension version sent to third-party)
2. UI manipulation (csser.top can control iframe height)
3. Dependency on external domain for UI rendering

**Verdict**: If csser.top is compromised or serves malicious JavaScript, it could manipulate the extension's UI, create phishing overlays, or potentially exploit vulnerabilities in the postMessage handler logic. The empty handler for "showBilibilihelperindooorsmanNoticeDialog" suggests incomplete implementation that could be exploited.

### 3. LOW: Content Security Policy Allows 'wasm-unsafe-eval'

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)
**Description**: The extension's CSP includes 'wasm-unsafe-eval' which is necessary for WASM execution but increases attack surface.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```

Static analysis also flagged: `[HIGH] CSP extension_pages: 'unsafe-eval'`

**Verdict**: While 'wasm-unsafe-eval' is required for FFmpeg WASM functionality, it does allow WebAssembly compilation which could be exploited if an attacker can inject malicious WASM. This is a necessary tradeoff for the extension's functionality but does increase the attack surface, especially given the unverified external WASM loading.

## False Positives Analysis

### Static Analysis Exfiltration Findings
The static analyzer reported two HIGH severity exfiltration flows:
```
[HIGH] document.getElementById → fetch(unpkg.com)
[HIGH] document.getElementById → window.fetch(unpkg.com)
```

**Analysis**: These are FALSE POSITIVES for data exfiltration. The extension fetches FFmpeg libraries from unpkg.com, but it does not send user data or sensitive information to external servers. The fetch operations retrieve external resources (WASM binaries, JavaScript) but do not exfiltrate user data. The flows trace from DOM element IDs used to retrieve extension configuration, not sensitive user data.

### Message-Based Attack Surface
Static analysis reported:
```
message data → *.innerHTML(unpkg.com)
message data → window.fetch(unpkg.com)
```

**Analysis**: These represent the postMessage communication between the main extension and the FFmpeg worker, and between the extension and the csser.top iframe. While the postMessage pattern without strict validation is concerning, the current implementation appears to only handle height adjustments and notice displays, not arbitrary HTML injection.

### Legitimate FFmpeg Usage
The extension's use of FFmpeg WASM for merging audio/video streams is legitimate and expected for a download helper. Video platforms like Bilibili serve audio and video in separate streams (DASH format), requiring client-side merging for downloads.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.bilibili.com | Fetch video playback URLs | Video IDs, quality preferences, credentials (cookies) | LOW - Expected functionality |
| unpkg.com | Download FFmpeg WASM libraries | None (GET requests only) | MEDIUM - Supply chain risk |
| csser.top | Load update notices/iframe content | Extension version | MEDIUM - Third-party dependency |
| docs.qq.com | User documentation link | None | LOW - Static link only |
| chromewebstore.google.com | Extension rating link | None | LOW - Static link only |
| microsoftedge.microsoft.com | Extension rating link (Edge) | None | LOW - Static link only |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension provides legitimate video download functionality for Bilibili, and its use of FFmpeg for audio/video merging is appropriate for this use case. However, the reliance on unverified external CDN resources (unpkg.com) and the embedded iframe from csser.top create meaningful supply chain attack vectors.

The primary risks are:
1. **Supply Chain Attack via unpkg.com**: If compromised, could inject malicious code with content script privileges on bilibili.com
2. **Third-Party UI Dependency**: csser.top controls part of the extension's UI and could create phishing overlays
3. **Incomplete Origin Validation**: While basic origin checks exist, the postMessage handlers have incomplete implementations

The extension does not appear to exfiltrate user data, harvest credentials, or perform malicious actions beyond its stated purpose. The security concerns stem from architectural choices (external dependencies) rather than intentionally malicious code.

**Recommendations for Users**:
- The extension provides useful functionality but users should be aware of the supply chain risks
- Consider the 300,000 user base as evidence of relatively stable operation
- Monitor for unexpected updates that might introduce malicious behavior via compromised dependencies

**Recommendations for Developers**:
1. Bundle FFmpeg libraries locally or implement Subresource Integrity (SRI) checks
2. Remove the csser.top iframe dependency or implement strict CSP for iframe sources
3. Complete the postMessage handler implementations with proper input validation
4. Consider code-signing or checksum verification for external resources
