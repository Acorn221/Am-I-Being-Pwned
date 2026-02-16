# Vulnerability Report: TwoSeven Extension

## Metadata
- **Extension ID**: cjdnfmjmdligcpfcekfmenlhiopehjkd
- **Extension Name**: TwoSeven Extension
- **Version**: 3.0.21
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

TwoSeven Extension is a legitimate watch-party application that enables synchronized video watching across multiple streaming platforms (Netflix, Hulu, Disney+, YouTube, Amazon Prime, etc.). The extension operates by injecting content scripts into streaming sites and coordinating playback through its service at twoseven.xyz.

While the extension's core functionality is legitimate, it exhibits security concerns primarily related to broad permissions and unsafe messaging patterns. The extension requests host permissions for all URLs (`*://*/*`) and injects content scripts on all pages, which creates an unnecessarily large attack surface. Additionally, it implements 39 instances of `window.addEventListener("message")` handlers without origin validation, making it vulnerable to cross-origin message injection attacks.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: dist/contentScripts/webext-bridge.js, dist/background/index.mjs, and 35+ other content script files
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**:
The extension implements webext-bridge for cross-context messaging, which adds 39 separate `window.addEventListener("message")` handlers across various content scripts and the background service worker. None of these handlers validate the origin of incoming messages before processing them.

**Evidence**:
From ext-analyzer output:
```
[HIGH] window.addEventListener("message") without origin check    dist/contentScripts/webext-bridge.js:29
[HIGH] window.addEventListener("message") without origin check    dist/contentScripts/index.js:394
[HIGH] window.addEventListener("message") without origin check    dist/background/index.mjs:6891
```

From webext-bridge.js:
```javascript
window.addEventListener("message", acceptMessagingPort);
```

The static analyzer also identified flows where message data reaches network sinks:
```
message data → fetch(${Mu})    from: dist/contentScripts/webext-bridge.js, dist/background/index.mjs
message data → *.src(placeholder)    from: dist/contentScripts/webext-bridge.js, dist/background/index.mjs
```

**Verdict**:
This is a standard risk with the webext-bridge library when used globally. While the extension appears to use internal message routing that may provide some validation at a higher level, the lack of origin checks at the event listener level creates potential for malicious pages to send crafted messages to the extension. Given the extension's broad host permissions, any compromised page could attempt message injection. However, there is no evidence of actual data exfiltration or malicious use of this pattern.

### 2. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests `*://*/*` host permissions and injects content scripts on all HTTP/HTTPS pages, despite only needing access to specific streaming platforms and its own service domain.

**Evidence**:
From manifest.json:
```json
"host_permissions": ["*://*/*"],
"content_scripts": [
  {
    "all_frames": true,
    "run_at": "document_start",
    "matches": ["http://*/*", "https://*/*"],
    "js": ["dist/contentScripts/webext-bridge.js", "dist/contentScripts/early-index.js"]
  }
]
```

The extension actually only needs access to:
- twoseven.xyz (its own service)
- Netflix, Amazon Prime, Hulu, Disney+, YouTube, Crunchyroll, Vimeo, etc. (specific streaming platforms)

**Verdict**:
This is a legitimate functionality concern but not an active security threat. The extension injects bridge scripts on all pages but appears to have logic to limit active intervention to supported streaming platforms (based on the `blockedPages` list in early-page.js). The broad permissions increase attack surface but do not indicate malicious intent.

## False Positives Analysis

1. **Obfuscation Flag**: The static analyzer flagged the code as "obfuscated." However, this is standard webpack/minified production code, not intentionally obfuscated malware. Variable names like `__defProp`, `__privateGet`, etc. are standard TypeScript/webpack helper functions.

2. **Network Flows**: The analyzer detected message data flowing to `fetch()` calls. This is expected behavior for a watch-party extension that needs to coordinate state with remote servers and other participants.

3. **Dynamic Code Injection**: The background script uses `chrome.scripting.executeScript()` to inject functions into page contexts (lines 8762-8771). This is a legitimate use of the Chrome API for the extension's stated purpose of coordinating video playback.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| twoseven.xyz | Primary service domain | Watch party coordination, user authentication | Low - legitimate service |
| vimeo.com | Video platform | Video metadata, playback state | Low - feature requirement |
| youtube.com | Video platform | Video metadata, playback state | Low - feature requirement |
| netflix.com | Video platform | Video metadata, playback state | Low - feature requirement |
| amazon.com/primevideo.com | Video platform | Video metadata, playback state | Low - feature requirement |
| hulu.com | Video platform | Video metadata, playback state | Low - feature requirement |
| disneyplus.com | Video platform | Video metadata, playback state | Low - feature requirement |
| max.com | Video platform | Video metadata, playback state | Low - feature requirement |
| crunchyroll.com | Video platform | Video metadata, playback state | Low - feature requirement |
| funimation.com | Video platform | Video metadata, playback state | Low - feature requirement |
| paramountplus.com | Video platform | Video metadata, playback state | Low - feature requirement |
| jiocinema.com | Video platform | Video metadata, playback state | Low - feature requirement |
| viki.com | Video platform | Video metadata, playback state | Low - feature requirement |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
TwoSeven Extension is a legitimate watch-party application with a genuine use case. The extension does not exhibit malicious behavior such as credential theft, hidden data exfiltration, or undisclosed tracking.

The MEDIUM risk rating is based on:
1. **Unsafe messaging patterns**: 39 postMessage listeners without origin validation create exploitable attack surface
2. **Excessive permissions**: Requesting all_urls and injecting on all pages when only specific streaming sites are needed
3. **Large attack surface**: Global content script injection increases the potential impact of any vulnerability

However, the extension does not cross into HIGH risk because:
- No evidence of data exfiltration beyond its stated functionality
- No credential harvesting or session hijacking detected
- No undisclosed tracking or analytics
- Legitimate business purpose with transparent functionality
- Uses standard libraries (webext-bridge) in expected ways

**Recommendations**:
1. Implement origin validation on all postMessage event listeners
2. Reduce host_permissions to only required domains
3. Limit content script injection to necessary pages rather than all_urls
4. Consider using chrome.runtime.sendMessage instead of window.postMessage where possible
