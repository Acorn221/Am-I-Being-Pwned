# Vulnerability Report: VK Music Saver

## Metadata
- **Extension ID**: ijgkbcbalaekboipcmaefchfjpognmog
- **Extension Name**: VK Next (VK Music Saver)
- **Version**: 2.10.1
- **Users**: Unknown (not provided)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

VK Music Saver (branded as "VK Next") is a legitimate browser extension that enables users to download music from VK.com and VK.ru social media platforms. The extension adds download functionality to VK's music player interface and integrates with the Genius.com API for lyrics retrieval. The codebase is webpack-bundled (not obfuscated) and uses the File System Access API for local file downloads.

The static analyzer flagged several postMessage handlers without origin validation. Upon manual review, these are internal message passing components using a custom Bridge implementation for extension-internal communication. While the handlers lack explicit origin checks in the addEventListener call, the Bridge implementation uses a message ID system for request-response pairing and appears to communicate only within the extension context (between content scripts and injected scripts on VK.com domains).

The "exfiltration" flows flagged by the analyzer are false positives - they represent hardcoded references to the Chrome Web Store review page URL for this extension, not actual data exfiltration.

## Vulnerability Details

### 1. LOW: PostMessage Handlers Without Origin Validation

**Severity**: LOW
**Files**: js/2692.vms.js, js/8669.vms.js
**CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)

**Description**:
Multiple postMessage event listeners are registered without explicit origin validation in the addEventListener callback. The analyzer identified 4 instances across the codebase:
- 2692.vms.js:160 - Bridge implementation message handler
- 8669.vms.js:816 - StreamSaver service worker state handler
- 8669.vms.js:893 - iframe loader message handler
- 8669.vms.js:936 - StreamSaver writer message handler

**Evidence**:
```javascript
// js/2692.vms.js - Bridge implementation
window.addEventListener("message", r), this._event.on("$destroy", () => {
  window.removeEventListener("message", r)
})

// Internal processing with message filtering
_processMessage(e) {
  // Bridge uses prefix-based message name filtering and _msgId system
}
```

**Verdict**:
While technically a security weakness, the practical risk is LOW because:
1. The Bridge implementation uses a prefix-based message naming system (`${this.prefix}${name}`)
2. Messages require matching message IDs for response correlation
3. The extension only injects on VK.com/VK.ru domains (content_scripts matches)
4. The StreamSaver handlers check for specific message types ("VKNext/StreamSaver::sw-ready", "VKNext/StreamSaver::sw-error")
5. No sensitive data is processed through these handlers - they're used for internal coordination

This is a minor defensive programming issue rather than an exploitable vulnerability. An attacker would need to be on the same page (VK.com) and know the internal message structure.

## False Positives Analysis

### Chrome Web Store URL References (Flagged as "Exfiltration")

The static analyzer flagged 4 HIGH-severity "exfiltration" flows involving `chromewebstore.google.com`. These are false positives. The actual code contains hardcoded string constants defining the extension's own review page URL:

```javascript
// js/vkcom_injected.vms.js:1268
const r = "https://chromewebstore.google.com/detail/ijgkbcbalaekboipcmaefchfjpognmog/reviews",
  i = "https://addons.mozilla.org/ru/firefox/addon/vk-music-saver/reviews",
  c = "https://vknext.net",
  l = "vknext",
  d = "https://vknext.net/donate";
```

These are UI constants for linking to the extension's public review pages and donation page. There are no actual fetch() calls to chromewebstore.google.com with user data - the analyzer incorrectly associated document.getElementById/querySelectorAll calls with these constant URLs.

### Webpack Bundling Flagged as "Obfuscation"

The extension is built with webpack and uses standard webpack runtime code. This is not obfuscation - it's normal module bundling. The deobfuscated code shows clear variable names, readable logic, and standard webpack chunk loading patterns.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.genius.com | Lyrics search and retrieval | Search query: artist name + song title | LOW - Public API, non-sensitive music metadata |
| vknext.net | Extension configuration/updates | None identified in code review | LOW - Developer's own domain |
| chromewebstore.google.com | No actual requests | N/A (URL constant only) | NONE - False positive |
| vk.com/vk.ru audio URLs | Music file downloads | None (downloads only) | NONE - Core functionality |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate music downloader extension with a clear, stated purpose. The postMessage handlers have minor security weaknesses but pose minimal practical risk due to:
- Scoped injection (only on VK.com domains)
- Internal message structure requirements
- No handling of sensitive user data
- No actual exfiltration or malicious behavior

The extension properly uses:
- Manifest V3 architecture
- declarativeNetRequest for request modification (transparent in rules file)
- File System Access API for local downloads
- Host permissions limited to VK.com and Genius.com

Recommended improvements:
1. Add explicit origin validation to postMessage handlers (check event.origin)
2. Consider using chrome.runtime.connect() for extension-internal messaging instead of window.postMessage

No evidence of malicious intent, data theft, or security exploits beyond the minor postMessage validation weakness.
