# Vulnerability Report: Live Stream Downloader

## Metadata
- **Extension ID**: looepbdllpjgdmkpdcdffhdbmpbcfekj
- **Extension Name**: Live Stream Downloader
- **Version**: 0.5.6
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Live Stream Downloader is a legitimate open-source tool for downloading HLS (HTTP Live Streaming) and DASH media streams. The extension is published under the Mozilla Public License 2.0 and maintained by Chandler Stimson on GitHub. The extension monitors network requests for media files (.m3u8, .mpd, video/audio MIME types) and provides a multi-threaded download interface for saving streaming content.

While the extension requests broad permissions including host access to all URLs and content script injection capabilities, these permissions are appropriate for its stated purpose of detecting and downloading media streams from web pages. The code is well-documented, follows secure coding practices, and does not exhibit any malicious behavior.

## Vulnerability Details

### 1. LOW: Overly Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests host permissions for `*://*/*`, granting it access to all web pages. While this is necessary for detecting media streams across all websites, it represents a broad attack surface if the extension were compromised.

**Evidence**:
```json
"host_permissions": [
  "*://*/*"
]
```

**Verdict**: This permission is justified for the extension's functionality (detecting media streams on any website). The extension does not abuse this access and only uses it for legitimate webRequest monitoring and content script injection for media detection.

### 2. LOW: Content Script Injection Without User Awareness
**Severity**: LOW
**Files**: worker.js (lines 131-155), blob-detector/core.js
**CWE**: CWE-749 (Exposed Dangerous Method)
**Description**: The extension injects content scripts dynamically using `chrome.scripting.executeScript` to store detected media URLs in page context and count them. Additionally, when "mime-watch" is enabled, it registers content scripts in both MAIN and ISOLATED worlds for blob URL detection.

**Evidence**:
```javascript
chrome.scripting.executeScript({
  target: { tabId: d.tabId },
  func: (size, v) => {
    self.storage = self.storage || new Map();
    self.storage.set(v.url, v);
    // ... stores media URLs in page context
  },
  args: [200, {...}]
})
```

**Verdict**: The content script injection is minimal, transparent in purpose (storing detected media URLs), and does not access sensitive page data beyond what's necessary for media detection. The MAIN world injection for blob detection is optional and user-controlled via the 'mime-watch' preference.

## False Positives Analysis

1. **Not Obfuscated**: While the static analyzer flagged the extension as "obfuscated", this appears to be due to bundled libraries (m3u8-parser, mpd-parser, mp4box) which are legitimate third-party media parsing tools. The core extension code is clean and readable.

2. **Not Data Exfiltration**: The extension fetches media manifests and segments from URLs detected on web pages, which is its core functionality. All network requests are for downloading user-requested content, not exfiltrating browsing data.

3. **Blocked Hosts Feature**: The extension includes logic to block downloads from certain hosts (e.g., YouTube) to respect terms of service. This is stored in `/network/blocked.json` and fetched from CDN, which is a legitimate anti-abuse feature.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cdn.jsdelivr.net/gh/chandler-stimson/live-stream-downloader@latest/v3/network/blocked.json | Fetch list of blocked hosts | None | Low - Read-only config |
| webextension.org/listing/hls-downloader.html | Homepage/FAQ/Uninstall URL | Version, reason (install/update) | Low - Standard telemetry |
| User-specified media URLs | Download media content | Referer headers as configured | Low - User-initiated downloads |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate, open-source media downloader that performs exactly as advertised. The code is well-documented with clear copyright notices and GitHub links. All permissions are justified for the extension's functionality:

- `storage`: Stores user preferences and detected media URLs
- `webRequest`: Monitors network traffic for media file detection
- `declarativeNetRequestWithHostAccess`: Modern MV3 approach to modifying requests
- `scripting`: Injects scripts to store detected media in page context
- `alarms`: Manages power management features
- `contextMenus`: Provides right-click download options
- `*://*/*`: Required to detect media streams on any website

The extension does not:
- Collect or exfiltrate user data
- Inject ads or modify page content beyond its stated purpose
- Communicate with suspicious third-party servers
- Use obfuscation to hide malicious behavior
- Access sensitive APIs like cookies, tabs, or browsing history

The extension is transparent about its functionality, provides user control over features (mime-watch, quality selection), and includes anti-abuse measures (blocked hosts). The broad permissions are inherent to its use case and are not abused.
