# Vulnerability Report: Dr.Web Link Checker

## Metadata
- **Extension ID**: aleggpabliehgbeagmfhnodcijcmbonb
- **Extension Name**: Dr.Web Link Checker
- **Version**: 3.9.21.7050
- **Users**: ~90,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Dr.Web Link Checker is a legitimate security extension from Doctor Web, a reputable antivirus company. The extension provides URL scanning functionality via context menu and automatic scanning of external links on social networks (VK and Facebook). It also includes ad/tracker blocking features and flash content filtering.

The extension sends user-clicked URLs to Dr.Web's servers (online.drweb.com) for malware scanning, which is the core documented functionality. While this involves data transmission to a third party, it is disclosed, expected behavior for an antivirus link checker, and the extension is from a well-established security vendor. The extension also blocks ads and web trackers using webRequest blocking, which is a disclosed secondary feature. Overall, the extension presents minimal security concerns beyond the inherent privacy trade-offs of URL scanning services.

## Vulnerability Details

### 1. LOW: URL Transmission to Third-Party Service
**Severity**: LOW
**Files**: content/js/background.js (line 380)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**:
The extension sends URLs that users click (when using the context menu scan feature) or external links on social networks to Dr.Web's online scanning service at `https://online.drweb.com/result/`. The URL being checked is transmitted as a query parameter.

**Evidence**:
```javascript
timeout(11000, fetch("https://online.drweb.com/result/?snp=".concat(request.sitename, "&url=").concat(request.url, "&r=xml"), {
  method: 'get'
})).then(function (response) {
  return response.text();
})
```

The content script also constructs URLs for scanning:
```javascript
window.open('https://online.drweb.com/result/?lng=' + currentLanguage + '&chromeplugin=1&url=' + encodeURIComponent(url), 'drweb_online_check', ...)
```

**Verdict**:
This is **disclosed and expected functionality** for an antivirus link checker. The extension's entire purpose is to scan URLs for malware, which requires sending them to Dr.Web's servers. Dr.Web is a legitimate, established antivirus company. The URLs are only sent when:
1. User explicitly requests a scan via context menu
2. User clicks an external link on VK/Facebook and has opted-in to automatic scanning

This is NOT undisclosed data exfiltration. Users choose to use this service specifically for URL scanning. The privacy policy is available and the behavior matches the extension's stated purpose.

## False Positives Analysis

### Webpack Bundled Code
The deobfuscated code shows webpack bundling artifacts, which is standard build tooling, not malicious obfuscation. Lines like:
```javascript
/******/ (function(modules) { // webpackBootstrap
/******/ 	var installedModules = {};
```

This is benign development tooling.

### jQuery Library
Both content.js and wizard.js contain bundled jQuery library code (visible from patterns like "Use getAttributeNode to fetch booleans when getAttribute lies"), which is a legitimate, widely-used JavaScript library.

### Encoded Database Patterns
The extension contains ASCII-encoded tracking/ad blocking patterns in `localDataBase.data.patterns` (background.js line 1454). These are encoded patterns for blocking analytics and ad services (Google Analytics, Yandex Metrica, social widgets, etc.). Example decoded patterns:
- "google-analytics.com/(urchin.js|ga.js)"
- ".yandex.ru/(resource|metrika)/watch"
- "vk.com/share.php"

This is part of the advertised ad/tracker blocking feature, not malicious code.

### webRequest Blocking
The extension uses `chrome.webRequest.onBeforeRequest` with blocking permissions to intercept and block ads, trackers, and flash content based on user preferences. This is disclosed functionality for the ad blocking feature.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| online.drweb.com | Malware scanning | URLs to be scanned, language preference | Low - disclosed functionality from reputable vendor |
| download.geo.drweb.com/pub/drweb/linkchecker/Bases/ | Database updates | Random cache-busting parameter | Minimal - fetches updated ad/tracker/malware databases |

## Additional Features

### Social Network Link Scanning
The extension monitors clicks on external links on VK and Facebook (when enabled by user) and scans them for malware before navigation. This is opt-in functionality that can be disabled in settings.

### Ad/Tracker/Flash Blocking
The extension blocks:
- Web analytics (Google Analytics, Yandex Metrica, etc.)
- Social widgets (Facebook Like, VK widgets, Twitter, etc.)
- Advertising networks
- Flash content

This uses webRequest blocking with configurable settings and exceptions list. The blocking database is updated from Dr.Web servers.

### Content Security Policy
The manifest includes a reasonable CSP:
```json
"content_security_policy": "script-src 'self'; img-src *; object-src 'self'"
```

This prevents loading external scripts while allowing images from any source (common for web content display).

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Dr.Web Link Checker is a legitimate security tool from an established antivirus vendor. The URL scanning functionality necessarily involves sending URLs to Dr.Web's servers, but this is:

1. **Disclosed**: The extension's name and description clearly indicate it's a link checker that scans URLs
2. **Expected**: Users install it specifically for this purpose
3. **Reputable source**: Dr.Web (Doctor Web) is a well-known antivirus company, not an unknown third party
4. **User-controlled**: URL scanning only occurs when the user explicitly requests it (context menu) or has opted-in to automatic scanning on social networks

The ad/tracker blocking features are secondary functionality that use standard webRequest blocking with a locally stored (and remotely updated) database of patterns. This is comparable to how ad blockers like uBlock Origin operate.

The only minor privacy consideration is that when users scan a URL, Dr.Web's servers learn which URL was checked. This is an inherent trade-off of cloud-based URL scanning services. For users who trust Dr.Web's antivirus products, this is an acceptable privacy trade-off for the security benefit.

No evidence of credential theft, hidden data exfiltration, malicious code execution, or other serious security issues was found.
