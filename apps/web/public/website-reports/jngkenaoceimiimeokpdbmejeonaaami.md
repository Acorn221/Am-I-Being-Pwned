# Vulnerability Report: PlayTo for Chromecast™

## Metadata
- **Extension ID**: jngkenaoceimiimeokpdbmejeonaaami
- **Extension Name**: PlayTo for Chromecast™
- **Version**: 1.6.0
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

PlayTo for Chromecast™ is a browser extension designed to send internet videos to Chromecast devices. The extension monitors web requests for video files (.mp4, .webm, .m3u8) and prompts users to cast them via an external service at playtochromecast.com. The extension includes an extensive ad-blocking list to filter out advertising video content from being cast.

While the extension's core functionality is legitimate, it uses broad permissions (<all_urls>, webRequest, webRequestBlocking) to intercept all web requests and redirect users to an external website. The extension also includes Google Analytics tracking. Overall risk is assessed as LOW since the functionality is transparent, user-initiated, and aligns with the extension's stated purpose.

## Vulnerability Details

### 1. LOW: Privacy Tracking via Google Analytics

**Severity**: LOW
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension uses Google Analytics (UA-50659011-4) to track various user events including installation, updates, status changes, and user interactions with video casting prompts.

**Evidence**:
```javascript
ga("create", "UA-50659011-4", "auto");
ga("send", "pageview", "/background.html");
ga("send", "event", "install", "version", ptcc.manifest.version);
ga("send", "event", "webalert", "accept");
ga("send", "event", "adblock", "test");
```

**Verdict**: This is standard analytics tracking for a free extension. Events tracked are relatively benign (installation, feature usage, language settings) and do not include personally identifiable information or browsing history. The analytics domain is properly declared in the CSP.

### 2. LOW: Dynamic URL Redirection

**Severity**: LOW
**Files**: background.js
**CWE**: CWE-601 (URL Redirection to Untrusted Site)
**Description**: When users confirm they want to cast a video, the extension dynamically constructs a URL and redirects the current tab to playtochromecast.com with the video URL as a parameter.

**Evidence**:
```javascript
ptcc.takeAction = function(result) {
  var ccUrl;
  if (result[0] === true) {
    ccUrl = ptcc.url + "play.php?q=" + encodeURIComponent(this.url) +
            "&t=" + encodeURIComponent(this.type) + "&l=" + ptcc.language;
    chrome.tabs.executeScript(this.tabId, {
      code: "window.location='" + ccUrl + "'"
    });
  }
};
```

**Verdict**: While this technique redirects the user's current tab to an external site, it only occurs after explicit user confirmation via a browser confirm() dialog. The video URL is properly encoded, and the base domain is hardcoded to playtochromecast.com. This is the expected behavior for a casting service.

## False Positives Analysis

**Minified/Obfuscated Code**: The ext-analyzer flagged this extension as "obfuscated", but the code is simply minified JavaScript, not intentionally obfuscated. The deobfuscated version reveals straightforward, readable code with clear variable names and logic.

**Broad Permissions**: The extension requires <all_urls>, webRequest, and webRequestBlocking to intercept video file requests across all websites. While these are powerful permissions, they are necessary for the extension's core functionality of detecting video files on any webpage.

**External Communication**: The extension communicates with playtochromecast.com, but this is the service's own casting infrastructure, not third-party data exfiltration. Users are explicitly redirected to this domain with their consent.

**Ad Blocking List**: The extensive adBlockList.js file contains regex patterns for blocking advertising video URLs. This is a legitimate feature to prevent casting unwanted ads, not malicious functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage analytics | Extension version, language, feature usage events | LOW - Standard analytics |
| www.playtochromecast.com | Video casting service | Video URL, video type, user language | LOW - Core functionality, user-initiated |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

PlayTo for Chromecast™ performs exactly as advertised - it detects video files and offers to cast them via an external service. The extension's behavior is transparent and requires explicit user confirmation before any action is taken.

**Positive Security Aspects**:
1. User consent required - All casting actions require user confirmation via browser dialog
2. URL encoding - Properly encodes video URLs before transmission
3. Ad blocking - Includes extensive list to filter advertising videos
4. Hardcoded domains - Does not accept dynamic/remote configuration for redirect URLs
5. No credential harvesting or sensitive data collection

**Minor Concerns**:
1. Google Analytics tracking (disclosed in privacy practices)
2. Broad permissions required for functionality
3. Redirects to external domain (but with user consent)

The extension does not exhibit malicious behavior, data exfiltration beyond disclosed analytics, or hidden functionality. It is a legitimate utility extension with appropriate privacy disclosures for its functionality.
