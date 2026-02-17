# Vulnerability Report: Video Downloader professional

## Metadata
- **Extension ID**: knkpjhkhlfebmefnommmehegjgglnkdm
- **Extension Name**: Video Downloader professional
- **Version**: 1.0.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Video Downloader professional is a browser extension that enables users to download videos from multiple social media platforms including Facebook, Twitter, Instagram, VK, Vimeo, and Dailymotion. The extension operates by detecting video elements on supported websites and providing download buttons with quality selection options.

The extension has broad permissions (`<all_urls>`, `webRequest`, `tabs`, `downloads`, `storage`) which are consistent with its stated functionality. Analysis reveals legitimate video downloading capabilities with no evidence of malicious data exfiltration, credential theft, or undisclosed tracking. The extension uses platform-specific APIs (Facebook DTSG tokens, Twitter OAuth, Instagram GraphQL) to retrieve video URLs, which is standard practice for video downloaders. One minor concern is the use of third-party domains for configuration/credentials, though no sensitive data appears to be sent to these endpoints.

## Vulnerability Details

### 1. LOW: Third-Party Configuration Endpoint Access

**Severity**: LOW
**Files**: js/lib/_config.js, js/serviceWorker.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension references a Google Sites page (`https://sites.google.com/view/video-loader/home`) for Twitter credential token retrieval and as a "more detail" link in the popup. This introduces a potential supply chain risk if the third-party site is compromised.

**Evidence**:
```javascript
// _config.js
TW_CREDENTIAL_TOKEN_URL="https://sites.google.com/view/video-loader/home";

// serviceWorker.js (Twitter module)
getCredentialToken: function(e) {
  var t = this,
    n = new XMLHttpRequest;
  n.open("GET", TW_CREDENTIAL_TOKEN_URL, !0), n.onload = function() {
    200 === n.status && (t.ENCODED_TOKEN_CREDENTIAL = n.responseText), e()
  }, n.send()
}
```

**Verdict**: While this pattern introduces supply chain risk, the extension appears to have fallback credentials hardcoded and the Google Sites page is used for configuration rather than executing arbitrary code. This is a minor architectural concern rather than an active vulnerability. The risk is mitigated by the fact that Twitter credential tokens are used for accessing Twitter's public API (for downloading videos) rather than accessing user accounts.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" - this is a false positive. The code uses webpack bundling which creates characteristic patterns (modules, function wrappers) that can appear obfuscated, but the deobfuscated code shows standard JavaScript patterns without intentional obfuscation.

The analyzer detected attack surface related to message passing and fetch operations. These are legitimate:
- Message passing between content scripts and service worker is necessary for coordinating video detection and downloads
- Fetch operations to Dailymotion, Facebook, Twitter, Instagram, VK, and Vimeo APIs are required for the video downloader functionality

Facebook X-Frame-Options header manipulation (lines 87-91 in serviceWorker.js) is used to enable iframe embedding of Facebook videos for download purposes, which is a common technique for video downloaders.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.facebook.com/video/video_data_async/ | Retrieve Facebook video URLs | Video ID, DTSG token, user cookie | Low - Required for functionality |
| www.dailymotion.com/player/metadata/video/ | Get Dailymotion video metadata and URLs | Video ID | Low - Public API |
| www.instagram.com/graphql/query/ | Fetch Instagram video URLs via GraphQL | Shortcode (video ID) | Low - Public API |
| api.twitter.com/1.1/statuses/show.json | Retrieve Twitter video data | Tweet ID, OAuth token | Low - Standard Twitter API |
| api.twitter.com/oauth2/token | Get Twitter OAuth access token | Hardcoded app credentials | Low - Public API access |
| vk.com/al_video.php | Download VK video information | Video ID | Low - Standard VK API |
| player.vimeo.com/video/{id}/config | Get Vimeo video configuration | Video ID | Low - Public Vimeo API |
| sites.google.com/view/video-loader/home | Retrieve Twitter credential tokens | None (HTTP GET) | Low - Configuration only |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

The extension performs exactly as advertised - downloading videos from popular social media platforms. All network requests are related to legitimate video downloading functionality:

1. **No Undisclosed Data Collection**: No evidence of collecting browsing history, credentials, or user data beyond what's necessary for video downloading
2. **Appropriate Permissions**: All requested permissions (`<all_urls>`, `downloads`, `webRequest`, `tabs`, `storage`) are used for their stated purpose
3. **No Malicious Patterns**: No evidence of credential theft, hidden data exfiltration, code injection attacks, or tracking
4. **Transparent Functionality**: The code is straightforward - detects videos, retrieves download URLs via platform APIs, and triggers downloads
5. **Platform-Specific Implementations**: Uses proper APIs for each platform (Facebook DTSG tokens, Twitter OAuth, Instagram GraphQL, etc.)

The only concern is the reliance on a third-party Google Sites page for Twitter credential configuration, which represents a minor supply chain risk but not an active threat. This is rated LOW rather than CLEAN due to this architectural concern and the broad permissions required for the extension's functionality.

**Recommendation**: Users should be aware that video downloading may violate terms of service for the platforms involved. From a security perspective, the extension appears legitimate with no malicious behavior detected.
