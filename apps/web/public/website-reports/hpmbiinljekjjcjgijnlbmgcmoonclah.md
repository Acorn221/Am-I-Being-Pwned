# Vulnerability Report: Previews (For Twitch & YouTube & Kick)

## Metadata
- **Extension ID**: hpmbiinljekjjcjgijnlbmgcmoonclah
- **Extension Name**: Previews (For Twitch & YouTube & Kick)
- **Version**: 15.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Previews is a legitimate quality-of-life enhancement extension for Twitch, YouTube, and Kick streaming platforms. The extension provides live hover previews, auto-quality settings, screenshot/recording features, playback controls, and sidebar enhancements. The code is well-structured and purpose-appropriate for a streaming platform enhancement tool. While the static analyzer flagged several patterns, all are false positives in the context of this extension's legitimate functionality.

The extension uses optional cookie permissions that require explicit user consent, fetches streaming metadata from public APIs, and all network activity is consistent with its stated purpose. The postMessage handlers without origin checks present a minor vulnerability but are low-risk given the isolated context.

## Vulnerability Details

### 1. LOW: postMessage Handler Without Origin Check
**Severity**: LOW
**Files**: main/ytq_inj.js, main/ttvq_inj.js, main/core_kick.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: Three injected scripts set up postMessage listeners without validating the message origin.

**Evidence**:
```javascript
// ytq_inj.js:38
window.addEventListener("message", (function(e) {
  if ("tp_setYTQuality" === e.data.type) {
    const { selected_quality, fallback_quality, is_live_stream } = e.data;
    // ... quality setting logic
  }
}))

// ttvq_inj.js:82
window.addEventListener("message", (function(e) {
  if ("tp_setTTVQuality" === e.data.type) {
    const { selected_quality, fallback_quality } = e.data;
    // ... quality setting logic
  }
}))
```

**Verdict**: Low risk. These handlers only process quality setting commands (e.g., "1080p60", "chunked") which are validated against available quality levels. An attacker would need to be on the same page and could only trigger quality changes, not exfiltrate data or execute arbitrary code. The handlers check for specific message types and validate parameters against platform APIs.

## False Positives Analysis

The static analyzer flagged several patterns that are legitimate for this extension type:

1. **Exfiltration Flows (7 flagged)**: All "exfiltration" flows are legitimate DOM queries for stream metadata (channel names, titles, viewer counts) being sent to streaming platform APIs (static-cdn.jtvnw.net, www.twitch.tv, www.youtube.com) to fetch thumbnail previews and stream information. This is the core functionality of a "preview" extension.

2. **fetch() calls to streaming APIs**: The extension fetches from:
   - `www.twitch.tv` - Twitch API for stream data
   - `www.youtube.com` - YouTube subscriptions/feed data
   - `kick.com` - Kick streaming platform API
   - `static-cdn.jtvnw.net` - Twitch CDN for thumbnails
   - `m.facebook.com/gaming` - Facebook Gaming public pages
   - `www.w3.org` - Standard web specifications (SVG)

3. **Cookie Access**: The extension uses optional_permissions for cookies (requires user consent) solely to read the Kick.com session token to fetch the user's own followed channels. This is necessary functionality and requires explicit user approval.

4. **Screenshot/Recording Features**: The extension captures video frames for screenshots and recordings, storing them locally as Blobs. The data never leaves the browser - it creates local URLs via `URL.createObjectURL()` for display/download.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.twitch.tv | Fetch stream metadata, channel info | Stream names, channel IDs (public data) | CLEAN |
| www.youtube.com | Fetch subscription feed, channel info | Channel usernames (public data) | CLEAN |
| kick.com | Fetch user's followed channels | Session token (only with user consent) | CLEAN |
| static-cdn.jtvnw.net | Fetch Twitch thumbnails/previews | Public stream identifiers | CLEAN |
| m.facebook.com/gaming | Fetch Facebook Gaming stream info | Public streamer names | CLEAN |
| previews-app.com | Extension homepage/subscription page | None identified | CLEAN |

All endpoints are legitimate streaming platform APIs or the extension's own website. No third-party analytics, tracking, or ad networks detected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate streaming platform enhancement extension. The single vulnerability (postMessage without origin check) has minimal impact - an attacker could only trigger video quality changes, not access sensitive data or execute malicious code. The extension's network activity is entirely consistent with its stated purpose of providing stream previews and quality-of-life features. Cookie access is optional and properly gated behind user permissions. The extension does not inject ads, harvest browsing data, or contact suspicious third-party servers. All flagged "exfiltration" patterns are false positives representing normal streaming API usage.
