# Vulnerability Report: UltraWide Video – Zoom, Stretch to Fill

## Metadata
- **Extension ID**: lngfncacljheahfpahadgipefkbagpdl
- **Extension Name**: UltraWide Video – Zoom, Stretch to Fill
- **Version**: 2.0.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

UltraWide Video is a video aspect ratio adjustment extension that helps users with ultrawide monitors remove black bars from videos. The extension modifies video elements on all websites using CSS transforms to zoom or stretch content based on user preferences.

The extension implements Google Analytics tracking and fetches server-side video scaling configurations from `service.ultrawidevideo.com`. While the analytics implementation exposes measurement credentials in client code (a poor security practice), the actual data collection is limited to usage telemetry and does not appear to exfiltrate sensitive user data. The extension collects basic video metadata (dimensions, playback state) and page URLs to provide server-side custom CSS for specific sites.

## Vulnerability Details

### 1. LOW: Hardcoded Google Analytics Credentials in Client Code

**Severity**: LOW
**Files**: background.bundle.js, popup.bundle.js
**CWE**: CWE-798 (Use of Hard-coded Credentials)

**Description**:
The extension hardcodes Google Analytics measurement ID (`G-P95JFE4HCB`) and API secret (`doGbQLi2Rp6nqq1jezESkw`) directly in the client-side JavaScript bundles. This allows anyone to view the analytics credentials and potentially send false analytics data to the extension's analytics account.

**Evidence**:
```javascript
// background.bundle.js, popup.bundle.js
const t = {chrome: "G-P95JFE4HCB"};
const a = {chrome: "doGbQLi2Rp6nqq1jezESkw"};

// Analytics endpoint
fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${v}&api_secret=${_}`, {
  method: "POST",
  body: JSON.stringify({
    client_id: p,
    events: [{
      name: this.sanitizeName(e),
      params: this.sanitizeParameters(t)
    }]
  })
})
```

**Verdict**:
This is a common but poor practice. The exposed credentials only allow sending analytics events, not viewing analytics data. The impact is limited to analytics pollution. This does not constitute a privacy or security risk to users, only to the developer's analytics accuracy.

## False Positives Analysis

The ext-analyzer flagged several "exfiltration" flows to Google Analytics:
- `document.getElementById → fetch(www.google-analytics.com)` - popup UI state tracking
- `document.querySelectorAll → fetch(www.google-analytics.com)` - DOM interaction events
- `chrome.storage.local.get → fetch(www.google-analytics.com)` - user preference tracking

These are **legitimate analytics flows** for usage telemetry. The data sent includes:
- Event names (button clicks, mode changes, scale adjustments)
- Session ID (generated locally)
- Client ID (randomly generated UUID stored in chrome.storage)

The extension does NOT send:
- User identities
- Cookies or session tokens
- Page content or form data
- Browsing history beyond current page URL

The cross-component message flow (`message data → fetch` from content script to background) is part of the video metadata collection feature, which sends:
- Video dimensions and aspect ratios
- Playback state (muted, paused, playback rate)
- Page URL and referrer
- Video element bounding boxes and CSS properties

This data is sent to `service.ultrawidevideo.com/get_video_scaling_settings` to retrieve custom CSS rules for specific video sites. This is a documented feature for providing site-specific video fixes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage telemetry | Event names, session ID, client UUID, user preferences | Low - standard analytics |
| service.ultrawidevideo.com | Video scaling configuration | Page URL, referrer, video metadata (dimensions, playback state), content type | Low - functional requirement for site-specific CSS |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

UltraWide Video is a legitimate video aspect ratio adjustment tool with expected functionality. The extension:

1. **Properly scoped permissions**: Requires `storage` and `*://*/*` host permissions, which are necessary for modifying videos on all sites and saving user preferences.

2. **Transparent data collection**: The extension collects page URLs and video metadata to provide server-side custom CSS configurations. This is disclosed in the privacy policy referenced in the popup UI.

3. **No sensitive data exfiltration**: Does not access cookies, passwords, form data, or other sensitive user information. Video metadata and page URLs are the only user data transmitted.

4. **Standard analytics implementation**: Uses Google Analytics for usage tracking with appropriate event sanitization.

5. **No code execution vulnerabilities**: No use of eval, Function constructor, or other dynamic code execution patterns.

6. **No injection vectors**: Does not inject ads, modify page content beyond video elements, or perform affiliate injection.

The only issue is the hardcoded analytics credentials, which is poor practice but has minimal security impact. The remote configuration feature (`remote_config` flag) is legitimate and necessary for the extension's site-specific video fixes functionality.

For a video manipulation extension with 200,000 users, this implementation is reasonable and does not present significant security or privacy concerns beyond what is expected for this type of utility.
