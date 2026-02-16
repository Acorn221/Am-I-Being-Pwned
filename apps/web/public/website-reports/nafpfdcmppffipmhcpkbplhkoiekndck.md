# Vulnerability Report: EXIF Viewer Classic

## Metadata
- **Extension ID**: nafpfdcmppffipmhcpkbplhkoiekndck
- **Extension Name**: EXIF Viewer Classic
- **Version**: 3.0.1
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

EXIF Viewer Classic is a photo metadata viewer extension that allows users to quickly access EXIF data from images on web pages. The extension operates as intended by extracting and displaying EXIF metadata (camera model, GPS coordinates, exposure settings, etc.) from JPEG images.

While the core functionality is legitimate, the extension exhibits two minor privacy concerns: (1) integration with Google Analytics that tracks user interactions and sends session data to www.google-analytics.com, and (2) a remote notification system that fetches promotional messages from external servers and displays them to users. The ext-analyzer flagged two exfiltration flows, but these are benign - one is for displaying Google Maps thumbnails of GPS coordinates, and the other is standard analytics tracking. The extension does not exfiltrate browsing data, credentials, or other sensitive information beyond what users would expect from analytics.

## Vulnerability Details

### 1. LOW: Google Analytics Integration with Session Tracking

**Severity**: LOW
**Files**: scripts/common.js, scripts/index.js, service_worker.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension integrates Google Analytics (measurement ID: G-70BF5Y4RDM, API secret hardcoded) to track user interactions. It collects a client ID (stored in chrome.storage.local as "ga_client_id"), session IDs, engagement times, and various action/label/value event parameters. Events are sent to www.google-analytics.com/mp/collect.

**Evidence**:
```javascript
// common.js lines 90-116
let d = async (e, t, o, s) => {
  // ... generates client_id if not exists
  if (!r) {
    const a = await chrome.storage.local.get("ga_client_id");
    !a || !a.ga_client_id ? (r = `inst_${Date.now()}`,
      await chrome.storage.local.set({ ga_client_id: r })) : r = a.ga_client_id
  }
  // ... sends to Google Analytics
  await fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${E}&api_secret=${I}`, {
    method: "POST",
    body: JSON.stringify({
      client_id: r,
      events: [{ name: C, params: g }]
    })
  })
}
```

**Verdict**: This is standard analytics implementation. The data collected (interaction events, session metrics) is typical for understanding user behavior. No browsing history, personal data, or EXIF content is exfiltrated - only extension usage patterns. However, users are not prominently informed about analytics tracking in the Chrome Web Store description.

### 2. LOW: Remote Notification System with Promotional Messages

**Severity**: LOW
**Files**: scripts/index.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches notification messages from remote JSON endpoints (dsnetx.web.app/apps/firelinks/msg.json and dsnet.bitbucket.io/apps/ext/msg/msg.json) with cache-busting query parameters. These messages can be displayed as web UI notifications to users. The system supports filtering by extension ID, version ranges, expiration dates, and repeat intervals.

**Evidence**:
```javascript
// index.js lines 309-343
const V = ["https://dsnetx.web.app/apps/firelinks/msg.json",
           "https://dsnet.bitbucket.io/apps/ext/msg/msg.json"];

function C(e) {
  const t = `${V[u]}?ref=${x}&r=${Math.random()}`;
  fetch(t, { cache: "no-store" })
    .then(i => i.json())
    .then(i => {
      E(x, "Notif", "Loaded"), I(i) ? (u++, ...) : (u = 0, Ie(i))
    })
}

function Se(e, t) {
  // Displays notifications in web UI
  W(e.msg, i)
}
```

**Verdict**: While this allows the developer to push promotional messages to users (e.g., update announcements, feature promotions), it does not execute arbitrary code - only displays HTML messages. The messages are filtered by extension ID to prevent targeting wrong extensions. This is a borderline practice as it enables post-installation communication without explicit user consent, but it's limited to informational/promotional content and does not pose a direct security risk.

## False Positives Analysis

### ext-analyzer Exfiltration Findings
The static analyzer flagged two "HIGH" exfiltration flows:
1. **document.getElementById → fetch(maps.google.com)**: This is NOT data exfiltration. When EXIF data contains GPS coordinates, the extension displays a Google Maps static map thumbnail showing the photo location. The map URL is constructed client-side using GPS lat/long from the EXIF data, and the fetch retrieves only the map image.

2. **chrome.storage.local.get → fetch(www.google-analytics.com)**: This is the Google Analytics tracking described above. While it does send data externally, it only transmits analytics event metadata (client_id, event names, session IDs), not user browsing data or EXIF content.

Both flows are legitimate for the extension's stated functionality and common development practices.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Analytics tracking | Client ID (timestamp-based), event labels, session metrics | Low - standard analytics |
| maps.google.com | Display GPS location maps | GPS coordinates from EXIF data | Minimal - public API, no personal data |
| dsnetx.web.app/apps/firelinks/msg.json | Fetch notification messages | Extension ID (in query param) | Low - informational messages only |
| dsnet.bitbucket.io/apps/ext/msg/msg.json | Fallback notification endpoint | Extension ID (in query param) | Low - informational messages only |
| tinyl.io/* | Install/update/uninstall redirect URLs | None (just redirects) | Minimal - tracking link service |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: EXIF Viewer Classic performs its stated function (extracting and displaying EXIF metadata from images) without major security or privacy violations. The two concerns identified are:

1. **Google Analytics integration** is a common practice but should be disclosed more prominently to users. The data collected is limited to usage patterns, not browsing history or personal information.

2. **Remote notification system** allows the developer to communicate with users post-installation, which could be used for promotional purposes. However, it doesn't execute code or exfiltrate data - only displays messages.

Neither issue constitutes malware, data theft, or a critical vulnerability. The extension is not obfuscated (beyond standard webpack bundling), does not hook XMLHttpRequest/fetch to intercept network traffic, does not enumerate other extensions, and does not inject ads. The broad host permissions (http://*/*, https://*/*) are necessary for the content script to detect and analyze images on all websites.

The risk level is LOW rather than CLEAN due to the lack of transparency around analytics tracking and the promotional notification system, but the extension is fundamentally safe to use.
