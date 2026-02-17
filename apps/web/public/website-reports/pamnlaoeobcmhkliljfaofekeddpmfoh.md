# Vulnerability Report: Web to PDF

## Metadata
- **Extension ID**: pamnlaoeobcmhkliljfaofekeddpmfoh
- **Extension Name**: Web to PDF
- **Version**: 3.3.5
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Web to PDF is a legitimate PDF conversion extension that allows users to save web pages as PDF files. The extension integrates with Google Drive for storage and uses a third-party paywall/monetization service (onlineapp.pro) for premium features. While the extension performs its stated functionality, it collects and transmits usage analytics and event tracking data to external domains. The main privacy concern is the tracking of user behavior (installation events, usage patterns) sent to onlineapp.pro with a persistent user ID. However, no sensitive browsing data, credentials, or personal information appears to be exfiltrated beyond basic telemetry.

The extension uses the debugger permission for PDF generation, which is a powerful capability but appears to be used legitimately for its core functionality. Sentry error tracking is embedded for debugging purposes, sending error reports to betterstackdata.com.

## Vulnerability Details

### 1. MEDIUM: Usage Analytics and Event Tracking

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension tracks user behavior and sends telemetry to onlineapp.pro. A persistent user ID is generated and stored in chrome.storage.sync, then sent with event tracking requests including installation events and usage patterns.

**Evidence**:
```javascript
// background.js line 41700
fetch("https://onlineapp.pro/api/track-event", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    event: a,
    wallId: ca,
    extensionId: x.runtime.id,
    userId: o,
    ...r
  })
})

// User ID generation (line 41730)
const o = crypto.randomUUID();
x.storage.sync.set({
  user_id: o,
  [`pw-${ca}-visitor-id`]: o
}, () => {
  a(o)
})
```

**Verdict**: While this tracking is concerning from a privacy perspective, it appears limited to usage events rather than browsing history or sensitive data. The extension does not explicitly disclose this tracking to users in its description, which reduces transparency. This is a common practice for monetized extensions but raises privacy concerns.

### 2. LOW: Externally Connectable to Paywall Domains

**Severity**: LOW
**Files**: manifest.json, background.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension declares `externally_connectable` with `<all_urls>` in the manifest, allowing any webpage to communicate with the extension. The background script does implement origin validation for onlineapp.pro domains when handling external messages.

**Evidence**:
```javascript
// manifest.json
"externally_connectable": {"matches": ["<all_urls>"]}

// background.js line 41694-41695
function e(a) {
  return ["onlineapp.pro", "onlineapp.live", "onlineapp.stream"].some(r => a.includes(r))
}

// External message validation (line 41747)
if (r.url && e(r.url))
```

**Verdict**: While `externally_connectable` with `<all_urls>` is overly permissive, the extension properly validates message origins before processing. The communication appears limited to paywall/authentication functionality with the onlineapp.pro service. The use of `includes()` rather than exact domain matching is slightly weak but appears intentional for subdomain support.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension type:

1. **chrome.debugger permission**: Used for PDF generation via Chrome DevTools Protocol, which is the recommended approach for advanced page manipulation and printing.

2. **Large bundled files**: The extension uses Vue.js and modern build tooling (webpack), resulting in large chunks files. This is standard for modern web applications and not indicative of obfuscation.

3. **Sentry error tracking**: The betterstackdata.com endpoints are part of Sentry error monitoring, a legitimate debugging service. The authentication token in the URL is expected for Sentry DSN configuration.

4. **OAuth2 configuration**: The googleapis.com integration is for Google Drive file uploads, matching the extension's stated functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| onlineapp.pro/api/track-event | Usage analytics | Extension ID, user ID, event type | Medium |
| onlineapp.pro/api/v1/paywall/* | Paywall/monetization | User authentication state | Low |
| s1720869.eu-fsn-3.betterstackdata.com | Error tracking (Sentry) | Error messages, stack traces | Low |
| webtopdf.space | Marketing/welcome page | None (redirect only) | None |
| googleapis.com/auth/drive.file | Google Drive integration | PDF files (user-initiated) | None |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension performs its stated functionality legitimately but includes undisclosed usage tracking and analytics. The tracking is limited to behavioral events rather than sensitive data, but the lack of transparency about data collection to third-party services (onlineapp.pro) is concerning. The extension uses powerful permissions (debugger, all_urls) appropriately for its PDF conversion functionality. No evidence of credential theft, unauthorized data exfiltration, or malicious behavior was found. The medium risk rating reflects the privacy implications of undisclosed tracking rather than active malicious intent.

**Recommendations**:
- Users concerned about privacy should be aware that usage data is sent to onlineapp.pro
- The developer should disclose analytics collection in the extension description
- Consider whether the paywall integration justifies the tracking overhead
