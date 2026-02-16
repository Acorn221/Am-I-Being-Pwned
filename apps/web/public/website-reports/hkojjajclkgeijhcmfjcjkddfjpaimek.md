# Vulnerability Report: QR Code (Generator and Reader)

## Metadata
- **Extension ID**: hkojjajclkgeijhcmfjcjkddfjpaimek
- **Extension Name**: QR Code (Generator and Reader)
- **Version**: 2.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

QR Code (Generator and Reader) is a browser extension that allows users to generate and scan QR codes. The extension sends user-created QR code data to third-party URL shortening services (hybridapps.net and amazonspot.net) and collects analytics via Google Analytics. While the extension's core functionality is legitimate, it transmits user data (including URLs and potentially sensitive content) to external servers without clear disclosure in the privacy policy or extension description. The data transmission is limited to user-initiated QR code generation, and the extension does not appear to exfiltrate browsing history or other sensitive browser data without user action.

The overall risk is assessed as LOW because the data collection is tied to the extension's stated functionality, but users should be aware that their QR code content is being sent to third-party services.

## Vulnerability Details

### 1. LOW: Undisclosed Third-Party Data Transmission

**Severity**: LOW
**Files**: scripts/common.js, scripts/shared/utils.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension sends user-generated QR code data to third-party URL shortening services without prominent disclosure. When users create QR codes, the extension transmits the content to hybridapps.net or amazonspot.net for shortlink generation.

**Evidence**:
```javascript
// scripts/common.js:90
QR_SERVICES: ["https://hybridapps.net/apps/URLShortner/bitly.php", "https://amazonspot.net/apps/URLShortner/bitly.php"]

// scripts/shared/utils.js:341-361
async function k(n) {
  let t;
  for (const e of d.QR_SERVICES) {
    try {
      const r = new URL(e);
      r.searchParams.append("src", d.APP_ID),
      r.searchParams.append("type", "QR"),
      r.searchParams.append("qrData", B(JSON.stringify(n))),
      r.searchParams.append("svcEnv", "QRCdOrg"),
      t = await F(r, "POST", null)
    } catch (r) {
      o.gaEventALV("QR_SERVICE_FAILED", e, r);
      continue
    }
    // ...
  }
}
```

The function `k()` (likely "getShortUrl") base64-encodes and sends QR data to external services. This data could include sensitive URLs, text, contact information, or other personal data that users encode into QR codes.

**Verdict**: This is a LOW severity issue because the data transmission is tied to the core functionality (URL shortening for QR codes) and occurs only when users explicitly create QR codes. However, users may not be aware that their data is being sent to third-party servers, especially if they expect local-only QR generation.

### 2. LOW: Analytics Tracking with Client ID

**Severity**: LOW
**Files**: scripts/common.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension implements Google Analytics tracking with a persistent client ID stored in chrome.storage.local, allowing cross-session tracking of user behavior within the extension.

**Evidence**:
```javascript
// scripts/common.js:126-151
let _ = async (e, t, o, s) => {
  try {
    // ...
    if (!c) {
      const l = await chrome.storage.local.get("ga_client_id");
      !l || !l.ga_client_id ? (c = `inst_${Date.now()}`,
        await chrome.storage.local.set({ ga_client_id: c }))
        : c = l.ga_client_id
    }
    // ...
    await fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${I}&api_secret=${u}`, {
      method: "POST",
      body: JSON.stringify({
        client_id: c,
        events: [{
          name: T,
          params: g
        }]
      })
    })
  }
}
```

The extension tracks various user interactions (popup opens, QR creation success/failure, settings changes) and sends them to Google Analytics with measurement ID `G-Y43XRGKDTW`.

**Verdict**: This is LOW severity because the analytics appear to track extension usage patterns rather than sensitive browsing data. However, the persistent client ID enables long-term tracking across sessions, which may not be adequately disclosed to users.

## False Positives Analysis

The ext-analyzer flagged one EXFILTRATION flow from `chrome.storage.local.get → fetch(hybridapps.net)`. This is a TRUE POSITIVE - the extension does retrieve data from local storage and send it to external services. However, the data being sent is:
1. User-created QR code content (not passively harvested data)
2. Sent only when users explicitly request QR code generation
3. Necessary for the URL shortening feature

The extension also includes standard references to tinyl.io URLs for install/uninstall tracking pages, which is common practice.

The "obfuscated" flag was raised, but this appears to be webpack-bundled code with minified variable names, not intentionally obfuscated malicious code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| hybridapps.net/apps/URLShortner/bitly.php | URL shortening service | User-created QR content (base64-encoded JSON with type, data, mode, name) | LOW - User-initiated, functional necessity |
| amazonspot.net/apps/URLShortner/bitly.php | Backup URL shortening service | Same as above | LOW - Fallback for primary service |
| www.google-analytics.com/mp/collect | Analytics collection | Extension usage events, client ID, session data | LOW - Standard analytics, no sensitive content |
| tinyl.io/QRExt5Install | Install tracking redirect | None (redirect on install) | MINIMAL - Standard install tracking |
| tinyl.io/QRExt5UnInstall | Uninstall tracking redirect | None (redirect on uninstall) | MINIMAL - Standard uninstall tracking |
| tinyl.io/QRExt5Updated | Update tracking redirect | None (redirect on update) | MINIMAL - Standard update tracking |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
The extension performs its stated functionality (QR code generation and reading) but transmits user data to third-party services without prominent disclosure. The key mitigating factors are:

1. **User-initiated only**: Data transmission occurs only when users actively create QR codes, not passively
2. **Functional necessity**: The URL shortening service appears to be a feature (creating short URLs for QR codes)
3. **No credential theft**: No evidence of password harvesting, cookie theft, or similar malicious activity
4. **No browsing history exfiltration**: The extension does not access or transmit general browsing data
5. **Limited permissions**: The extension uses activeTab (not <all_urls>) and does not request overly broad permissions

**Concerns**:
1. Privacy disclosure appears inadequate - users may not know their QR content is sent to third parties
2. The third-party services (hybridapps.net, amazonspot.net) are not well-known or clearly documented
3. Persistent analytics tracking via Google Analytics

**Recommendation**: Users who create QR codes with sensitive content should be aware that this data may be transmitted to third-party servers. For maximum privacy, users should consider local-only QR code generators.
