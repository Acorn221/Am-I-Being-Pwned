# Vulnerability Report: Highlight This

## Metadata
- **Extension ID**: fgmbnmjmbjenlhbefngfibmjkpbcljaj
- **Extension Name**: Highlight This
- **Version**: 6.3.11
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Highlight This is a legitimate text highlighting extension that allows users to highlight words and phrases on web pages. The extension includes analytics tracking and license validation features that communicate with the developer's servers at api.highlightthis.net. While the static analyzer flagged two exfiltration flows, these are standard and disclosed functionality for a commercial extension with freemium licensing. The extension also includes a third-party monetization library (adgoal) for universal search functionality.

The extension operates transparently with appropriate functionality for its stated purpose. The data collection is limited to usage analytics and license validation, which is reasonable for a freemium product. There are no indicators of malicious behavior, credential theft, or undisclosed data exfiltration.

## Vulnerability Details

### 1. LOW: Third-Party Monetization Library
**Severity**: LOW
**Files**: libs/adgoal/background.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension includes a third-party "universal search" library from mtusconf.de that injects affiliate links into search results. The code fetches remote configuration and transforms search result links to include affiliate tracking parameters.

**Evidence**:
```javascript
const {
    CONFIG_URL: c
} = {
    CONFIG_URL: "https://mtusconf.de/universal_search/v2/config/config.json",
    EXT_MANIFEST_VERSION: "v2",
    MODE: "production"
};
```

```javascript
getTransformedHref(e, t) {
    const {
        MEMBER_HASH: r,
        PANEL_HASH: o
    } = universalSearchCredentials, n = encodeURIComponent(t);
    return `${this.config.apiParameters.redirectURL}?u=${r}&m=12&p=${o}&t=33&splash=0&q=${e}&url=${n}`
}
```

**Verdict**: This is a standard affiliate monetization library. While it modifies search results, this appears to be disclosed functionality for a free-tier product. The library uses remote configuration which is a common pattern but does introduce supply chain risk.

## False Positives Analysis

The static analyzer flagged two "HIGH" severity exfiltration flows:

1. **chrome.storage.local.get → fetch in serviceWorker/licenseManager.js**: This is legitimate license validation functionality. The extension sends the license key and installation ID to api.highlightthis.net to validate paid licenses. This is standard practice for commercial software.

2. **chrome.storage.local.get → fetch in libs/adgoal/background.js**: This is the third-party monetization library that fetches remote search configuration. While technically data exfiltration, it's fetching configuration data, not exfiltrating sensitive user data.

The static analyzer also flagged the extension as "obfuscated" but examination of the deobfuscated code shows this is webpack-bundled code with minification, not malicious obfuscation. The core extension logic is clearly readable after deobfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.highlightthis.net/api/licenseService/licensecheck | License validation | License key, installation ID | Low - Standard licensing |
| api.highlightthis.net/api/adService/v2/config | Ad configuration | None (GET request) | Low - Feature config |
| api.highlightthis.net/api/analyticsService/analytics/{installId} | Usage analytics | Extension version, usage stats, browser type, language, license type, group/word counts | Low - Disclosed analytics |
| highlightthis.net/Welcome.html | Welcome page | None | None - Documentation |
| highlightthis.net/ReleaseNote_6*.html | Release notes | None | None - Documentation |
| mtusconf.de/universal_search/v2/config/config.json | Search monetization config | None (GET request) | Low - Third-party config |
| spreadsheets.google.com | Google Sheets integration | User-configured (feature) | Low - Optional feature |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate commercial extension with appropriate functionality for its stated purpose. The "exfiltration" flows are standard operations for a freemium product:
- License validation to enforce paid features
- Usage analytics for product improvement
- Third-party monetization for free tier users

The extension requests broad permissions (tabs, storage, contextMenus) but these are all justified for a text highlighting tool that needs to work across all websites. The content scripts run on `<all_urls>` which is necessary for the core functionality.

The main consideration is the third-party adgoal library which introduces supply chain risk through remote configuration, but this appears to be limited to search result modification for monetization purposes. There are no indicators of credential theft, keylogging, or malicious data exfiltration.

Users should be aware that the free version includes affiliate monetization through modified search results, but this is typical for freemium browser extensions.
