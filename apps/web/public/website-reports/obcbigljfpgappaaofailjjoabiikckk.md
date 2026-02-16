# Vulnerability Report: FoxClocks

## Metadata
- **Extension ID**: obcbigljfpgappaaofailjjoabiikckk
- **Extension Name**: FoxClocks
- **Version**: 7.0.0
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FoxClocks is a legitimate world clock and timezone tracker extension that displays times from different timezones at the bottom of the browser. The extension has been analyzed using both static code analysis and manual code review. The codebase is clean, well-documented, and contains no security vulnerabilities or privacy concerns. All network communications are limited to updating the timezone database from the official developer-controlled domain (foxclocks.org) and optional user-initiated actions like viewing maps or making donations.

The extension requests `<all_urls>` host permission solely for the purpose of injecting a statusbar UI element at the bottom of web pages to display world clocks. The content script operates in a read-only manner with respect to page content and does not collect, transmit, or modify any user data from visited websites.

## Vulnerability Details

No vulnerabilities were identified during the analysis.

## False Positives Analysis

### 1. `<all_urls>` Host Permission
**Pattern**: Extension requests `<all_urls>` host permission
**Why It's Legitimate**: The permission is required to inject the statusbar UI element that displays world clocks at the bottom of browser tabs. The content script (`content.js`) only injects an iframe containing the clock display and does not access, modify, or transmit any page content.

### 2. Obfuscation Flag from Static Analyzer
**Pattern**: ext-analyzer flagged the extension as "obfuscated"
**Why It's Legitimate**: The extension uses minified third-party libraries (jQuery, Moment.js, jsTree, jQuery UI) which are standard dependencies for UI functionality. The extension's own code in the `/lib/` directory is clean, readable, and properly commented with copyright notices. This is normal webpack bundling, not malicious obfuscation.

### 3. Network Requests
**Pattern**: Extension makes fetch() calls to external domains
**Why It's Legitimate**:
- `https://foxclocks.org/data/tz-db-update-check.cgi` - Automated weekly checks for timezone database updates (IANA timezone data)
- `https://maps.google.com/maps` - Optional user-initiated map viewing when clicking timezone locations
- `https://www.geonames.org/` - Attribution link for search functionality (not actively used for data collection)
- `https://www.paypal.com/` - Optional donation link in options page

All network requests are either automated updates from the official developer domain or user-initiated actions.

### 4. postMessage Usage
**Pattern**: Uses `window.postMessage()` for communication
**Why It's Legitimate**: The extension properly validates message origin before processing:
```javascript
const iframe = document.getElementById("foxclocks-statusbar-iframe");
const extensionOrigin = chrome.runtime.getURL("").slice(0, -1);

if (!iframe || e.source !== iframe.contentWindow ||
    e.origin !== extensionOrigin || !e.data)
    return;
```
This is secure cross-frame communication between the content script and its own iframe.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://foxclocks.org/data/tz-db-update-check.cgi | Check for timezone database updates | Client type (Chrome/Firefox/Edge), current DB version, timestamp | None - standard version checking |
| https://foxclocks.org/extension-installed | One-time new install notification | Client type, extension version | None - analytics only, user-initiated |
| https://foxclocks.org/extension-updated | One-time update notification | Client type, current version, previous version | None - analytics only, user-initiated |
| https://maps.google.com/maps | User-initiated map viewing | Timezone coordinates, location name | None - user-initiated |
| https://www.geonames.org/ | Attribution link | None (static link) | None - attribution only |
| https://www.paypal.com/ | Donation link | None (static link) | None - user-initiated |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

FoxClocks is a well-designed, legitimate utility extension with no security or privacy concerns. The codebase demonstrates professional development practices including:

1. **Proper Origin Validation**: All postMessage handlers validate message origins
2. **Minimal Permissions Usage**: While it requests `<all_urls>`, it's used strictly for UI injection
3. **Transparent Network Communication**: All network requests are to the official developer domain or well-known services
4. **No Data Collection**: The extension does not access, collect, or transmit any browsing data, form inputs, cookies, or other sensitive information
5. **Clean Code Quality**: Properly commented, readable code with copyright notices
6. **Manifest V3 Migration**: Successfully migrated to MV3 architecture with service worker
7. **No Dynamic Code Execution**: No use of eval(), Function(), or dynamic script injection
8. **Appropriate CSP**: Uses secure content security policies

The extension's functionality matches its stated purpose exactly. It provides a useful timezone tracking feature without any hidden behaviors or privacy risks.

**Recommendation**: This extension is safe for general use.
