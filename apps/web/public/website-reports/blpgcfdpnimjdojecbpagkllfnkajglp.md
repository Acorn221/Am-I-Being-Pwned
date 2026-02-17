# Vulnerability Report: gs location changer

## Metadata
- **Extension ID**: blpgcfdpnimjdojecbpagkllfnkajglp
- **Extension Name**: gs location changer
- **Version**: 3.8
- **Users**: ~0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"gs location changer" is a clean, legitimate Chrome extension designed to spoof geographic location for Google searches. The extension modifies HTTP headers (specifically `x-geo` and `accept-language`) on requests to Google domains using the declarativeNetRequest API to simulate searches from different locations. This is a common use case for testing localized search results, circumventing geo-restrictions, or privacy purposes.

The extension operates transparently within its stated purpose. It uses modern Manifest V3 APIs, stores user preferences in chrome.storage.sync, and provides both a popup interface and context menu for location selection. No security or privacy concerns were identified beyond the extension's core functionality, which is to intentionally modify the user's apparent location to Google services.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### Header Modification
The extension modifies `x-geo` and `accept-language` headers on requests to Google domains. While header manipulation could be considered suspicious in malicious contexts, this is the core legitimate functionality of a location spoofing tool. The extension only targets Google domains (google.com, maps.google.com) with host_permissions, making it clear and limited in scope.

### External API Call
The extension makes requests to `photon.komoot.io/api/` for geocoding services (converting location names to coordinates). This is a legitimate, open-source geocoding API provided by Komoot. The extension only sends the user's search query (location name) to this service and receives coordinate data. No personal information or browsing data is transmitted. The extension also offers an alternative mode using Google's own geocoding service.

### Cookie Access
The extension has `cookies` permission and deletes UULE cookies (Google's location cookies) when the user disables location spoofing. This is appropriate cleanup behavior to ensure the fake location is properly removed.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| photon.komoot.io/api/ | Geocoding service (location name to coordinates) | User-entered location query string | Low - legitimate public API, only location queries sent |
| www.google.com/s?tbm=map | Google Maps geocoding (alternative mode) | User-entered location query string | Low - Google's own service |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension performs exactly as advertised without any deceptive or malicious behavior. Key positive indicators:

1. **Transparent Functionality**: The extension's purpose (spoofing location for Google searches) is clearly stated and all behavior aligns with this purpose.

2. **Modern Security Practices**: Uses Manifest V3 with declarativeNetRequest instead of webRequest, limiting the extension's ability to intercept or read actual request/response content.

3. **Limited Scope**: Only requests host permissions for the specific domains it needs (Google domains and the geocoding API). Does not request broad permissions like `<all_urls>`.

4. **No Data Exfiltration**: The extension stores all user preferences locally using chrome.storage.sync (which syncs across the user's Chrome instances but doesn't send data to third parties). No analytics, tracking, or data collection infrastructure present.

5. **Clean Code**: The deobfuscated code shows straightforward JavaScript without obfuscation, no eval/Function usage, and standard extension patterns. Uses well-known libraries (jQuery, Handlebars, Typeahead.js).

6. **Static Analysis Clean**: The ext-analyzer tool reported "No suspicious findings" and filtered out 2 benign flows.

The extension serves a legitimate use case and implements it securely without introducing security or privacy risks beyond its stated functionality.
