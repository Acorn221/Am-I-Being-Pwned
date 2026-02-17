# Vulnerability Report: IP Domain Country Flag

## Metadata
- **Extension ID**: mlpapfcfoakknnhkfpencomejbcecdfp
- **Extension Name**: IP Domain Country Flag
- **Version**: 0.2.5
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

IP Domain Country Flag is a browser extension that displays country flags and geolocation information for websites based on their server location. The extension sends only the hostname/domain name to the developer's API (addon.dnslytics.uk) to retrieve geolocation data, which is then cached locally for 7 days. The extension's privacy statement explicitly discloses this data collection: "To protect your privacy, we only send the domain name to our database."

The code is clean, well-structured, and the data collection is minimal and appropriate for the stated functionality. The extension uses local caching to minimize API calls and does not collect any sensitive user data beyond the domain names of visited websites. This is a legitimate geolocation lookup service with appropriate privacy disclosure.

## Vulnerability Details

No security or privacy vulnerabilities were identified in this extension.

## False Positives Analysis

The static analyzer flagged one exfiltration flow: `chrome.tabs.get → fetch(addon.dnslytics.uk)`. This is a **false positive** for the following reasons:

1. **Disclosed behavior**: The extension description explicitly states "To protect your privacy, we only send the domain name to our database"
2. **Minimal data**: Only the hostname/domain is extracted from tab.url using regex extraction (`getHostname()` function), not full URLs, cookies, or other sensitive data
3. **Legitimate functionality**: Geolocation lookup services require sending the hostname to a backend API to determine server location
4. **Appropriate caching**: Results are cached locally for 7 days to minimize repeated API calls
5. **Proper permissions**: Only requests `tabs` permission (read-only), not sensitive permissions like cookies, history, or webRequest

The data flow is:
```
chrome.tabs.get(tabId) → extract hostname via regex → check local cache →
if not cached: fetch("https://addon.dnslytics.uk/flaginfo/v1/" + hostname)
```

This is standard behavior for any IP/domain geolocation extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| addon.dnslytics.uk | Geolocation lookup | Hostname/domain only | Low - disclosed, minimal data |

**API Call Pattern:**
```javascript
fetch("https://addon.dnslytics.uk/flaginfo/v1/" + hostname)
```

The API returns geolocation data including:
- Country code
- City/region/country name
- IP address
- ASN information
- Domain ranking

This data is cached locally using chrome.storage.local with a 7-day expiration.

## Code Quality Assessment

**Positive indicators:**
- Clean, readable code with no obfuscation
- Proper error handling throughout
- MV3 compliant (service worker background script)
- Strong CSP policy: `default-src 'self'; connect-src https://*.dnslytics.uk;`
- Host permissions restricted to `https://*.dnslytics.uk/*` only
- Cache purging mechanism to prevent unlimited local storage growth
- Private IP detection (10.x.x.x, 127.x.x.x, 172.16-31.x.x, 192.168.x.x) to avoid sending local hostnames

**Security features:**
- No use of eval() or dynamic code execution
- No access to sensitive permissions (cookies, webRequest, history)
- No content scripts injected into pages
- No modification of web pages

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate geolocation service extension that operates exactly as described in its privacy policy. While it does send domain names to an external API (which the static analyzer correctly identified), this behavior is:

1. **Fully disclosed** in the extension description
2. **Minimal in scope** (only hostnames, no full URLs or sensitive data)
3. **Necessary for functionality** (geolocation requires backend lookup)
4. **Appropriately cached** to minimize data transmission
5. **Privacy-conscious** (filters out private/local IP addresses)

The extension poses minimal privacy risk as it only collects the domain names of visited websites, which is explicitly disclosed and necessary for providing geolocation information. No other user data is accessed or transmitted.
