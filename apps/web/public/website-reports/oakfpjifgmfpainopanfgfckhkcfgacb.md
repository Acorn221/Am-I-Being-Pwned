# Vulnerability Report: Yandex Access

## Metadata
- **Extension ID**: oakfpjifgmfpainopanfgfckhkcfgacb
- **Extension Name**: Yandex Access
- **Version**: 5.2.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Yandex Access is a legitimate VPN/proxy extension developed by Yandex LLC. The extension provides proxy functionality to help users access region-restricted content by routing traffic through Yandex proxy servers. After thorough analysis of the deobfuscated code, no security vulnerabilities or privacy concerns beyond the extension's stated purpose were identified.

The extension uses powerful permissions (proxy, cookies, scripting, declarativeNetRequest, <all_urls>) that are all necessary for its core functionality. It fetches remote configuration from Yandex's CloudFront CDN, manages proxy settings intelligently with health checking and fallback mechanisms, and sends anonymized telemetry to Yandex endpoints. All observed behavior is consistent with a legitimate VPN/proxy service.

## Vulnerability Details

No vulnerabilities were identified. The extension exhibits standard behavior for a VPN/proxy service from a major technology company.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are legitimate for this extension type:

1. **Remote Configuration Fetching**: The extension fetches configuration from `https://d1cv6bu0xiop18.cloudfront.net/config_5_0_P.json`. This is standard practice for VPN/proxy extensions that need to maintain updated lists of proxy servers.

2. **Proxy Control**: The code extensively uses `chrome.proxy.settings.set()` and `chrome.proxy.settings.clear()` to configure PAC scripts. This is the core functionality of a proxy extension.

3. **Cookie Access**: The extension requests the `cookies` permission and accesses cookies for Yandex domains. This appears to be for maintaining user session state with Yandex services, not for credential harvesting.

4. **Scripting Permission**: Limited use of `chrome.scripting.executeScript()` was found (line 6960), used only to toggle DNS cache settings in specific tabs, not for malicious code injection.

5. **Network Requests**: The extension makes network requests to:
   - `https://d1cv6bu0xiop18.cloudfront.net/` - Configuration fetching
   - `https://soft.export.yandex.ru/status.xml` - Installation/usage statistics
   - `https://yandex.ru/clck/click/` - Analytics/telemetry

All these endpoints are owned by Yandex and are used for legitimate operational purposes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| d1cv6bu0xiop18.cloudfront.net/config_5_0_P.json | Fetch proxy server configuration | None (GET request) | Low - Standard remote config |
| soft.export.yandex.ru/status.xml | Send installation statistics | Platform info, install/usage metrics | Low - Disclosed telemetry |
| yandex.ru/clck/click/ | Analytics tracking | Event data, timestamps | Low - Standard analytics |

## Code Architecture

The extension is well-structured TypeScript code compiled with Webpack:

- **service_worker.js**: Main entry point that loads config and event_page modules
- **config.js**: Contains hardcoded URLs for remote configuration endpoints
- **event_page.js**: Core logic (8,816 lines) including:
  - ProxyController class: Manages proxy lifecycle, health checking, and fallback
  - Network utilities: HTTP request handlers with timeout and error handling
  - Detector system: Checks proxy reachability and switches to working servers
  - Statistics module: Sends anonymized usage data to Yandex
  - DNS cache management for performance optimization

## Permission Justification

All requested permissions are necessary and properly used:

- **proxy**: Required to configure PAC scripts for traffic routing
- **cookies**: Used for Yandex session management
- **storage**: Stores proxy configuration and user preferences
- **declarativeNetRequest**: Used for URL filtering/routing rules
- **scripting**: Minimal usage for DNS cache toggling
- **alarms**: Likely for periodic health checks of proxy servers
- **<all_urls>**: Required to proxy traffic for any domain

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate proxy/VPN service from Yandex, a major Russian technology company. The extension's behavior is entirely consistent with its stated purpose. While it has powerful permissions and makes network requests to external servers, all functionality is appropriate for a VPN/proxy extension. There is no evidence of:

- Hidden data exfiltration beyond disclosed telemetry
- Credential theft or session hijacking
- Undisclosed tracking or surveillance
- Malicious code injection
- Residential proxy abuse

The extension operates transparently within the expected boundaries of a commercial VPN/proxy service. Users should be aware that:
1. Traffic is routed through Yandex-controlled proxy servers
2. Usage statistics are sent to Yandex
3. The extension has access to all web traffic when enabled

These are standard characteristics of VPN/proxy extensions and are likely disclosed in the extension's privacy policy.
