# Vulnerability Report: Free VPN Proxy - VPNLY

## Metadata
- **Extension ID**: lneaocagcijjdpkcabeanfpdbmapcjjg
- **Extension Name**: Free VPN Proxy - VPNLY
- **Version**: 2.2.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Free VPN Proxy - VPNLY is a legitimate VPN browser extension that provides proxy functionality through authenticated proxy servers. The extension implements standard VPN features including proxy configuration, authentication handling, and server connection management. While the extension exhibits expected behavior for its category, it contains one medium-severity finding related to its externally_connectable configuration that allows localhost connections.

The extension uses various VPNLY-related domains for service functionality including vpnly.com, vpnlyru.com, and API endpoints. All network activity appears consistent with expected VPN service operations including geolocation, service notifications, and user support features.

## Vulnerability Details

### 1. MEDIUM: Localhost External Connectivity
**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension declares `externally_connectable` with a wildcard pattern for localhost (`*://localhost/*`), which allows any web page or application running on localhost to communicate with the extension via `chrome.runtime.sendMessage`. While this may be intended for development purposes or companion application integration, it creates an expanded attack surface where local malware or malicious local web servers could interact with the extension.

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "*://localhost/*"
  ]
}
```

**Verdict**: This configuration is a security concern as it allows any localhost application to send messages to the extension. If exploited by local malware, this could potentially be used to control proxy settings, trigger authentication flows, or access extension functionality. However, the risk is mitigated by requiring local access. For a production VPN extension with 1M users, this should either be removed or restricted to specific localhost ports if companion software integration is needed.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated". However, upon review, the code appears to be webpack-bundled and minified, which is standard practice for modern browser extensions built with build tools. The background.js file contains the Bowser library (browser detection) inline, which contributes to code density but is not malicious obfuscation.

The extension's use of proxy authentication and offscreen documents is legitimate functionality required for VPN operation in Manifest V3:
- The `webRequest.onAuthRequired` listener is necessary for proxy authentication
- The offscreen document is used to trigger authentication handlers, which is a standard MV3 pattern
- The proxy configuration and bypass list management is standard VPN behavior

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| vpnly.com | Main service website | Navigation only | Low |
| vpnlyru.com | Russian language site | Navigation only | Low |
| gapi.268222219.xyz | User geolocation/IP lookup | None (GET request) | Low |
| api.268222219.xyz | Support ticket submission | User feedback (name, email, message, platform info) | Low |
| s3.amazonaws.com/static.vpnly.com | Static resources | None (GET request) | Low |
| api.telegra.ph | SSL connectivity check | None (GET request) | Low |
| chrome-stats.com | Extension reviews | Navigation only | Low |
| chromewebstore.google.com | Extension store page | Navigation only | Low |

All endpoints are related to legitimate VPN service functionality. The geolocation endpoint is used to display user location, the API endpoint handles support tickets, and the S3 bucket serves service notifications and advertising interstitial data. No evidence of unauthorized data exfiltration.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate VPN proxy extension that performs its advertised functionality without significant security or privacy concerns. The extension properly implements VPN features including:

1. **Proxy Configuration**: Standard proxy.settings API usage with authentication
2. **Geolocation**: Uses external API to determine user location (expected for VPN services)
3. **Service Communication**: All network endpoints are VPNLY-related services
4. **Permission Usage**: All permissions are appropriately used for VPN functionality
5. **Auto-connect**: Standard feature for VPN extensions

The one medium-severity finding (externally_connectable to localhost) represents an unnecessary attack surface that should be addressed, but does not constitute malicious behavior. The extension does not exhibit characteristics of malware such as:
- Hidden data exfiltration
- Credential harvesting beyond proxy authentication
- Tracking beyond service requirements
- Code injection into web pages
- Undisclosed user monitoring

The extension appears to be a professionally developed VPN service with proper error handling, multi-browser support, and localization for 15+ languages. The webpack-bundled code is minified but not maliciously obfuscated.

**Recommendation**: The developer should remove the externally_connectable configuration or restrict it to specific localhost ports if companion application integration is genuinely required.
