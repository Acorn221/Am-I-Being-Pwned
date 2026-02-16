# Vulnerability Report: AdGuard Browser Assistant

## Metadata
- **Extension ID**: fbohpolgemkbfphodcfgnpjcmedcjhpn
- **Extension Name**: AdGuard Browser Assistant
- **Version**: 1.4.8
- **Users**: ~600,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AdGuard Browser Assistant is a legitimate companion extension for the AdGuard desktop application. The extension provides in-browser UI controls for AdGuard's ad blocking features and communicates with the desktop application via Chrome's native messaging API. All functionality is consistent with its stated purpose as a browser assistant for the AdGuard desktop app. No security or privacy concerns were identified.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### Native Messaging Communication
The extension uses the `nativeMessaging` permission to communicate with a native host application (`com.adguard.browser_extension_host.nm`). This is the legitimate and documented method for browser extensions to communicate with desktop applications. The communication is used to:
- Control ad blocking settings (enable/disable protection, pause filtering)
- Add custom filtering rules
- Report issues to AdGuard
- Access filtering logs
- Check application state

The extension sends the current page URL to the native host to determine filtering status, which is disclosed in the post-install consent screen shown to users.

### Webpack Bundling
The code is bundled with webpack and includes standard libraries (lodash, React, webextension-polyfill). This is normal modern JavaScript development practice and not code obfuscation. The static analyzer flagged the extension as "obfuscated" but this is a false positive - the code uses standard webpack module wrapping.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| N/A | No external network requests | N/A | None |

The extension only communicates with the local AdGuard desktop application via native messaging, not with any external servers.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate browser extension published by Adguard Software Ltd that serves as a companion to their desktop ad blocking application. The extension:

1. Uses native messaging appropriately to communicate with the local AdGuard desktop app
2. Requests only necessary permissions (nativeMessaging, tabs, activeTab, contextMenus, storage, scripting)
3. Has no host permissions (does not inject content into web pages by default)
4. Shows a clear consent dialog explaining that it sends URLs to the desktop app
5. Does not make external network requests
6. Does not exfiltrate user data
7. Does not execute dynamic code or use eval
8. Is published by a reputable security software company (Adguard)
9. Has 600,000 users and a 4.0 rating

The extension's behavior is fully consistent with its stated purpose and privacy policy. All features are documented and transparent to users.
