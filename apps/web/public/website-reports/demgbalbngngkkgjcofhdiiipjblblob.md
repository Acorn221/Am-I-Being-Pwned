# Vulnerability Report: Horizon Browser Redirection

## Metadata
- **Extension ID**: demgbalbngngkkgjcofhdiiipjblblob
- **Extension Name**: Horizon Browser Redirection
- **Version**: 8.17.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Horizon Browser Redirection is a legitimate enterprise browser extension developed by VMware as part of the VMware Horizon virtual desktop infrastructure (VDI) solution. The extension enables seamless browser tab redirection from a virtual desktop to the user's local browser, improving performance and user experience in enterprise VDI environments.

The extension communicates exclusively via native messaging with the locally installed VMware Horizon Client software. It uses WebSocket connections to localhost (wss://view-localhost) with a dynamic port number provided by the native host. All functionality is governed by whitelists and configurations managed by the enterprise Horizon Client, ensuring that only authorized URLs can trigger redirection. This is a clean, legitimate enterprise tool with no security or privacy concerns.

## Vulnerability Details

No vulnerabilities identified. This is a legitimate enterprise tool operating as designed.

## False Positives Analysis

### Broad Permissions Are Expected for Enterprise VDI Tools

The extension requests powerful permissions including:
- `nativeMessaging` - Required to communicate with the Horizon Client
- `declarativeNetRequest` - Used to implement whitelist-based URL redirection rules
- `webRequest` + `webNavigation` - Monitor navigation events to redirect whitelisted URLs
- `scripting` - Inject content scripts for enhanced browser redirection mode
- `http://*/*` and `https://*/*` - Required to intercept navigation across all URLs (only redirects whitelisted ones)

These permissions are necessary and appropriate for the extension's stated purpose. The extension does NOT abuse these permissions - all URL interception is strictly controlled by whitelists provided by the enterprise Horizon Client via native messaging.

### WebSocket Connection to Localhost

The extension establishes WebSocket connections to `wss://view-localhost` on a dynamically assigned port. This is NOT data exfiltration - the WebSocket connection is exclusively to the local Horizon Client process running on the same machine. The port number is securely provided via native messaging and changes per session.

### Dynamic Content Injection

Enhanced Browser Redirection mode dynamically injects scripts (`enhBrowserRedir.js`, `injectEnhBrowserRedir.js`) into whitelisted pages. This is legitimate functionality to enable advanced features like overlay visibility control and bidirectional messaging between the far side (web page) and near side (local browser) for seamless VDI experiences.

### DeclarativeNetRequest Rules

The extension dynamically creates redirect rules using `declarativeNetRequest` API based on whitelists received from the Horizon Client. This is the correct implementation for URL redirection in Manifest V3 and is entirely controlled by enterprise policies.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| wss://view-localhost:{dynamic-port} | Local WebSocket connection to Horizon Client | Tab metadata, URL navigation events, overlay positions | None (localhost only) |

The extension does NOT communicate with any external servers. All communication is strictly local between the browser extension and the Horizon Client native application.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate VMware enterprise product with over 200,000 users. The extension operates exactly as documented - it enables browser tab redirection in VMware Horizon VDI environments. All functionality is controlled by the enterprise-managed Horizon Client via native messaging, with strict whitelist-based access controls. There is no data exfiltration, no credential theft, no unauthorized tracking, and no malicious behavior. The broad permissions are necessary and appropriately used for enterprise VDI browser redirection.

### Key Security Features
1. **Native Messaging Authentication**: Extension only works when paired with legitimate Horizon Client installation
2. **Whitelist-Based Access Control**: Only URLs explicitly whitelisted by the enterprise can be redirected
3. **Localhost-Only Communication**: All WebSocket connections are to localhost, preventing external data leakage
4. **Feature Detection**: Extension verifies browser redirection is supported by the client before enabling
5. **Version Checking**: Enhanced features only enabled for supported Horizon Client versions (8.13.0+)

This extension represents legitimate enterprise software with no security concerns.
