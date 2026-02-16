# Vulnerability Report: IBM Aspera Connect

## Metadata
- **Extension ID**: kpoecbkildamnnchnlgoboipnblgikpn
- **Extension Name**: IBM Aspera Connect
- **Version**: 5.0.0
- **Users**: ~900,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

IBM Aspera Connect is a legitimate enterprise file transfer extension published by IBM. The extension serves as a browser-native messaging bridge between web applications and IBM's Aspera Connect desktop application, which enables high-speed file transfers using IBM's proprietary FASP protocol. The extension implements a well-architected message passing system between content scripts, background service worker, and the native host application.

The extension contains no malicious code, no data exfiltration, no tracking, and no unnecessary permissions. All functionality is limited to its stated purpose: facilitating communication between web pages and the Aspera Connect desktop application. The code quality is professional with proper error handling and cross-browser compatibility layers (Edge polyfills).

## Vulnerability Details

No vulnerabilities identified. This section would normally contain specific security issues, but none were found during analysis.

## False Positives Analysis

### Broad Host Permissions (`http://*/*`, `https://*/*`)
While the extension requests access to all URLs, this is necessary and legitimate for its use case. Aspera file transfers can be initiated from any web application (enterprise file sharing platforms, cloud storage services, media companies, etc.), so the extension needs to inject its content script on any page that might use Aspera transfer functionality. The content script only activates when a page specifically dispatches the `AsperaConnectCheck` custom event, making it a passive listener rather than actively injecting functionality everywhere.

### Content Script on `<all_urls>` with `all_frames: true`
The content script (`asperaweb.js`) runs at `document_start` on all URLs and frames. However, its behavior is entirely passive - it only registers event listeners for `AsperaConnectCheck` and `AsperaConnectRequest` custom events. It does not read page content, modify the DOM, or access sensitive data unless explicitly invoked by the host page through custom events.

### Native Messaging Permission
The `nativeMessaging` permission enables communication with the desktop Aspera Connect application. This is the core purpose of the extension and is used legitimately to relay transfer requests and responses between the browser and native application. The native host is configured as `com.aspera.connect.nativemessagehost`, which is IBM's official native messaging host.

### Script Injection via `chrome.scripting.executeScript`
The background script uses `executeScript` to locate tabs with the `.aspera-connect-ext-locator` CSS class selector and reload them when the extension is updated. This is standard extension update behavior to ensure new extension code is loaded in existing tabs that use Aspera functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | Extension uses only native messaging, no external HTTP endpoints | N/A | None |

The extension does not make any network requests. All communication flows through:
1. Web page → Content script (via `postMessage` with origin validation)
2. Content script → Background worker (via `chrome.runtime` messaging)
3. Background worker → Native host (via `chrome.runtime.connectNative`)

## Code Architecture Analysis

### Content Script (`asperaweb.js`)
- Generates unique UUID per frame for message routing
- Establishes `chrome.runtime.connect` port to background script
- Listens for `AsperaConnectCheck` and `AsperaConnectRequest` events from page
- Sends responses back via `window.postMessage` with proper origin targeting
- Handles native host disconnection/reconnection gracefully

### Background Service Worker (`background.js`)
- Manages bidirectional communication between content scripts and native host
- Maintains connection map indexed by frame UUID
- Spawns native host process (`com.aspera.connect.nativemessagehost`) per connection
- Implements Mac-specific fullscreen workaround for better UX
- Includes extension update handler that reloads affected tabs
- Proper error handling for native host disconnection

### Bridge Files (Edge Compatibility)
The `backgroundScriptsAPIBridge.js` and `contentScriptsAPIBridge.js` files are Microsoft Edge polyfills that bridge Chrome extension APIs to Edge's `browser` namespace. These are standard compatibility shims and contain no security concerns - they simply wrap browser APIs with logging and fallback implementations.

## Security Strengths

1. **Origin Validation**: Content script validates `message.sender.origin` before using `postMessage`
2. **No External Communication**: Zero HTTP requests or data exfiltration
3. **Passive Activation**: Content script only activates when page explicitly requests it
4. **MV3 Architecture**: Modern service worker-based background script
5. **Professional Code Quality**: Proper error handling, connection lifecycle management
6. **IBM Publisher**: Extension is from a legitimate enterprise vendor

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

IBM Aspera Connect is a legitimate enterprise tool with no security or privacy concerns. The extension's architecture is appropriate for its purpose: acting as a browser-native messaging bridge for high-speed file transfers. All permissions are necessary and properly utilized. The code contains no malicious functionality, no data collection, no tracking, and no external communication beyond the documented native messaging channel to IBM's desktop application.

The low user rating (1.7/5) likely reflects technical issues or user experience problems rather than security concerns - enterprise tools often have poor ratings due to deployment/configuration complexity or being required rather than chosen by users.

This extension is safe for enterprise deployment and poses no security risk to users.
