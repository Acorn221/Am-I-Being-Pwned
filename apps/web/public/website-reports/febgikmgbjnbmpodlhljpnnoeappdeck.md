# Vulnerability Report: Sense Messaging for Chrome

## Metadata
- **Extension ID**: febgikmgbjnbmpodlhljpnnoeappdeck
- **Extension Name**: Sense Messaging for Chrome
- **Version**: 1.43.4
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Sense Messaging for Chrome is a legitimate enterprise messaging application that provides a popover chat interface for the Sense platform. The extension injects a content script on all web pages to provide sidebar chat functionality. While the extension's core purpose is legitimate, it has a notable security vulnerability: multiple postMessage handlers lack origin validation, creating potential attack vectors for malicious websites to communicate with the extension's messaging system. The extension uses webpack bundling (not obfuscated), follows modern development practices with Sentry error tracking, and restricts network communication to specific Sense-owned domains.

The extension requests standard permissions for a messaging application (notifications, storage, tabs, cookies) and uses Google Cloud Messaging (GCM) for push notifications. All API communication is limited to sensehq.co, sensehq.com, sensehq.eu, dserver.com, and proxysense.link domains with CSRF protection.

## Vulnerability Details

### 1. MEDIUM: Missing Origin Validation in postMessage Handlers

**Severity**: MEDIUM
**Files**: page.js:31365, page.js:31405, page.js:41728, background.js:20574, background.js:32848, background.js:32888, action-menu.js:75076, action-menu.js:75116
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension implements multiple window.addEventListener("message") handlers across content scripts, background service worker, and popup pages without proper origin validation. The code includes TODO comments acknowledging this issue: "TODO (kyle): see if we can verify that the message is coming from our extension" (page.js:31385).

**Evidence**:
```javascript
// page.js:31384-31406
function listenToWindowMessages(handler) {
  // TODO (kyle): see if we can verify that the message is coming from our extension
  // @ts-expect-error - TS7031 - Binding element 'message' implicitly has an 'any' type.
  const handleMessage = async ({
    data: message,
    source
  }) => {
    if (message.direction === 'out') {
      source.postMessage({
        id: message.id,
        direction: 'back'
      }, '*');
      const result = await handler(message.data);
      source.postMessage({
        id: message.id,
        direction: 'back',
        data: result
      }, '*');
    }
  };
  windowHandlers.set(handler, handleMessage);
  window.addEventListener('message', handleMessage);
}
```

The handler uses wildcard origin ('*') in postMessage responses and doesn't validate event.origin. While the message format includes a direction field that provides some filtering, any malicious page could craft messages matching this structure.

**Verdict**:
This is a legitimate security concern that could allow malicious websites to interact with the extension's messaging system. However, the impact is mitigated by:
1. The message handler checks for specific message.direction values ("out")
2. The content script only injects on non-Chrome pages and specific Sense tabs
3. The extension's externally_connectable is restricted to Sense domains only
4. No sensitive operations (credential theft, data exfiltration) are directly accessible through these handlers

The vulnerability allows potential information disclosure or limited UI manipulation but does not provide direct access to user credentials or enable data exfiltration beyond what's already visible on the page.

## False Positives Analysis

**Webpack Bundling**: The extension uses standard webpack bundling with source maps. While the static analyzer flagged it as "obfuscated," this is normal minified production code, not intentional obfuscation to hide malicious behavior.

**WASM Flag**: The extension bundles WebAssembly modules, likely for performance optimization in the React-based UI. This is a standard practice and not indicative of malicious behavior.

**Content Script on <all_urls>**: The extension needs broad injection permissions to show the messaging sidebar on any website where users might need to access their Sense chat. The manifest explicitly excludes sensehq and related domains from content script injection, which is appropriate.

**Cookies Permission**: Required for authentication with the Sense platform. The code only accesses cookies on Sense-owned domains (sensehq.co, sensehq.com, sensehq.eu, dserver.com, proxysense.link) via host_permissions.

**GCM/Firebase Messaging**: Standard push notification implementation using Chrome's deprecated GCM API (being migrated to FCM). This is legitimate functionality for a messaging app.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| sensehq.com/api/v1/* | Core API endpoints | User messages, authentication tokens, app state | LOW - Legitimate service backend |
| sensehq.com/api/v2/* | Extended API (phone number inboxes) | Messaging data | LOW - Legitimate service backend |
| sensehq.com/api/v3/analytics/* | Analytics endpoints | Usage metrics | LOW - Standard analytics |
| cdn.sensehq.com | CDN for fonts | None | LOW - Static assets only |
| dserver.com | Backend server | Application data | LOW - Owned by Sense |
| proxysense.link | Proxy service | Unknown | LOW - Owned by Sense |

All API calls include:
- CSRF token validation for POST/PUT/DELETE
- Extension version header (X-Sense-Chrome-Extension-Version)
- Same-origin credentials
- Stored appUrl from chrome.storage.local

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This is a legitimate enterprise messaging extension with standard functionality for its purpose. The primary security concern is the missing origin validation in postMessage handlers, which creates a moderate risk surface for cross-site attacks. However, this vulnerability is significantly mitigated by:

1. **Limited attack surface**: The message handlers have structural validation (direction field) that prevents arbitrary command execution
2. **Domain restrictions**: externally_connectable limits which websites can initiate communication with the extension
3. **No credential exposure**: The vulnerable handlers don't directly access or transmit sensitive authentication data
4. **Scoped permissions**: The extension's host_permissions are limited to Sense-owned domains
5. **No data exfiltration**: All network communication goes exclusively to documented Sense infrastructure

The MEDIUM rating reflects that while a vulnerability exists, it requires specific conditions to exploit and the potential impact is limited. The extension does not exhibit characteristics of malware, adware, or privacy-invasive behavior. It's a professionally developed application with standard error tracking (Sentry), proper code structure, and clear business purpose.

**Recommendation**: The developers should add origin validation to all postMessage event listeners to check event.origin against an allowlist of trusted domains (primarily chrome-extension:// origins).
