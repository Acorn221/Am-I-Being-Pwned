# Vulnerability Report: Applied Epic Extension

## Metadata
- **Extension ID**: jmigehagkgopllnhcjngjgfblmjladih
- **Extension Name**: Applied Epic Extension
- **Version**: 3.16.17
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Applied Epic Extension is a legitimate enterprise browser extension developed by Applied Systems to support advanced functionality within their Applied Epic insurance software platform. The extension acts as a bridge between the web application (hosted on *.appliedepic.com) and native desktop applications via Chrome's nativeMessaging API, enabling integration with desktop components like the Desktop Connector and Print Center.

While this is a legitimate business tool with a clear enterprise use case, it contains one medium-severity vulnerability: a postMessage event listener in the content script that does not validate the origin of incoming messages, potentially allowing malicious websites to send crafted messages to the extension if they can determine the expected message format.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js:50
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The content script registers a `window.addEventListener("message")` handler that forwards messages from the page to the background script without validating the origin of the message. While the content script only runs on `*://*.appliedepic.com/*` domains, this creates a potential attack vector if:
1. An attacker can inject malicious JavaScript into an Applied Epic page (via XSS)
2. A compromised subdomain exists under appliedepic.com
3. The web application itself is compromised

**Evidence**:
```javascript
// content.js lines 4-16
function onMessageFromContentHandler(event) {
  if (event.source === window && event.data.target === 'page-to-extension') {
    // send message to the background script.
    // Sender info is appended by the browser.
    chrome.runtime.sendMessage(
      undefined,
      event.data.message,
      undefined,
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      () => {}
    );
  }
}
// ...
window.addEventListener('message', onMessageFromContentHandler, false);
```

The handler only checks that:
- `event.source === window` (message originated from the same window)
- `event.data.target === 'page-to-extension'` (message has the correct target property)

It does NOT validate `event.origin` to ensure the message came from a trusted source.

**Verdict**: This is a real vulnerability but with limited exploitability. The extension is scoped to `*.appliedepic.com` domains only, so an attacker would need to compromise the Applied Epic web application itself or exploit an XSS vulnerability within it. For an enterprise software platform, this is a realistic but not immediate threat. The vulnerability should be fixed by validating that `event.origin` matches the expected Applied Epic domain.

### 2. INFO: Externally Connectable to Applied Epic Domains

**Severity**: INFO (Design Feature)
**Files**: manifest.json:9-13
**CWE**: N/A

**Description**: The extension declares `externally_connectable` permissions allowing any page on `*.appliedepic.com` to send messages to the extension via `chrome.runtime.sendMessage()`.

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "*://*.appliedepic.com/*"
  ]
}
```

**Verdict**: This is expected behavior for this type of enterprise extension. The extension is designed to communicate with the Applied Epic web application, so allowing those pages to initiate communication is intentional and appropriate. This is not a vulnerability when combined with proper origin validation (which is currently missing in the postMessage handler).

## False Positives Analysis

### Native Messaging
The extension uses Chrome's `nativeMessaging` permission to communicate with native applications:
- `asi.epic.desktop.connector` - Desktop Connector for file operations and system integration
- `asi.epic.desktop.printcenter` - Print Center for specialized printing functionality

This is legitimate functionality for enterprise software that needs to integrate browser-based applications with desktop workflows. The extension properly handles connection failures and disconnections.

### Management Permission
The extension requests the `management` permission and uses `chrome.management.onEnabled` to detect when the extension is re-enabled after being disabled. This is used to re-inject content scripts into existing Applied Epic tabs, which is appropriate for ensuring the extension works correctly after updates or re-enablement.

### Cookie Access
The extension accesses cookies via the `cookies` permission and includes them in messages sent to the native Desktop Connector. The cookies are filtered to only include session cookies from the current tab's domain:
```javascript
this.cookies.getAll(
  { url: sender.tab.url, session: true, secure: true },
  (cookies) => {
    // Filter for F5 load balancer session cookies
    message.cookies = [...cookies];
    this.nativePostMessage(request.type, message);
  }
);
```

This is legitimate functionality - the extension needs to forward session cookies to the native Desktop Connector to ensure requests are routed to the correct backend server in a load-balanced environment. The cookies are only accessed from Applied Epic domains and only sent to the native application, not to any external servers.

### Multi-Tab Coordination
The extension implements sophisticated multi-tab coordination logic to manage multiple Applied Epic tabs and synchronize logout operations across tabs. This includes tracking which program areas are open in which tabs, managing tab focus, and coordinating session expiration. This is expected functionality for a complex enterprise web application.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| appliedepic.com | Host domain for Applied Epic insurance software | Messages forwarded to native desktop applications; session cookies | LOW - Legitimate business application |

**Note**: The extension does not make any direct network requests. All communication is either:
1. Between the extension and the Applied Epic web application (same domain, via postMessage and chrome.runtime)
2. Between the extension and native desktop applications (via nativeMessaging)

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise extension developed by Applied Systems for their Applied Epic insurance platform. The extension provides necessary functionality for integrating the web application with desktop components, managing multi-tab sessions, and coordinating complex workflows.

The MEDIUM risk rating is assigned due to the postMessage handler vulnerability (CWE-345) that lacks origin validation. While the extension is scoped to only run on Applied Epic domains, the missing origin check could allow malicious code (via XSS or a compromised subdomain) to send crafted messages to the extension.

**Mitigating Factors**:
- Extension is scoped to `*.appliedepic.com` domains only
- All sensitive operations require specific message types and data structures
- No direct network communication to external servers
- Native messaging connections are to specific, named native applications
- Developed by a legitimate enterprise software company

**Risk Factors**:
- Missing origin validation in postMessage handler
- Privileged permissions (management, nativeMessaging, cookies)
- Access to session cookies (though limited to secure, httpOnly, session cookies)

**Recommendation**: Applied Systems should add origin validation to the postMessage handler in content.js to verify that messages originate from trusted Applied Epic origins. The fix is straightforward:

```javascript
function onMessageFromContentHandler(event) {
  // Add origin validation
  if (!event.origin || !event.origin.match(/^https:\/\/[^\/]*\.appliedepic\.com$/)) {
    return;
  }

  if (event.source === window && event.data.target === 'page-to-extension') {
    chrome.runtime.sendMessage(undefined, event.data.message, undefined, () => {});
  }
}
```

For enterprise users: This extension is safe to use for its intended purpose within the Applied Epic platform. The vulnerability requires an attacker to first compromise the Applied Epic web application or exploit an XSS vulnerability, which is a separate security concern for Applied Systems to address.
