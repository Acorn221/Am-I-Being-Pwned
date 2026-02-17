# Vulnerability Report: Fabasoft Folio 2016

## Metadata
- **Extension ID**: hiejidhjgjpelfgldfhmnaoahnephhfg
- **Extension Name**: Fabasoft Folio 2016
- **Version**: 16.0.11.83
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Fabasoft Folio 2016 is an enterprise document management browser extension developed by Fabasoft R&D GmbH. The extension serves as a bridge between web applications and the native Fabasoft Folio desktop client via Chrome's native messaging API. While this appears to be a legitimate enterprise tool, it exhibits two medium-severity security concerns: automatic collection and transmission of cookies to the native host without explicit user awareness, and unsafe postMessage communication patterns that could allow message interception.

The extension requests broad permissions including `<all_urls>`, `cookies`, `tabs`, and `nativeMessaging`, enabling it to interact with all websites and access sensitive session data. The primary functionality is facilitating authentication and communication between web-based Fabasoft Folio instances and the locally installed desktop client.

## Vulnerability Details

### 1. MEDIUM: Cookie Harvesting and Transmission to Native Host

**Severity**: MEDIUM
**Files**: nmextback.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension automatically collects all cookies from the user's active tab and transmits them to the native messaging host without explicit user consent or notification. This occurs during the `Init` and `UpdateLoginToken` methods.

**Evidence**:
```javascript
// nmextback.js lines 367-408
function postMessageWithCookies(data, contentport, contentportid)
{
  // ...
  chrome.cookies.getAll({url:data.srcurl, storeId:storeid}, function(cookies) {
    try {
      var cookiestr = "";
      if (cookies) {
        for (var i = 0;i < cookies.length; i++) {
          var cookie = cookies[i];
          cookiestr += (cookiestr ? "; " : "") + cookie.name + "=" + cookie.value;
        }
      }
      data.indata.cookies = cookiestr;
      // console.log("Cookies from url [" + data.srcurl + "] and store [" + storeid + "] for message: " + cookiestr);
    } catch(e) {
      handleError(e);
    }
    try {
      port.postMessage(data);
    } catch(e) {
      handleError(e, true);
    }
  });
}
```

The function extracts all cookies for the source URL and includes them in messages sent to the native host application via `chrome.runtime.connectNative("com.fabasoft.nmhostpm16")`.

**Verdict**: While cookie transmission is necessary for this enterprise SSO/authentication system to function properly, the lack of visible user notification or consent mechanism represents a privacy concern. For an enterprise deployment with explicit IT policy, this would be acceptable, but the extension is publicly available in the Chrome Web Store. Users should be explicitly informed that their cookies are being shared with a native application.

### 2. MEDIUM: PostMessage Without Origin Validation

**Severity**: MEDIUM
**Files**: nmext.js
**CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
**Description**: The content script uses `window.postMessage()` with a wildcard origin (`"*"`), allowing any frame or script on the page to potentially receive messages from the extension.

**Evidence**:
```javascript
// nmext.js line 57
window.postMessage(data, "*");

// nmext.js line 138
window.postMessage(response, "*");

// nmext.js line 168
window.postMessage(response, "*");

// nmext.js line 186
window.postMessage(response, "*");
```

Multiple instances throughout nmext.js use the wildcard origin when posting messages back to the page. While the extension does validate incoming messages (checking `event.source != window` on line 115), the outbound messages could potentially be intercepted by malicious iframes or scripts injected into the page.

**Verdict**: This represents a moderate security risk. A compromised or malicious website could inject code to listen for these messages and potentially capture sensitive data being passed between the extension and the legitimate Fabasoft web application. The messages include method names, call IDs, and potentially sensitive data in the `outdata` or `faildata` fields. Origin validation should be implemented to restrict message delivery to trusted origins only.

## False Positives Analysis

### Native Messaging Architecture
The use of `chrome.runtime.connectNative()` is the legitimate and intended mechanism for browser-to-native-app communication in Chrome extensions. The native host identifier `com.fabasoft.nmhostpm16` indicates a properly registered native messaging host.

### XMLHttpRequest to Login Endpoint
The POST request to `/login/fork` (lines 113-127 in nmextback.js) is part of the legitimate authentication flow. The extension sends a token to create a session fork, which is standard for SSO implementations.

### <all_urls> Permission
While broad, the `<all_urls>` content script permission is necessary for this extension to function on any Fabasoft Folio installation, which could be hosted on any domain in enterprise environments.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| help.folio.fabasoft.com | Help documentation | None (GET request via chrome.tabs.create) | LOW |
| `{domainhref}/login/fork` | Session authentication | Authentication token | MEDIUM |

The dynamic endpoint at `{domainhref}/login/fork` is constructed from data received from the native host (`message.outdata.domainhref`), making it configurable for different enterprise deployments. This introduces some risk if the native host is compromised, as it could redirect authentication tokens to malicious servers.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise tool from a reputable software vendor (Fabasoft R&D GmbH) with a clear business purpose. However, two medium-severity issues prevent a CLEAN rating:

1. **Cookie transmission**: The automatic collection and transmission of all cookies to the native host happens without explicit runtime user consent or notification. While necessary for the authentication workflow, this represents a privacy concern for users who may not fully understand that installing this extension grants cookie access to a native application.

2. **Unsafe postMessage patterns**: Using wildcard origins for postMessage() creates an attack surface where malicious scripts on compromised pages could intercept extension communications.

For enterprises deploying this extension with proper IT governance and network controls, these risks are mitigated. However, for general public availability in the Chrome Web Store, users should be clearly informed about the data sharing behavior. The extension does not exhibit malicious behavior and serves its stated purpose as a document management bridge, but the implementation could be hardened against potential abuse scenarios.

**Recommendations**:
- Implement origin validation for all postMessage() calls
- Add visible user notification about cookie sharing with native host
- Consider implementing Content Security Policy directives in the manifest
- Add explicit user consent flow before first cookie transmission
