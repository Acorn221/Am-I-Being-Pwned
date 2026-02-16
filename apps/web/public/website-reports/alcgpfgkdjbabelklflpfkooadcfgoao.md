# Vulnerability Report: Fabasoft Client

## Metadata
- **Extension ID**: alcgpfgkdjbabelklflpfkooadcfgoao
- **Extension Name**: Fabasoft Client
- **Version**: 25.11.0.74
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Fabasoft Client is a legitimate enterprise document management extension that bridges web-based Fabasoft applications with native desktop clients through Chrome's native messaging API. The extension runs on all URLs and acts as a conduit between web pages and the native Fabasoft application installed on the user's computer.

While the extension serves a legitimate enterprise purpose, it contains a security vulnerability in its postMessage event handler that lacks proper origin validation. This could potentially allow malicious websites to inject commands into the extension's communication channel, though the impact is mitigated by the requirement for a native Fabasoft application to be installed and the subsequent validation that occurs at the native layer.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: nmext.js:224
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The content script implements a `window.addEventListener("message")` handler that does not perform adequate origin validation before processing messages. While the code does store and validate the `windoworigin` after the first message is received (line 228-229, 257-258), the initial message from any website can establish this origin. This creates a race condition where the first page to send a properly formatted message establishes trust.

**Evidence**:
```javascript
window.addEventListener("message", el = async (event) => {
  if (event.source !== window) {
    return;
  }
  if (windoworigin && event.origin !== windoworigin) {
    return;
  }
  var data = event.data;
  var typeprefix = "com.fabasoft.nm.send";
  if (data.type && data.type.startsWith(typeprefix)) {
    // Process message...
  }
  // ...
  if (!windoworigin) {
    windoworigin = event.source.origin || event.source.location.origin;
    // console.log("com.fabasoft.nm/pm21/nmext: Extension content script initialize window origin: " + windoworigin);
  }
```

The vulnerability exists because:
1. The content script runs on `<all_urls>` at `document_start`
2. Any website can send a postMessage with `type: "com.fabasoft.nm.send*"`
3. The first valid message from any origin establishes trust for that tab
4. Subsequent messages from that origin are forwarded to the background script and native host

**Verdict**:
This is a MEDIUM severity issue rather than HIGH because:
- The extension's purpose is to communicate with trusted Fabasoft domains
- The native messaging host likely performs its own validation
- Exploitation requires the user to have the native Fabasoft client installed
- The message format is non-trivial and domain-specific
- Each tab maintains its own isolated origin tracking

However, it remains a genuine vulnerability because a malicious site could potentially:
- Win the race condition to establish origin trust
- Send crafted messages to probe the native application
- Potentially trigger unintended behavior if the native host has exploitable command handlers

### 2. LOW: Cookie Access with Broad Host Permissions

**Severity**: LOW
**Files**: nmextback.js:492-583
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The background script accesses cookies from all URLs visited by the user and forwards them to the native messaging host. While this appears to be necessary for the extension's legitimate function (forwarding authentication cookies to the native Fabasoft client), the combination of `cookies` permission and `<all_urls>` host permission means the extension can technically access cookies from any domain.

**Evidence**:
```javascript
async function postMessageWithCookies(data, contentport, contentportid, typesuffix) {
  var stores = await chrome.cookies.getAllCookieStores();
  var cookies = await chrome.cookies.getAll({url:data.srcurl, storeId:storeid});
  var cookievalues = {};
  // ... cookie processing ...
  data.indata.cookies = cookiestr;
  nativeports[typesuffix].port.postMessage(data);
}
```

**Verdict**:
This is rated LOW rather than MEDIUM/HIGH because:
- The extension only accesses cookies when explicitly requested via the native messaging protocol
- Cookies are only sent to the local native application, not to remote servers
- This functionality is necessary for the extension's stated purpose (SSO with native client)
- The extension is from a legitimate enterprise software vendor (Fabasoft)
- Users installing this extension likely understand it's for deep integration with Fabasoft systems

## False Positives Analysis

Several patterns in this extension might appear suspicious but are legitimate for this extension type:

1. **Native Messaging**: The use of `nativeMessaging` permission and `chrome.runtime.connectNative()` is expected for an extension that bridges web and native applications.

2. **Broad Permissions**: The `<all_urls>` permission is necessary because Fabasoft installations can be hosted on various domains, and the extension needs to detect and interact with Fabasoft web applications wherever they're deployed.

3. **Cookie Access**: While accessing cookies broadly could be concerning, it's necessary for this extension to provide single sign-on between the web application and native client.

4. **postMessage Communication**: The use of window.postMessage is a standard pattern for content script to page communication and is appropriate here.

5. **Web Accessible Resources**: The `installed.js` and `register.js` files are intentionally exposed to allow web pages to detect the extension's presence, which is a standard pattern for browser-native integration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | This extension does not communicate with remote servers | N/A | NONE |

**Note**: The extension only communicates with a local native messaging host (`com.fabasoft.nmhostpm21`). No network requests are made directly by the extension code. The native host may make its own network connections, but that's outside the scope of this extension analysis.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The Fabasoft Client extension serves a legitimate enterprise purpose and is developed by a reputable software company. However, it contains a genuine security vulnerability in the form of inadequate origin validation in its postMessage handler. While the practical exploitability is limited by several factors (need for native client installation, native-side validation, complex protocol), the vulnerability represents a real attack surface that could potentially be exploited by a malicious website to interact with the user's native Fabasoft client.

The cookie access functionality, while broad in scope, is appropriate for the extension's stated purpose and the data is only sent to the local native application rather than remote servers.

**Recommendations**:
1. **Fix Origin Validation**: The extension should validate the message origin against a whitelist of trusted Fabasoft domains before establishing the `windoworigin` trust relationship.
2. **Consider Content Security Policy**: Add additional CSP restrictions if possible.
3. **Document Security Model**: Clearly document which domains are trusted for native messaging integration.

**Target Audience**: This extension is clearly intended for enterprise users who have Fabasoft's document management system deployed. For its target audience and use case, the risk is acceptable with the understanding that the postMessage vulnerability should be patched.
