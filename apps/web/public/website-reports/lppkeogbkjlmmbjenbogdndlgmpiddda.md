# Vulnerability Report: Ntko office document control browser plug-in.

## Metadata
- **Extension ID**: lppkeogbkjlmmbjenbogdndlgmpiddda
- **Extension Name**: Ntko office document control browser plug-in.
- **Version**: 1.8.7
- **Users**: ~800,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a native messaging bridge that enables web pages to interact with a native "Ntko office document control" application (com.ntko.extensionsoffice) for Office document editing functionality. While the functionality appears legitimate, the implementation contains serious security vulnerabilities that expose sensitive user data to any website through an insecure postMessage API. The extension automatically harvests all cookies for the current tab and transmits them to the native application whenever a connection is established, without explicit user consent or awareness. The combination of wildcard host permissions (`http://*/`, `https://*/`), cookie access, and an origin-unchecked postMessage handler creates a significant attack surface that could be exploited by malicious websites.

The extension runs a content script on all frames of all websites (`*://*/*`) that relays messages between the web page and the service worker, which in turn communicates with the native application. Any website can trigger this bridge by posting messages with the type `FROM_NTKO_PAGE`, allowing arbitrary sites to initiate connections, retrieve cookies, and send data to the native application.

## Vulnerability Details

### 1. HIGH: Insecure postMessage API Without Origin Validation

**Severity**: HIGH
**Files**: background/ntko-background.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The content script accepts postMessage communications from any origin without validation. The event listener checks only that `event.source == window` but does not verify `event.origin`, allowing any website to send messages that will be forwarded to the service worker and native application.

**Evidence**:
```javascript
window.addEventListener("message", function(event) {
  if ( event.source != window )
    return;

  if (event.data.type && (event.data.type == "FROM_NTKO_PAGE")) {
    chrome.runtime.sendMessage( event.data.text );
  }
}, false);
```

The response path is equally insecure, broadcasting messages to all websites:
```javascript
chrome.runtime.onMessage.addListener( function( response )
{
  var jsonValue = JSON.stringify(response);
  if ( ( typeof jsonValue != "undefined" ) && ( (null != jsonValue) && ("" != jsonValue) ) )
    window.postMessage({ type: "FROM_NTKO_CONTEXT_PAGE", text: jsonValue }, "*");
});
```

**Verdict**: This allows any malicious website to communicate with the native application bridge by simply posting messages with the correct type. Combined with the cookie harvesting functionality, this creates a severe attack vector.

### 2. HIGH: Automatic Cookie Harvesting and Transmission to Native Application

**Severity**: HIGH
**Files**: background/background.js (lines 250-296)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: When a connection to the native application is opened, the extension automatically retrieves ALL cookies for the current tab URL and transmits them to the native messaging application without explicit user consent or notification.

**Evidence**:
```javascript
chrome.cookies.getAll({url: tab.url}, function(cookies)
{
  var varCookiesValue = "";
  for (var i in cookies)
  {
    if( 0 != i )
      varCookiesValue +=  "; ";
    varCookiesValue += cookies[i].name;
    varCookiesValue += "=";
    varCookiesValue += cookies[i].value;
    if(varcookiesDomainPath){
      if ( ( typeof cookies[i].domain != "undefined" ) && ( (null != cookies[i].domain) && ("" != cookies[i].domain) ))
      {
        varCookiesValue +=  ";Domain=";
        varCookiesValue += cookies[i].domain;
      }
      if (( typeof cookies[i].path != "undefined" ) && ( (null != cookies[i].path) && ("" != cookies[i].path) ))
      {
        varCookiesValue +=  ";Path=";
        varCookiesValue += cookies[i].path;
      }
    }
  }

  JsonObject["SessionURL"] = tab.url;
  if( 0 != varCookiesValue.length )
    JsonObject["Cookie"] = varCookiesValue;
  JsonObject["Referer"] = tab.url;

  var jsonValue = JSON.stringify(JsonObject);
  sendmessage( varGUID, varURLMd5, jsonValue );
});
```

**Verdict**: While this may be necessary for the document control functionality (to authenticate with document servers), the automatic, transparent collection and transmission of all cookies to a native application represents a significant privacy concern. Any website can trigger this by exploiting the postMessage vulnerability, potentially stealing session cookies for other domains.

### 3. MEDIUM: Broadcast Messaging to All Tabs Without Context

**Severity**: MEDIUM
**Files**: background/background.js (lines 20-41, 114-136)
**CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)

**Description**: When receiving responses from the native application, the service worker broadcasts messages to ALL open tabs rather than only to the tab that initiated the connection. This could leak information between different web contexts.

**Evidence**:
```javascript
chrome.tabs.query({}, function(tabs){
  for( let tab of tabs )
  {
    var varReturnResponse = response;
    var vData = varReturnResponse["content"];
    // ... process data ...
    chrome.tabs.sendMessage( tab.id, vData );
  }
});
```

**Verdict**: While the code attempts to match connections using GUID identifiers, the broadcast-to-all-tabs approach creates unnecessary cross-context exposure. A malicious website in one tab could potentially receive data intended for another tab if GUID collisions occur or if the native application sends unexpected messages.

## False Positives Analysis

The extension's core functionality is legitimate - it serves as a bridge between web pages and a native Office document control application (likely for online document editing with ActiveX-style controls). The cookie harvesting, while concerning from a privacy perspective, may be necessary for the document control to authenticate with document servers. However, the lack of origin validation in the postMessage handler and the automatic nature of cookie transmission without user awareness elevate this from a privacy concern to a security vulnerability.

The extension does not appear to be outright malicious - the native messaging host is clearly identified (com.ntko.extensionsoffice), and the functionality aligns with the stated purpose. However, the insecure implementation creates exploitable attack vectors.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Messaging: com.ntko.extensionsoffice | Communication with native document control | Cookies, tab URL, referer, user data from web pages | HIGH - Sensitive session data transmitted to native app |
| Native Messaging: com.ntko.extensionsoffice2 | Edge browser variant of native messaging | Same as above | HIGH - Same security concerns |

No external HTTP/HTTPS endpoints are contacted directly by the extension. All data flows are between the web page, extension, and native application.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While the extension serves a legitimate enterprise document editing purpose, it contains serious security vulnerabilities that expose user data to potential theft. The combination of:

1. Wildcard host permissions on all HTTP/HTTPS sites
2. Automatic cookie harvesting without user consent
3. Insecure postMessage API allowing any website to trigger native messaging connections
4. Broadcast messaging that could leak data between tabs

Creates a high-risk scenario where a malicious website could:
- Trigger connections to the native application without user awareness
- Steal session cookies for the current domain
- Potentially intercept data intended for other tabs
- Abuse the native messaging bridge for unintended purposes

The 800,000 user base and 1.0 rating suggest this is a widely-deployed enterprise tool, making the security implications more severe. The vulnerabilities are not theoretical - they are directly exploitable by any website a user visits while the extension is installed.

**Recommendations**:
1. Implement strict origin validation in the postMessage handler (whitelist specific domains)
2. Require explicit user consent before transmitting cookies to the native application
3. Target messages to specific tabs rather than broadcasting to all tabs
4. Add visual indicators when the native messaging bridge is active
5. Consider implementing a permission prompt or confirmation dialog for sensitive operations
6. Restrict host permissions to only domains that actually need the document control functionality
