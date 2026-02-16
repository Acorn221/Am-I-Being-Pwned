# Vulnerability Report: M-Files for Chrome

## Metadata
- **Extension ID**: lapmgejioldofnecdomcdgblbiffefhb
- **Extension Name**: M-Files for Chrome
- **Version**: 2.1.1
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

M-Files for Chrome is an enterprise document management extension that integrates Chrome with M-Files document management systems via native messaging. The extension enables web applications to interact with locally installed M-Files software for document handling. While the extension implements a trust-based security model with user consent prompts and site blacklisting, it contains a medium-severity postMessage vulnerability that could allow malicious pages to communicate with the extension before trust is established. The extension accesses cookies from all trusted sites and uses broad host permissions, which is appropriate for its enterprise use case but requires careful security implementation.

The extension's architecture includes a trust verification system where users must explicitly allow sites to use the extension, maintains a list of blacklisted pages that should never have access, and bridges communication between web pages and native M-Files software. However, the postMessage listener lacks origin validation, creating a potential attack surface for malicious content injection.

## Vulnerability Details

### 1. MEDIUM: postMessage Listener Without Origin Validation

**Severity**: MEDIUM
**Files**: contentscripts/page.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script registers a window.addEventListener("message") handler on line 48 without validating the event origin. While the extension has a trust system in place, the message listener is registered after trust is established and does not validate that messages come from the expected source.

**Evidence**:
```javascript
// contentscripts/page.js:48
window.addEventListener( "message", function( e ) {
    if( e.data.type && e.data.type == "NativeFuncCall" ) {
        var msg = e.data;
        msg.Action = msg.methodName;
        msg.callbackRes = "";
        msg.callbackIndex = e.data.callbackIndex;
        msg.callbackType = e.data.callbackTyp;
        msg.ChormeExtnVersion = chrome.runtime.getManifest().version;

        // Sending a message to the Chrome extension to call the required method.
        chrome.runtime.sendMessage( msg, function( response ) {
            if( ! response ) {
                // The error should have been logged in the extension.
            }
        } );
    }
});
```

**Verdict**: While the background script validates trust before processing native calls, the postMessage listener itself does not check `e.origin`. This creates a window where a malicious iframe on a trusted page could send messages that appear to originate from the page context. The background script's trust check (in `isTrusted()` function) only validates the sender.url of the content script, not the origin of the postMessage event. This is partially mitigated by the trust system and the fact that only pages with `id="mfwa"` or `id="mfwaChromeExtn"` elements will initialize the listener (lines 21-23).

### 2. MEDIUM: Dynamic Script Injection via CustomEvent

**Severity**: MEDIUM
**Files**: script.js, contentscripts/page.js
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension dynamically injects and evaluates arbitrary JavaScript code received from the native messaging host via a CustomEvent mechanism.

**Evidence**:
```javascript
// contentscripts/page.js:210-212
var injectedFuncCode = functionName + "(" + paramsInString + ");";
document.dispatchEvent( new CustomEvent( "addfunction", {detail: injectedFuncCode} ) );

// script.js:12-26
document.addEventListener( "addfunction", function( info ) {
    var script = document.createElement( "script" );
    script.appendChild( document.createTextNode( "document.getElementById ('hidFuncRes').value = " + info.detail) );
    ( document.body || document.head || document.documentElement ).appendChild( script );
    var res = document.getElementById( "hidFuncRes" ).value;
    script.parentElement.removeChild( script );
    return res;
} );
```

**Verdict**: This pattern allows the native application to execute arbitrary JavaScript in the page context by invoking page functions with parameters. While this is by design for the M-Files integration, it creates a code execution pathway controlled by data from the native messaging host. This is appropriate for an enterprise tool where users install both the extension and the native application, but represents a trust boundary where compromised native software could inject malicious code. The risk is mitigated by the requirement that users must install both components and explicitly trust sites.

### 3. LOW: Broad Cookie Access on Trusted Sites

**Severity**: LOW
**Files**: main.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension reads all cookies from trusted sites and forwards them to the native messaging host.

**Evidence**:
```javascript
// main.js:641-671
if( !isInternalMessageAction( msg.Action ) && getSite( currentURL.origin + "/" ) && chrome.cookies ) {
    chrome.cookies.getAll( { url: currentURL.origin }, function( cookies ) {
        var newCookies = '';
        for( var i=0; i < cookies.length; i++ ) {
            var currentCookies = cookies[ i ].name + '=' + cookies[ i ].value;
            if( newCookies == "" ) {
                newCookies = currentCookies;
            } else {
                newCookies = newCookies + ";" + currentCookies;
            }
        }
        if( msg.header ) {
            msg.header.Cookie = newCookies;
        }
        port.postMessage( msg );
        return true;
    });
}
```

**Verdict**: The extension collects all cookies from trusted sites and sends them to the native messaging host. This is necessary for M-Files authentication and session management but represents a significant trust boundary. If the native application were compromised, it would have access to all cookies from M-Files sites. This is acceptable for an enterprise tool where the native application is trusted software, but users should be aware that trusting a site grants the native application access to that site's cookies.

## False Positives Analysis

**Obfuscation Flag**: The static analyzer flagged this extension as "obfuscated", but examination of the code shows this is standard minified/bundled JavaScript, not malicious obfuscation. The code is readable after deobfuscation and follows clear enterprise software patterns.

**Native Messaging**: The use of `chrome.runtime.connectNative()` and `chrome.runtime.sendNativeMessage()` is legitimate for this extension's purpose of bridging Chrome with desktop M-Files software. This is a standard pattern for enterprise Chrome extensions that need to interact with native applications.

**Broad Host Permissions**: The `http://*/*` and `https://*/*` permissions are necessary because M-Files can be deployed on any domain, and the extension needs to support arbitrary customer deployments. This is appropriate for enterprise document management software.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cdn.m-files.com/public/Add-ons/M-Files_for_Chrome/M-Files-for-Chrome.exe | Download link for Windows native component | None (link only) | LOW - Legitimate download |
| cdn.m-files.com/public/Add-ons/M-Files_for_Chrome/M-Files-for-Chrome.zip | Download link for macOS native component | None (link only) | LOW - Legitimate download |

## Security Mechanisms

The extension implements several security features:

1. **Trust-Based Access Control**: Sites must be explicitly trusted by the user via notification prompts before they can use the extension's native messaging features.

2. **Page Blacklisting**: Specific pages are blacklisted and cannot access full extension features even on trusted sites, including: openfile.aspx, login.aspx, configuration.aspx, and other public-facing pages that shouldn't need native access.

3. **MFWA Detection**: The extension only initializes on pages that advertise themselves with `id="mfwa"` or `id="mfwaChromeExtn"` elements, limiting the attack surface.

4. **Internal Method Protection**: Internal methods like getSiteList and deleteSite can only be called from extension pages, not external sites.

5. **IndexedDB for Trust Storage**: Trusted sites are stored in IndexedDB rather than localStorage for better data isolation.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: M-Files for Chrome is a legitimate enterprise document management extension with appropriate permissions for its use case. The primary security concern is the postMessage listener without origin validation, which creates a potential avenue for malicious iframes on trusted pages to send messages to the extension. However, this risk is partially mitigated by:

- The requirement for explicit user trust via notification prompts
- Page-level blacklisting of sensitive pages
- MFWA element detection limiting which pages initialize the listener
- Background script trust validation before processing native calls

The extension's broad permissions (all hosts, cookies, native messaging) are appropriate for an enterprise tool that needs to integrate with arbitrary M-Files deployments, but represent a significant trust boundary. The cookie forwarding to the native application and dynamic script injection are by-design features for M-Files integration but require users to trust both the extension and the native application.

This extension is appropriate for enterprise environments where IT departments deploy both the extension and native software, but individual users should understand that granting trust to a site gives the native M-Files application access to that site's cookies and the ability to execute JavaScript on the page.

**Recommendation**: Add origin validation to the postMessage listener to ensure messages come from the expected page context, not malicious iframes. Consider using a more restrictive CSP and validating the MFWA.NativeAPI object exists before executing script.js functionality.
