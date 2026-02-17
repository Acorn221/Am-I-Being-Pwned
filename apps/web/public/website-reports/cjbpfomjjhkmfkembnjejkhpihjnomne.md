# Vulnerability Report: Oracle Smart View for Office

## Metadata
- **Extension ID**: cjbpfomjjhkmfkembnjejkhpihjnomne
- **Extension Name**: Oracle Smart View for Office
- **Version**: 23.11.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Oracle Smart View for Office is a legitimate enterprise extension that bridges Chrome with Oracle's Smart View desktop application via native messaging. The extension implements a communication channel between web pages and a native host application using sessionStorage as a relay mechanism. While the extension serves a legitimate business purpose, it contains a medium-severity vulnerability: the content script's postMessage event listener does not validate message origins, allowing any web page to potentially trigger native messaging operations and cookie manipulation. This is concerning given the extension's broad `<all_urls>` content script injection and `*://*/*` host permissions.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content-script.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script registers a window message event listener at line 43 without validating the origin of incoming messages. While the handler reads from sessionStorage rather than directly processing the event data, this creates a race condition where any malicious web page could potentially influence the sessionStorage state that triggers native messaging.

**Evidence**:
```javascript
// content-script.js:43
window.addEventListener('message', onWindowMessage, false);

function onWindowMessage(evt) {
    var msg = null;
    try {
        msg = sessionStorage.getItem(storageIdRx);
    } catch (err) {
        console.error('[Smart View failed to read session storage] ' + err);
        return;
    }

    if (msg !== null && msg !== emptyMessage)
    {
        sessionStorage.setItem(storageIdRx, emptyMessage);
        try {
            var obj = JSON.parse(msg);
            if (obj && obj.context && obj.data) {
                chrome.runtime.sendMessage(obj, onMessageFromBG);
            }
        } catch (err) {
            console.error('[Smart View failed to process a web page message] '+err+' : '+msg);
        }
    }
}
```

The handler checks sessionStorage on every message event, and if valid data is found (containing `context` and `data` properties), it forwards this to the background service worker via `chrome.runtime.sendMessage`. The background worker then routes this to the native messaging host (`com.oracle.smartview.nmh`).

**Verdict**: This design pattern is vulnerable to timing attacks where a malicious page could set sessionStorage values and trigger the message event to initiate native messaging calls. However, exploitation requires:
1. The Oracle Smart View native host to be installed
2. The target page to be using this extension's sessionStorage keys
3. Knowledge of the expected message format

The risk is mitigated by the fact that this is an enterprise extension with a specific native host dependency, limiting the attack surface to environments where Smart View is deployed.

### 2. MEDIUM: Unrestricted Cookie Manipulation via Background Script

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-942 (Overly Permissive Cross-domain Whitelist)
**Description**: The background script's message handler accepts cookie-setting requests from content scripts without validating the origin or domain of the cookies being set. Combined with the postMessage vulnerability, this could allow malicious pages to set cookies on arbitrary domains.

**Evidence**:
```javascript
// background.js:21-56
chrome.runtime.onMessage.addListener(
    function(data, sender, sendResponse) {
        // ... native messaging handling ...
        } else {
            let cookieArray = data.value.split(',')
            for (let i = 0; i < cookieArray.length; i++) {
                let currCookie = cookieArray[i].split(';').map(s=>s.trim());
                let cNameAndVal = currCookie[0].split('=');
                let currDetails = {
                    url: data.url,
                    name: cNameAndVal[0],
                    value: cNameAndVal[1]
                };
                // ... parse cookie attributes ...
                chrome.cookies.set(currDetails,
                    function (cookie) {
                        if (i == (cookieArray.length - 1))
                            chrome.runtime.sendMessage('FpAR5GW8pSh74hWy');
                    });
            }
        }
    }
);
```

The code accepts a `data.url` and `data.value` from any message sender and uses them to set cookies. The `cookies` permission combined with `*://*/*` host permissions means this could theoretically set cookies on any domain.

**Verdict**: While concerning, this functionality appears designed for the legitimate Smart View workflow where the native application needs to set authentication cookies for Oracle services. The risk is primarily theoretical since exploitation requires both the postMessage vulnerability and knowledge of Oracle's specific cookie format.

## False Positives Analysis

The following patterns appear security-concerning but are legitimate for this extension type:

1. **declarativeNetRequest redirect rule**: The extension redirects URLs matching `b46a546434d04b2999833265bbb49462=` to an internal `redir.html` page. This is not ad injection or malicious redirection—it's part of the Smart View protocol for handling data passed from the desktop application to web applications.

2. **Native messaging to `com.oracle.smartview.nmh`**: All communication with the native host is legitimate—this is the core purpose of the extension. The native host acts as a secure bridge to the Oracle Smart View desktop application.

3. **Base64 decoding in redir.js**: The extension decodes base64-encoded form data (`window.atob(response.link.data)`) which is passed in URL parameters. This is not code injection—it's legitimate data transfer from the native application.

4. **sessionStorage as communication channel**: Using sessionStorage events to communicate between the content script and web page appears unusual but is a deliberate design pattern to avoid direct postMessage coupling.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | This extension does not make external network requests | N/A | N/A |

The extension operates entirely through native messaging (`com.oracle.smartview.nmh`) and does not contact any external APIs or servers. All data flows are between the extension, web pages, and the local Oracle Smart View desktop application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate Oracle enterprise product with a legitimate use case (bridging browser and desktop application). However, the postMessage event listener without origin validation creates a real vulnerability that could allow malicious web pages to trigger native messaging operations when Smart View is installed. The impact is limited by the enterprise deployment context and native host dependency, but the vulnerability is genuine and should be addressed.

**Recommendations**:
1. Add origin validation to the postMessage event listener in content-script.js
2. Consider restricting host permissions to specific Oracle domains rather than `*://*/*`
3. Validate sender context in the background script's message handler to ensure messages originate from trusted sources
4. Consider implementing a more secure communication pattern between web pages and the content script

**Risk Classification Notes**:
- This is rated MEDIUM rather than HIGH because exploitation requires the Oracle Smart View native host to be installed (limiting attack surface to enterprise environments)
- The vulnerability is real but has limited practical exploitability
- Oracle's legitimate business purpose and enterprise deployment model provide additional security context
