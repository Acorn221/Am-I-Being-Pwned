# Vulnerability Report: Microsoft Power Automate (Legacy)

## Metadata
- **Extension ID**: gjgfobnenmnljakmhboildkafdkicala
- **Extension Name**: Microsoft Power Automate (Legacy)
- **Version**: 2.0.19
- **Users**: ~1,000,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Microsoft Power Automate (Legacy) is a legitimate browser automation extension developed by Microsoft for use with Power Automate Desktop (formerly WinAutomation/Robin). This extension enables Robotic Process Automation (RPA) by allowing a local desktop application to control the Chrome browser via native messaging.

The extension has powerful capabilities including arbitrary JavaScript execution and full browser control. However, these features are intentional and necessary for its RPA functionality. The extension communicates exclusively with a local native messaging host (`com.robin.messagehost`) and does not send data to external servers. While the code execution capabilities would be concerning in most extensions, they are legitimate and expected for this automation tool. The extension is being deprecated in favor of a Manifest V3 version for compatibility with future Chrome releases.

## Vulnerability Details

### 1. LOW: Arbitrary JavaScript Code Execution via Native Messaging

**Severity**: LOW
**Files**: content.js (lines 82-113), background.js (lines 227-250)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**:

The extension implements several handlers that allow arbitrary JavaScript code execution on web pages. The `RunScript` handler in content.js executes any script received from the native messaging host by dynamically creating script elements and injecting them into the page context. Additionally, there are handlers for injecting custom JavaScript libraries (`InjectOwnJavascriptLibrary`, `InjectOwnRuntimeJavascriptLibrary`, `InjectJavascriptLibrary`).

**Evidence**:

```javascript
// content.js - RunScript handler
communicator.on("RunScript", (message, responseFunction) => {
    try {
        var result = runScript(message.arg0);
        responseFunction({ result: result });
    }
    catch (e) {
        responseFunction({ err: 'Error ' + e + ' ' + e.stack });
    }
});

function runScript(scriptAsString) {
    var targetWnd = window;
    var targetDoc = window.document;
    var script = targetDoc.createElement('script');
    targetWnd._result = undefined;
    targetWnd._complete = false;
    targetWnd._timeout = 100;
    script.textContent = 'var result = undefined; try{ result = ' + scriptAsString + ';}catch(e){}; document.documentElement.setAttribute("result", result); document.documentElement.setAttribute("complete", "true");';
    (targetDoc.head || targetDoc.documentElement).appendChild(script);
    script.parentNode.removeChild(script);
    // ... result extraction code
}

// InjectOwnJavascriptLibrary handler
communicator.on("InjectOwnJavascriptLibrary", (message, responseFunction) => {
    try {
        var script = document.createElement('script');
        script.id = "WAJavascriptLib";
        script.textContent = message.arg0;
        (document.head || document.documentElement).appendChild(script);
        script.remove();
        responseFunction({});
    }
    catch (e) {
        responseFunction({ err: 'Error ' + e + ' ' + e.stack });
    }
});
```

**Verdict**:

While this code allows arbitrary JavaScript execution, it is a **legitimate design choice** for an RPA tool. The extension only accepts commands from the local native messaging host (`com.robin.messagehost`), which requires explicit OS-level permissions to install. This is equivalent to any local automation tool (like Selenium, Playwright, or Puppeteer) that can control the browser. The attack surface is limited to:

1. A compromised Power Automate Desktop installation on the user's machine
2. A malicious application masquerading as the native messaging host

Both scenarios require the attacker to already have significant access to the user's system, making this extension no more dangerous than the local application itself. This is a LOW severity issue rather than CLEAN because the extension does have powerful capabilities, but they are appropriately scoped for its intended purpose.

## False Positives Analysis

Several patterns in this extension would typically be red flags but are legitimate for an RPA automation tool:

1. **Broad host permissions (`<all_urls>`)**: Necessary for automating any website
2. **Content scripts on all pages with `document_start` timing**: Required to inject automation hooks before page load
3. **Dynamic script injection**: Core functionality for RPA to interact with page JavaScript context
4. **Native messaging**: The entire purpose of the extension is to bridge browser and desktop application
5. **Tab manipulation APIs**: Standard RPA features for opening, closing, and navigating tabs
6. **BrowsingData API**: Used for legitimate "clear cookies/cache" automation steps

The extension is transparent about its purpose (visible in the name and description), and users explicitly install it as part of Power Automate Desktop setup.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| com.robin.messagehost (Native Messaging) | Communication with Power Automate Desktop application | Tab events, window events, command responses | Low - Local only, requires explicit OS-level native messaging host installation |

**Note**: The extension does not communicate with any external HTTP/HTTPS endpoints. All communication is via Chrome's native messaging protocol to a local application.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise RPA tool developed by Microsoft. While it has powerful capabilities including arbitrary code execution and full browser control, these are intentional design features necessary for its automation purpose. The extension:

1. ✅ Is developed and signed by Microsoft
2. ✅ Has a clear, legitimate purpose (browser automation for RPA)
3. ✅ Only communicates with a local native messaging host, not external servers
4. ✅ Requires explicit user installation of both the extension and native host
5. ✅ Does not collect or exfiltrate user data
6. ✅ Has appropriate permissions for its stated functionality
7. ✅ Uses TypeScript/clean code patterns (not obfuscated)

The LOW rating (rather than CLEAN) reflects that the extension does have powerful capabilities that could be abused if the local Power Automate installation were compromised. However, this is comparable to the risk of any local automation tool and is not a vulnerability in the extension itself.

**Recommendation**: Users should ensure they download Power Automate Desktop only from official Microsoft sources and keep it updated. The extension itself poses minimal additional risk beyond the desktop application it's designed to work with.
