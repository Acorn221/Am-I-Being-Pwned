# Vulnerability Report: INISAFE SmartManagerEX

## Metadata
- **Extension ID**: ligfpkgaijhppilphabeoligampecpce
- **Extension Name**: INISAFE SmartManagerEX
- **Version**: 1.0.2.3
- **Developer**: INITECH co., Ltd.
- **Users**: ~900,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

INISAFE SmartManagerEX is a native messaging bridge extension developed by INITECH co., Ltd., a South Korean security software company. The extension facilitates communication between web pages and a native application (`kr.co.initech.smartmanagerex`) for security and authentication purposes, commonly used in Korean enterprise and government environments.

While the extension serves a legitimate business purpose as an enterprise security tool, it presents significant security risks due to its privileged permissions, dynamic callback execution pattern, and reliance on the security posture of the native host application. The extension grants all websites the ability to invoke native code through a messaging bridge, with callback functions dynamically executed using `window[callback]()` - a pattern that could enable code execution if the native host is compromised or manipulated. The broad host permissions (`*://*/*`) combined with native messaging capabilities create a high-privilege attack surface.

## Vulnerability Details

### 1. HIGH: Dynamic Callback Execution via Native Host Response

**Severity**: HIGH
**Files**: contentscript.js (line 52)
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)

**Description**: The extension dynamically executes callback functions received from the native host using `window[pcbfname](JSON.stringify(result.reply))`. While the background script applies input sanitization to callback names (lines 234-264 in background.js), the sanitization can be bypassed, and the fundamental issue remains: callback function names originating from the native host are used to directly invoke functions from the global window scope.

**Evidence**:
```javascript
// contentscript.js lines 45-52
window.addEventListener('__smartmanagerex_extension_setcallback__', function(event){
    var result = JSON.parse(document.getElementById("setcallback").getAttribute('result'));
    var pcbfname = pushcbfname;
    var pcbframeidx = pcbfname.lastIndexOf(".");
    if(pcbframeidx > 0){
        pcbfname = pcbfname.substring(pcbframeidx+1, pcbfname.length);
    }
    window[pcbfname](JSON.stringify(result.reply));  // Dynamic function invocation
});
```

The background script sanitization (background.js lines 234-264):
```javascript
request.callback = request.callback.replaceAll("<", "");
request.callback = request.callback.replaceAll(">", "");
request.callback = request.callback.replaceAll("/", "");
request.callback = request.callback.replaceAll("(", "");
request.callback = request.callback.replaceAll(")", "");
// ... etc
request.callback = request.callback.replaceAll("javascript", "");
```

**Verdict**: HIGH severity. While sanitization is present, the pattern of dynamically invoking functions based on names from an external source (the native host) is inherently risky. If the native application is compromised or contains vulnerabilities, an attacker could potentially manipulate callback names to invoke arbitrary global functions. The sanitization uses simple string replacement which may be bypassable (e.g., "jajavascriptscript" becomes "javascript"). The security of this extension is fundamentally dependent on the security of the native host application.

### 2. HIGH: Unrestricted Native Messaging Bridge on All URLs

**Severity**: HIGH
**Files**: manifest.json (lines 24-30, 32), background.js (lines 59-157), inject.js (entire)
**CWE**: CWE-276 (Incorrect Default Permissions)

**Description**: The extension injects a native messaging bridge into all websites (`*://*/*`) via content scripts that run at `document_start` with `all_frames: true`. This allows any website to communicate with the native host application through the extension. While there is tab tracking logic (`managed_tabs`) that attempts to restrict access to initialized tabs, the broad injection surface combined with native code execution capabilities creates significant risk.

**Evidence**:
```json
// manifest.json
"content_scripts": [
    {
        "matches": ["*://*/*"],
        "js": ["inject.js"],
        "all_frames": true,
        "run_at": "document_start"
    }
],
"host_permissions": ["*://*/*"],
```

The native messaging logic in background.js:
```javascript
// Lines 65-104: Native host connection and message relay
if (request.cmd == "native" || request.cmd == "setcallback" || request.cmd == "init") {
    if (port == null) {
        port = chrome.runtime.connectNative(appid);  // kr.co.initech.smartmanagerex
        // ... message handling
    }
```

**Verdict**: HIGH severity. While this is standard behavior for enterprise security tools that need to monitor/protect all web activity, it creates a privileged bridge between arbitrary web content and native code. The extension attempts to implement access control via the `managed_tabs` Map (lines 126-132), requiring tabs to be initialized before accepting native commands, but the initialization process itself (lines 108-124) has a relatively weak validation through the `checkRequest()` function. An attacker who can satisfy the initialization requirements could potentially abuse the native messaging interface.

### 3. MEDIUM: Insufficient Origin Validation for Message Passing

**Severity**: MEDIUM
**Files**: inject.js (lines 12-32), contentscript.js (entire)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: Communication between the content script and injected page script uses custom DOM events with base64-encoded page URLs as event identifiers. While this provides some isolation, it doesn't implement proper origin validation. The event names are predictable (constructed from the page URL), and messages are relayed through DOM attributes without cryptographic integrity checks.

**Evidence**:
```javascript
// inject.js lines 8-10
const PREFIX = "smartmanagerex";
const EVENT_FROM_PAGE = "__" + PREFIX + "__rw_chrome_ext_" + btoa(pageurl);
const EVENT_REPLY = "__" + PREFIX + "__rw_chrome_ext_reply_" + btoa(pageurl);
```

Message relay via DOM attributes:
```javascript
// inject.js lines 16-18
var request = JSON.parse(transporter.getAttribute("data"));
transporter.removeAttribute("data");
request.id = transporter.id;
```

**Verdict**: MEDIUM severity. The event-based communication pattern using base64-encoded URLs provides basic isolation but could be vulnerable to same-origin attackers who can predict the event names and inject malicious messages. A malicious script on the same page could potentially intercept or forge messages. However, this is partially mitigated by the `checkRequest()` validation in the background script and the fact that the native host connection requires proper initialization.

### 4. LOW: Tab Management Information Disclosure

**Severity**: LOW
**Files**: background.js (lines 159-217, 279-281)
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**: The extension tracks tab navigation and closure events, sending this information to the native host application via `__tab_status__` function calls. This includes full URLs when tabs navigate (line 207: `request.exfunc.args = ["move", tab.url]`).

**Evidence**:
```javascript
// background.js lines 206-209
if (type == "update") {
    request.exfunc.args = ["move", tab.url];
} else {
    request.exfunc.args = ["close"];
}
```

**Verdict**: LOW severity. This is expected behavior for an enterprise monitoring/security tool. The native host needs to track which tabs are active to manage security contexts. However, this means full browsing history for managed tabs is sent to the native application, which users should be aware of. This is more of a privacy consideration than a vulnerability, appropriate for enterprise deployments but potentially concerning if users install it unknowingly.

## False Positives Analysis

1. **Native Messaging on All URLs**: While this appears extremely privileged, it's standard for enterprise security tools that need to provide authentication, encryption, or security services across all websites. Korean banking and government sites commonly require such extensions.

2. **Callback Sanitization**: The extensive string replacement in `checkRequest()` (lines 234-264) might appear primitive, but it's a deliberate defense-in-depth measure. While not perfect, it does block many common injection patterns.

3. **Web Accessible Resource**: The `contentscript.js` file is exposed as a web accessible resource, which might seem concerning. However, this is necessary for the injection pattern used (inject.js loads contentscript.js), and the file only contains bridge logic without sensitive data.

4. **Special Handling for misumi-ec.com**: Lines 66-83 in inject.js contain special injection logic for the misumi-ec.com domain. This is likely legitimate customization for a specific partner site requiring different timing for script injection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.initech.com | Homepage URL (manifest) | None (just reference) | None |
| Native Host: kr.co.initech.smartmanagerex | Local native messaging | Tab URLs, function calls, user interactions | HIGH - All privileged operations go through native host |

The extension makes no direct network requests. All functionality is mediated through the native host application (`kr.co.initech.smartmanagerex`), which means the security posture depends entirely on that native application.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While INISAFE SmartManagerEX serves a legitimate enterprise security purpose and is developed by an established security vendor (INITECH), it presents HIGH risk due to:

1. **Privileged Attack Surface**: The combination of `*://*/*` host permissions, native messaging capabilities, and injection into all frames creates a powerful and privileged interface. If either the extension or the native host application contains vulnerabilities, the impact would be severe.

2. **Dynamic Code Execution Pattern**: The `window[callback]()` pattern in contentscript.js (line 52) creates a code execution risk dependent on the security of the native host. While sanitization is present, it may be bypassable, and the fundamental design pattern is inherently risky.

3. **Dependency on Native Host Security**: The extension's security is entirely dependent on the native application's security. If the native host is compromised, has vulnerabilities, or is maliciously modified, attackers could leverage the extension's privileges to execute arbitrary code, intercept data, or manipulate web pages across all sites.

4. **Limited User Control**: With 900,000 users and a low 1.2 rating, this extension is likely deployed in enterprise environments where users may not have full understanding or control over its installation. The extensive privileges and monitoring capabilities should be clearly disclosed.

**Mitigating Factors**:
- This is a legitimate enterprise security tool from an established vendor
- Some input validation and sanitization is implemented
- Tab tracking attempts to limit access to initialized tabs
- Korean enterprises/government commonly require such tools for authentication

**Recommendation**: This extension is appropriate for controlled enterprise deployments where the native host application is properly secured and managed. Users should understand that it provides full website access and browsing monitoring to the native application. The dynamic callback execution pattern should be redesigned to use a whitelist of allowed callback functions rather than dynamic invocation based on names from the native host.
