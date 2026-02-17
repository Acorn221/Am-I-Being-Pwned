# Vulnerability Report: CrossWarpEX 확장

## Metadata
- **Extension ID**: icadabneccecohhaonmhgbjelhgodfaa
- **Extension Name**: CrossWarpEX 확장
- **Version**: 1.0.2.8
- **Publisher**: iniLINE Co., Ltd.
- **Users**: ~800,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

CrossWarpEX is a legitimate enterprise software integration tool developed by iniLINE Co., Ltd., a Korean software company. The extension serves as a bridge between web applications and a native application (kr.co.iniline.crosswarpex) using Chrome's nativeMessaging API. This is a common pattern for enterprise software that needs to interact with locally installed applications for tasks like file system access, hardware integration, or legacy system connectivity.

While the extension implements basic security measures such as input sanitization and tab-based access control, it contains a medium-severity dynamic function invocation vulnerability in the callback handler mechanism. The overall risk is classified as MEDIUM because the extension's functionality is limited to users who have intentionally installed both the extension and the companion native application, reducing the practical exploit surface.

## Vulnerability Details

### 1. MEDIUM: Dynamic Function Invocation via Window Accessor

**Severity**: MEDIUM
**Files**: contentscript.js (line 52)
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)

**Description**:
The extension's callback mechanism uses dynamic function invocation via the window object accessor pattern: `window[pcbfname](JSON.stringify(result.reply))`. The callback function name (`pcbfname`) is derived from data received from the native application through the extension's messaging system.

**Evidence**:
```javascript
// contentscript.js, lines 45-52
window.addEventListener('__crosswarpex_extension_setcallback__', function(event){
    var result = JSON.parse(document.getElementById("setcallback").getAttribute('result'));
    var pcbfname = pushcbfname;
    var pcbframeidx = pcbfname.lastIndexOf(".");
    if(pcbframeidx > 0){
        pcbfname = pcbfname.substring(pcbframeidx+1, pcbfname.length);
    }
    window[pcbfname](JSON.stringify(result.reply));  // Dynamic invocation
});
```

The callback name originates from web page requests:
```javascript
// contentscript.js, line 19
let pushcbfname = message.exfunc.args[0].callback;
```

While the background script attempts to sanitize callback strings (background.js, lines 234-264), this sanitization:
1. Only removes specific dangerous characters and keywords
2. Does not apply to the final function name extraction in contentscript.js
3. Can be bypassed if the native application returns manipulated callback names

**Verdict**:
The vulnerability allows arbitrary function invocation in the page context. However, exploitation requires:
- The user to have the native application installed
- The native application to be compromised or malicious
- The attacker to control or influence the native application's responses

Given that this is an intentionally-installed enterprise tool with a legitimate native messaging bridge, the practical risk is medium rather than high. The extension's design inherently trusts the native application, which is a conscious security trade-off in this architecture.

### 2. LOW: Insufficient Callback Sanitization

**Severity**: LOW
**Files**: background.js (lines 234-264)
**CWE**: CWE-20 (Improper Input Validation)

**Description**:
The extension uses string replacement (replaceAll) to sanitize callback parameters, attempting to filter out XSS-prone patterns. This approach is known to be bypassable and is not a robust defense mechanism.

**Evidence**:
```javascript
// background.js, lines 234-249
if(request.cmd == "native" && typeof request.callback == "string") {
    request.callback = request.callback.replaceAll("<", "");
    request.callback = request.callback.replaceAll(">", "");
    request.callback = request.callback.replaceAll("/", "");
    request.callback = request.callback.replaceAll("(", "");
    request.callback = request.callback.replaceAll(")", "");
    request.callback = request.callback.replaceAll("#", "");
    request.callback = request.callback.replaceAll("&", "");
    request.callback = request.callback.replaceAll(":", "");
    request.callback = request.callback.replaceAll("\"", "");
    request.callback = request.callback.replaceAll("'", "");
    request.callback = request.callback.replaceAll("javascript", "");
    request.callback = request.callback.replaceAll("document", "");
    request.callback = request.callback.replaceAll("onclick", "");
    request.callback = request.callback.replaceAll("onerror", "");
    return true;
}
```

**Verdict**:
While the sanitization provides some defense-in-depth, it's not comprehensive. However, since callbacks are ultimately invoked as function names (not eval'd as code), and the extension's threat model trusts the native application, this is classified as a low-severity code quality issue rather than a critical vulnerability.

## False Positives Analysis

### Broad Host Permissions and Content Script Injection
The extension requests `*://*/*` host permissions and injects content scripts on all pages at `document_start`. While this appears overly broad, it's required for the extension's legitimate functionality as a universal native messaging bridge. Enterprise integration tools need to work across all internal and external web applications that may require native app connectivity.

### Native Messaging to Unknown Application
The extension connects to `kr.co.iniline.crosswarpex`, which requires a separately installed native application. This is not malicious behavior - it's the core purpose of the extension. The security model of Chrome's nativeMessaging API assumes that users intentionally install both components.

### Tab Tracking and Management
The extension maintains a map of "managed" tabs (lines 89-90, 126-127 in background.js) and only accepts commands from initialized tabs. This is actually a security feature, not a vulnerability, preventing arbitrary pages from accessing the native messaging bridge without proper initialization.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | No external network communication | N/A | N/A |

The extension does not communicate with any external servers. All data flow is:
1. Web page → Content script → Background script → Native application
2. Native application → Background script → Content script → Web page

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension serves as a legitimate enterprise software integration bridge between web applications and a native application. The identified vulnerabilities stem from the extension's design pattern of dynamic callback invocation, which introduces code execution risks.

However, the practical risk is limited by several factors:

1. **Intentional Installation**: Users must deliberately install both the extension and the native application, indicating informed consent for the functionality.

2. **Limited Attack Surface**: Exploitation requires either:
   - Compromise of the native application itself
   - A malicious web page that has been granted access by user initialization
   - Neither scenario represents a drive-by or passive attack vector

3. **No Data Exfiltration**: The extension does not send data to external servers. All communication is local between the browser and native app.

4. **Enterprise Context**: With 800,000 users and a low 1.1 rating, this appears to be an enterprise-mandated tool rather than consumer software, suggesting organizational oversight and potentially acceptable risk in controlled environments.

5. **Security Features Present**: The extension implements tab-based access control, callback sanitization (albeit imperfect), and input validation, demonstrating security awareness.

**Recommendations**:

1. Replace dynamic function invocation (`window[funcname]()`) with a whitelist-based callback dispatcher
2. Implement Content Security Policy restrictions to limit inline script execution
3. Add stricter validation of callback names using allowlists rather than denylists
4. Consider requiring explicit user confirmation for callback registration
5. Implement logging of all native messaging calls for audit purposes

**Risk Classification**: The extension is rated MEDIUM rather than HIGH because the vulnerabilities require specific preconditions (native app installation, user initialization) and occur within an expected trust boundary for enterprise integration software. Organizations using this tool should ensure proper security controls around the native application component and restrict installation to trusted environments.
