# Vulnerability Report: 影刀

## Metadata
- **Extension ID**: nhkjnlcggomjhckdeamipedlomphkepc
- **Extension Name**: 影刀 (ShadowBot)
- **Version**: 1.1
- **Users**: ~400,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

影刀 (ShadowBot) is a Chrome browser automation extension that functions as a bridge between a native application (shadowbot.chrome.bridge) and the Chrome browser. The extension exposes extremely dangerous capabilities through arbitrary code execution via `eval()` triggered by messages from the native messaging host. With access to the debugger API, cookies, clipboard, all URLs, and the ability to execute arbitrary JavaScript in both background and content script contexts, this extension represents a complete browser takeover mechanism.

While this appears to be a legitimate automation/RPA (Robotic Process Automation) tool with 400,000 users, the security model is fundamentally broken. Any compromise of the native host application or man-in-the-middle attack on the native messaging channel would grant an attacker complete control over the user's browser, including access to all credentials, session tokens, browsing history, and the ability to execute arbitrary actions on any website.

## Vulnerability Details

### 1. CRITICAL: Arbitrary Code Execution via Native Messaging

**Severity**: CRITICAL
**Files**: background.static.js (line 70), content.static.js (line 4)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: Both the background and content scripts accept arbitrary JavaScript code via native messaging and execute it using `eval()` without any validation, sanitization, or restrictions.

**Evidence**:

Background script (background.static.js):
```javascript
'Extension.Init': (params) => {
    try {
        eval.call(window, params.code)
        nativeHost.response({
            content: null
        })
    } catch (error) {
        nativeHost.response({
            error: {
                code: -1,
                message: error.stack
            }
        })
        console.warn('extension init fail', error)
    }
}
```

Content script (content.static.js):
```javascript
function invoke(method, params) {
    try {
        if (method === 'init') {
            const result = eval.call(window, params.code)
            return { status: 'success', result: result }
        }
        // ...
    }
}
```

**Verdict**: This represents a complete compromise of browser security. The native messaging host can execute arbitrary JavaScript in both the privileged background context (with access to all Chrome APIs) and in the content script context of any webpage (with access to page DOM and credentials). Combined with the debugger permission, this allows complete browser control including:
- Reading/writing cookies from any domain
- Accessing clipboard contents
- Manipulating downloads
- Controlling browser windows and tabs
- Reading/modifying all webpage content
- Bypassing same-origin policy
- Accessing session storage, local storage, and IndexedDB

### 2. CRITICAL: Overprivileged Permission Set

**Severity**: CRITICAL
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests an extremely dangerous combination of permissions that, when combined with arbitrary code execution, provides total browser control.

**Evidence**:
```json
"permissions": [
    "cookies",
    "management",
    "tabs",
    "debugger",
    "nativeMessaging",
    "downloads",
    "webNavigation",
    "clipboardRead",
    "clipboardWrite",
    "<all_urls>"
]
```

Particularly concerning permissions:
- **debugger**: Allows attaching to and controlling any tab, injecting JavaScript, intercepting network traffic
- **management**: Can disable/uninstall other extensions
- **cookies**: Full access to authentication cookies across all domains
- **clipboardRead/clipboardWrite**: Access to sensitive clipboard data (passwords, tokens, etc.)
- **<all_urls>**: Content scripts injected into every webpage including file:// URLs

**Verdict**: While these permissions may be necessary for legitimate browser automation, they create an unacceptable attack surface when combined with the arbitrary code execution vulnerability. The debugger API alone is equivalent to developer tools access, allowing complete control over all browser tabs.

### 3. HIGH: Unsafe Content Security Policy

**Severity**: HIGH
**Files**: manifest.json (line 7)
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
**Description**: The extension uses 'unsafe-eval' in its CSP, which is required for the eval-based architecture but eliminates CSP protections against code injection.

**Evidence**:
```json
"content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"
```

**Verdict**: The 'unsafe-eval' directive is required for the extension's architecture but defeats the purpose of CSP. This means if there were any other injection vulnerabilities (e.g., XSS in the extension's pages), they could be exploited to execute arbitrary code in the extension context.

### 4. MEDIUM: No Origin Validation on Native Messaging

**Severity**: MEDIUM
**Files**: background.static.js (line 86-99)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension trusts all messages from the native messaging host without any validation of message structure, origin, or authentication tokens.

**Evidence**:
```javascript
conn.onMessage.addListener((message) => {
    if (message) {
        if (handlers[message.method] !== undefined) {
            handlers[message.method].call(window, message.params)
        } else {
            uiaDispatcher.invoke(message, (response) => {
                conn.postMessage(response);
            })
        }
    } else {
        console.error(`未知的消息格式, ${message}`)
    }
})
```

**Verdict**: While native messaging is generally considered secure (Chrome validates the native host binary), there's no additional authentication or integrity checking within the protocol itself. If the native host is compromised or spoofed, the extension blindly executes commands.

## False Positives Analysis

None. All identified vulnerabilities are genuine security concerns. While this extension appears to be a legitimate RPA/browser automation tool (based on the Chinese name "影刀" which translates to "Shadow Blade/Knife" and references to "ShadowBot"), the architecture is fundamentally insecure:

1. **Eval usage is intentional**: This is not obfuscated code or accidental eval usage - it's the core mechanism for remote control
2. **Permissions are used**: The debugger, cookies, and clipboard permissions are actively utilized
3. **No network exfiltration detected**: The extension doesn't make direct network requests, relying instead on the native host

However, these design choices create an unacceptable security risk for a browser extension with 400,000 users.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| shadowbot.chrome.bridge (native) | Native messaging host for browser automation commands | Window IDs, arbitrary eval results, extension version | CRITICAL - complete trust boundary |
| (None - no network endpoints) | - | - | - |

The extension does not make direct network requests. All communication is through native messaging to "shadowbot.chrome.bridge". However, this native host has unrestricted ability to execute arbitrary code in the browser, so any network activity could be performed indirectly through eval'd code.

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:

This extension implements a remote code execution backdoor in the user's browser, controlled by a native application. While it appears to be a legitimate automation tool, the security implications are severe:

1. **Complete Browser Control**: The combination of arbitrary code execution via eval, debugger API access, and <all_urls> permissions means the native host (or any attacker who compromises it) has total control over the browser
2. **Credential Theft Potential**: Full access to cookies, clipboard, and debugger API allows harvesting credentials from any website
3. **Large User Base**: With 400,000 users, a compromise would affect a significant population
4. **Attack Surface**: Any vulnerability in the native host application, the IPC channel, or the native messaging manifest could be exploited to gain browser control
5. **Persistence**: The extension auto-reloads all non-Chrome tabs on installation, ensuring malicious code would run across all user sessions

**Mitigating Factors**:
- The extension appears to be a legitimate RPA tool, not intentionally malicious
- Native messaging has some OS-level protections (binary signature validation)
- No evidence of actual malicious behavior or data exfiltration in the code

**Aggravating Factors**:
- Zero input validation on eval'd code
- Overly broad permission set
- No authentication or rate limiting on commands
- Content scripts run at document_start on all frames, maximizing attack surface
- CSP with unsafe-eval eliminates XSS protections

This extension should be considered a critical security risk regardless of its legitimate use case. The architecture violates fundamental browser security principles and creates an unacceptable attack surface. Users of this extension are one native host compromise away from complete browser takeover.
