# VULN_REPORT: INISAFE CrossWeb EX

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | INISAFE CrossWeb EX |
| Extension ID | dheimbmpmkbepjjcobigjacfepohombn |
| Version | 1.0.2.3 |
| Author | INITECH co., Ltd. |
| Users | ~4,000,000 |
| Manifest Version | 3 |
| Homepage | http://www.initech.com/ |

## Executive Summary

INISAFE CrossWeb EX is a Korean PKI/banking security middleware extension by INITECH, widely deployed across South Korean financial institutions. It acts as a bridge between web pages and a native messaging host (`kr.co.iniline.crosswebex`) to provide certificate-based authentication and cryptographic operations required by Korean banking regulations.

The extension injects a content script into every page on every URL at `document_start` in all frames. This content script exposes a `crosswebex_nativecall()` function to page-level JavaScript, which can send arbitrary commands to the native messaging host via the extension's background service worker. While this architecture is inherently risky, it is the standard design pattern for Korean banking security extensions and serves a legitimate regulated purpose.

Several security concerns exist around input validation and the broad attack surface, but no malicious behavior, data exfiltration, remote config/kill switches, or obfuscation was found.

## Vulnerability Details

### VULN-01: Web Page to Native Host Message Relay with Weak Validation
- **Severity:** MEDIUM
- **Files:** `background.js` (lines 59-157), `contentscript.js`, `inject.js`
- **Description:** Any web page can call `crosswebex_nativecall()` (injected via `contentscript.js` into the page context as a web-accessible resource) to send messages to the native messaging host. The background script validates message structure via `checkRequest()` but the validation is shallow -- it checks for non-empty fields (`cmd`, `exfunc`, `module`, `origin`, `id`) but does not whitelist specific function names, module names, or argument values. Any website can invoke native host functions if it constructs a properly-formatted message.
- **Code:**
```javascript
// contentscript.js - exposed to page context
function crosswebex_nativecall(message, callback) {
    // Any page JS can call this function
    // Messages are relayed to extension -> native host
}
```
```javascript
// background.js - only checks structure, not content
if (request.cmd == "native" || request.cmd == "setcallback" || request.cmd == "init") {
    // Forwards to native host with minimal validation
    port.postMessage(json);
}
```
- **Verdict:** MEDIUM -- While the native host itself should perform its own authorization checks, the extension provides minimal gatekeeping. This is a wide attack surface that relies on the native component for security. However, the `managed_tabs` check (line 126) does restrict `native` commands to tabs that have previously completed initialization, which provides some protection.

### VULN-02: Bypassable Callback Sanitization (Denylist Approach)
- **Severity:** MEDIUM
- **Files:** `background.js` (lines 234-265)
- **Description:** The `checkRequest()` function sanitizes the `callback` field using a denylist approach, stripping characters like `<`, `>`, `/`, `(`, `)`, and keywords like `javascript`, `document`, `onclick`, `onerror`. This is a weak sanitization pattern that can potentially be bypassed with encoding tricks, case variations, or unlisted dangerous patterns. An allowlist approach would be more secure.
- **Code:**
```javascript
request.callback = request.callback.replaceAll("javascript", "");
request.callback = request.callback.replaceAll("document", "");
request.callback = request.callback.replaceAll("onclick", "");
request.callback = request.callback.replaceAll("onerror", "");
```
- **Verdict:** MEDIUM -- The denylist is fragile. However, the callback value is ultimately used as an event name prefix for custom DOM events (not evaluated as code directly), which limits exploitability.

### VULN-03: Tab URL Sent to Native Host on Navigation
- **Severity:** LOW
- **Files:** `background.js` (lines 193-217)
- **Description:** When a managed tab navigates, the `navigatePage()` function sends the full `tab.url` to the native messaging host. This means the native application receives the complete URLs of pages the user visits in managed tabs.
- **Code:**
```javascript
request.exfunc.args = ["move", tab.url];
// ...
port.postMessage(request);
```
- **Verdict:** LOW -- This is limited to tabs that have initiated a CrossWeb session (managed_tabs), not all tabs. It is part of the session management lifecycle. However, it does send browsing URLs to a local native application.

### VULN-04: Hardcoded Domain Exception (misumi-ec.com)
- **Severity:** LOW
- **Files:** `inject.js` (line 66)
- **Description:** There is a hardcoded special case for `misumi-ec.com` that changes the script injection timing to `DOMContentLoaded` instead of immediate. This is likely a compatibility workaround but is unusual to see a specific third-party domain hardcoded.
- **Code:**
```javascript
if (document.location.origin.indexOf("misumi-ec.com") > 0) {
    window.addEventListener('DOMContentLoaded', () => { ... });
}
```
- **Verdict:** LOW -- Likely a compatibility fix, not malicious. misumi-ec.com is a Japanese industrial parts supplier.

### VULN-05: Dynamic Function Invocation via Callback Name
- **Severity:** MEDIUM
- **Files:** `contentscript.js` (line 52)
- **Description:** In the `setcallback` path, the content script dynamically invokes a function on the `window` object using a name derived from the push callback. This is a potential code execution vector if an attacker can control the callback name and the corresponding window property.
- **Code:**
```javascript
window[pcbfname](JSON.stringify(result.reply));
```
- **Verdict:** MEDIUM -- The callback name originates from the page itself (which already has full JS execution), so this does not grant additional privileges beyond what the page already has. The real concern would be cross-frame scenarios, but the `activeElement.contentDocument` check on line 37 provides some frame boundary protection.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| innerHTML / DOM manipulation | contentscript.js | Standard DOM element creation for message transport (createElement, appendChild) -- no user-controlled HTML |
| `chrome.scripting.executeScript` | background.js:13 | Used on install to inject content script into existing tabs -- standard MV3 pattern |
| `chrome.runtime.reload()` | background.js:57,113 | Standard auto-update mechanism via `onUpdateAvailable` and `requestUpdateCheck` |
| Custom DOM events | inject.js, contentscript.js | Standard messaging pattern for content script <-> page script communication |
| `btoa()` usage | inject.js:9-10, contentscript.js:3-4 | Used to create unique event names from page URLs, not encoding sensitive data |

## API Endpoints Table

| Endpoint | Type | Purpose |
|----------|------|---------|
| `kr.co.iniline.crosswebex` | Native Messaging Host | Local native application for PKI/crypto operations |
| None | HTTP/HTTPS | No remote server communication from extension code |

## Data Flow Summary

```
Web Page (any URL)
  |
  | calls crosswebex_nativecall() [page-context JS from contentscript.js]
  |
  v
contentscript.js (page context, web-accessible resource)
  |
  | Custom DOM event (__crosswebex__rw_chrome_ext_*)
  |
  v
inject.js (content script context)
  |
  | chrome.runtime.sendMessage()
  |
  v
background.js (service worker)
  |
  | checkRequest() validation (structure + denylist sanitization)
  | managed_tabs check for native commands
  |
  | chrome.runtime.connectNative() / port.postMessage()
  |
  v
Native Host (kr.co.iniline.crosswebex)
  |
  | Response flows back through same chain
  |
  v
Web Page (callback or DOM event with result)
```

**Additional data flow:** On tab navigation events, the URL of managed tabs is sent to the native host for session management.

## Overall Risk Assessment

**Risk: LOW**

**Rationale:** This is a legitimate Korean banking/PKI security middleware extension from INITECH, a well-known Korean security software company. The extension's architecture -- bridging web pages to a native messaging host for cryptographic operations -- is the standard pattern used by all Korean banking security extensions. While the broad permissions (all URLs, all frames, nativeMessaging) and the web-to-native relay create a significant attack surface, this is inherent to the extension's regulated purpose, not indicative of malicious intent.

Key mitigations:
- No remote server communication (no data exfiltration)
- No obfuscation or minification
- No dynamic code loading or eval
- Managed tab tracking limits native commands to initialized sessions
- Input validation (though denylist-based) is present
- MV3 service worker architecture
- No tracking, analytics, or third-party SDKs

The security concerns (weak input validation, denylist sanitization, broad page access) are architectural issues common to all Korean banking security extensions rather than vulnerabilities unique to this extension. The actual security boundary relies heavily on the native messaging host, which is outside the scope of this analysis.
