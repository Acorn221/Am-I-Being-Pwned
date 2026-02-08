# Vulnerability Report: Cisco Webex Extension

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Cisco Webex Extension |
| Extension ID | jlhmfgmfgeifomenelglieieghnjghma |
| Version | 2.0.4 |
| Manifest Version | 3 |
| Users | ~24,000,000 |
| Publisher | Cisco |

## Executive Summary

The Cisco Webex Extension is a minimal, well-scoped extension that serves as a bridge between the Webex web application (running on `*.webex.com` and `*.webex.com.cn`) and a native messaging host (`com.webex.meeting`) installed on the user's machine. The extension uses Manifest V3 with a very tight permission model: only `nativeMessaging` permission and host permissions limited to Webex domains. The codebase is small (3 JS files, 1 HTML stub), well-structured, and contains no obfuscation beyond standard minification. No malicious behavior, data exfiltration, tracking SDKs, ad injection, or suspicious remote code execution was found.

## Vulnerability Details

### 1. Web-Accessible Resource Available to All Origins
- **Severity:** LOW
- **File:** `manifest.json` (line 24-27)
- **Code:**
```json
"web_accessible_resources": [{
    "resources": [ "cwcsf-nativemsg-iframe-43c85c0d-d633-af5e-c056-32dc7efc570b.html" ],
    "matches": [ "<all_urls>" ]
}]
```
- **Verdict:** The HTML page `cwcsf-nativemsg-iframe-43c85c0d-d633-af5e-c056-32dc7efc570b.html` is accessible to all origins. However, it is just a static HTML stub with no scripts or functionality embedded in it. The content scripts that run on this page are gated by the `content_scripts.matches` pattern which restricts execution to `*.webex.com` and `*.webex.com.cn` domains only. The UUID in the filename provides some obscurity. The actual security boundary is enforced by the content script match patterns, not the web-accessible resource declaration. **Low risk, no exploit path identified.**

### 2. CustomEvent Listener for Cross-Frame Communication
- **Severity:** LOW
- **File:** `content_script.js`
- **Code:**
```javascript
document.addEventListener("connect", function(e) {
    p.token_ = e.detail.token;
    p.connectPort(chrome.runtime.id);
});
document.addEventListener("message", function(e) {
    p.sendMessage(e.detail, p.handleNativeMessage);
});
```
- **Verdict:** The content script listens for custom DOM events (`connect` and `message`) which could theoretically be dispatched by any script on the page. However, this is mitigated by: (a) the content script only runs on Webex-owned domains, (b) all messages pass through `p.verify()` which validates message types and applies strict regex whitelisting of script calls, (c) the `verifyScriptCall()` function enforces a 20KB size limit, validates against a regex whitelist of allowed function names, and blocks calls matching known-bad SHA-256 hashes in `hashList`. **Low risk due to strong input validation.**

### 3. Use of `atob()` for Message Decoding
- **Severity:** INFO
- **File:** `content_script.js`
- **Code:**
```javascript
var a = document.createElement("a");
if (a.href = atob(r), ...)
```
- **Verdict:** Base64 decoding via `atob()` is used in `filterLog()`, `verify()`, and `verifyScriptCall()` to decode parameters that are base64-encoded by the Webex web app. This is standard protocol handling, not obfuscation or dynamic code execution. All decoded values are validated before use. **Informational only.**

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `CryptoJS` SHA-256/MD5/AES | `CryptoJS.js` | Standard CryptoJS v3.1.2 library used for SHA-256 hashing of function call names in `verifyScriptCall()`. No encryption of exfiltrated data. |
| `innerHTML` / DOM manipulation | N/A | Not present in this extension. |
| `chrome.runtime.sendMessage` | `content_script.js` | Used for internal extension messaging (content script to background), not external communication. |
| `chrome.runtime.connectNative` | `background.js` | Legitimate native messaging to `com.webex.meeting` host. This is the extension's core purpose. |
| `DOMParser` | `content_script.js` | Used in `filterLog()` to parse XML for log filtering/sanitization, not for injection. |

## API Endpoints Table

| Endpoint | Purpose | File |
|----------|---------|------|
| `com.webex.meeting` (Native Host) | Native messaging bridge to local Webex meeting application | `background.js` |
| `https://clients2.google.com/service/update2/crx` | Chrome extension auto-update (standard) | `manifest.json` |

No external HTTP/HTTPS endpoints are contacted by the extension JavaScript code itself. All network communication is delegated to the native messaging host.

## Data Flow Summary

1. User visits a Webex meeting page on `*.webex.com` or `*.webex.com.cn`.
2. The Webex web app loads the extension's web-accessible resource (`cwcsf-nativemsg-iframe-*.html`) in an iframe.
3. The content script (running only on Webex domains) listens for `connect` and `message` custom DOM events from the parent Webex page.
4. On `connect`, the content script opens a port to the background service worker via `chrome.runtime.connect()`.
5. The background service worker opens a native messaging connection to `com.webex.meeting` via `chrome.runtime.connectNative()`.
6. Meeting launch messages are validated by `verify()` which checks: message type whitelist, JSON structure, platform-specific binary names (e.g., `atgpcext`, `atgpcext64`), and script call whitelisting via regex + SHA-256 blocklist.
7. Valid messages are forwarded to the native host; responses flow back through the same chain to the web page via `CustomEvent`.
8. The `filterLog()` function sanitizes log messages before forwarding, stripping out URLs and numeric values, only forwarding unexpected/suspicious fields.

## Overall Risk Assessment

**CLEAN**

This is a legitimate Cisco enterprise extension with an extremely focused scope. It uses minimal permissions (`nativeMessaging` only), restricts itself to Webex domains, employs thorough input validation (regex whitelisting, SHA-256 hash blocklists, size limits), contains no obfuscation, no remote code loading, no tracking SDKs, no data exfiltration, and no ad injection. The extension serves solely as a bridge between the Webex web application and the locally installed Webex meeting client. Its 24 million user base and Cisco provenance are consistent with a legitimate enterprise tool.
