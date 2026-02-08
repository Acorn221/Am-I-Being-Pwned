# Vulnerability Report: TouchEn PC보안 확장

## Metadata
- **Extension Name:** TouchEn PC보안 확장
- **Extension ID:** dncepekefegjiljlfbihljgogephdhph
- **Version:** 1.0.2.4
- **Author:** 라온시큐어㈜ (Raon Secure)
- **User Count:** ~9,000,000
- **Manifest Version:** 3
- **Homepage:** https://www.raonsecure.com

## Permissions
| Permission | Justification |
|---|---|
| `nativeMessaging` | Communicates with local TouchEn PC security native application |
| `scripting` | Injects content scripts on install into existing tabs |
| `*://*/*` (host_permissions) | Needs to operate on any banking/security site that uses TouchEn |
| `*://*/*` (content_scripts match) | Content script injected into all pages at document_start, all_frames |

## Executive Summary

TouchEn PC보안 확장 is a Korean banking/enterprise security extension by Raon Secure (라온시큐어). It acts as a **bridge between web pages and a native application** (`kr.co.raon.touchenex`) via Chrome's Native Messaging API. This is a well-known pattern in Korean internet banking where ActiveX was replaced by browser extensions + native apps for keyboard security, anti-keylogging, and other endpoint security functions.

The extension injects a content script (`inject.js`) into every page at `document_start` in all frames. This script loads `contentscript.js` as a page-level script (via `<script>` tag injection using `web_accessible_resources`). The page-level script (`contentscript.js`) exposes a `touchenex_nativecall()` function that web pages call to communicate with the native app through the extension as a relay.

**The extension has broad permissions and a large attack surface, but this is consistent with its stated purpose as a Korean banking security component. No malicious behavior, data exfiltration, ad injection, or suspicious remote endpoints were found.**

## Vulnerability Details

### VULN-001: Weak XSS Sanitization in Callback Parameter (MEDIUM)

- **Severity:** MEDIUM
- **File:** `background.js` (lines 235-246, 249-261)
- **Description:** The `checkRequest()` function sanitizes the `callback` string by stripping characters like `<`, `>`, `/`, `(`, `)`, `#`, `&`, `:` and keywords `javascript`, `document`, `onclick`, `onerror`. This is a blocklist-based approach which is inherently fragile. While it prevents the most common XSS vectors, blocklist sanitization can be bypassed with encoding tricks, double-encoding, or novel payloads. However, the callback value is used as a DOM event identifier, not directly evaluated as code in the extension itself.
- **Code:**
```javascript
request.callback = request.callback.replaceAll("<", "");
request.callback = request.callback.replaceAll(">", "");
// ... more character stripping ...
request.callback = request.callback.replaceAll("javascript", "");
request.callback = request.callback.replaceAll("document", "");
```
- **Impact:** Limited. The callback is used as part of an event dispatch name and DOM attribute, not directly `eval()`'d. The page-level script does call `window[pcbfname]()` in `contentscript.js` line 51, but the callback name goes through multiple transforms before reaching that point.
- **Verdict:** MEDIUM - Weak sanitization pattern, but exploitation is constrained by the data flow.

### VULN-002: Arbitrary Function Call via window[pcbfname] (MEDIUM)

- **Severity:** MEDIUM
- **File:** `contentscript.js` (line 51)
- **Description:** The `contentscript.js` file calls `window[pcbfname](JSON.stringify(result.reply))` where `pcbfname` is derived from the callback name set during the `setcallback` command. This is a controlled dynamic dispatch pattern common in Korean banking security SDKs -- the web page itself provides the callback function name, and the result is dispatched to that function. Since `contentscript.js` runs in the page context (injected via `<script>` tag), this is equivalent to the page calling its own function.
- **Code:**
```javascript
window[pcbfname](JSON.stringify(result.reply));
```
- **Impact:** Since this runs in the page's own context (not the extension's isolated world), a page that calls `touchenex_nativecall` already has full page-context access. The page is calling itself back. The risk would arise if a different origin could somehow control `pcbfname`, but the event naming is origin-scoped via `btoa(pageurl)`.
- **Verdict:** MEDIUM - Dynamic dispatch is a code smell, but the trust boundary is correctly scoped to same-page context.

### VULN-003: URL Sent to Native App on Tab Navigation (LOW)

- **Severity:** LOW
- **File:** `background.js` (lines 206-208)
- **Description:** When a managed tab navigates, the extension sends the full `tab.url` to the native application via the `__tab_status__` function. This occurs only for tabs that have been registered through a prior `get_versions` call (managed_tabs Map).
- **Code:**
```javascript
if (type == "update") {
    request.exfunc.args = ["move", tab.url];
}
```
- **Impact:** The native app receives URLs of pages using the TouchEn security module. This is expected behavior for a security product that needs to know which banking site is active. Only managed tabs (those that initiated a TouchEn session) are tracked.
- **Verdict:** LOW - Expected behavior for the product's security monitoring purpose.

### VULN-004: Content Script Runs on All Pages (LOW)

- **Severity:** LOW
- **File:** `manifest.json` (lines 24-30), `inject.js`
- **Description:** The content script (`inject.js`) is injected into every page (`*://*/*`) at `document_start` in `all_frames: true`. This is a broad injection surface. However, the injected script only sets up event listeners and does not perform any autonomous data collection or DOM manipulation until explicitly called by the page.
- **Impact:** Performance overhead on all pages. The script is lightweight (~80 lines) and only activates when a page calls `touchenex_nativecall()`. No data is collected from pages that don't explicitly use the API.
- **Verdict:** LOW - Broad but passive injection, consistent with Korean banking security extension patterns.

### VULN-005: Hardcoded Domain-Specific Workaround (INFO)

- **Severity:** INFO
- **File:** `inject.js` (line 66)
- **Description:** There is a hardcoded check for `misumi-ec.com` that changes the injection timing to wait for `DOMContentLoaded`. This is a site-specific compatibility fix.
- **Code:**
```javascript
if (document.location.origin.indexOf("misumi-ec.com") > 0) {
```
- **Impact:** None. This is a benign compatibility workaround for a specific Japanese industrial supply website.
- **Verdict:** INFO - No security impact.

## False Positive Table

| Pattern | Location | Reason Not Flagged |
|---|---|---|
| `window[pcbfname](...)` dynamic call | `contentscript.js:51` | Runs in page context, page calls itself back -- standard callback dispatch pattern for Korean banking SDKs |
| `innerHTML` / DOM manipulation | N/A | Not present in codebase |
| `eval()` / `new Function()` | N/A | Not present in codebase |
| `chrome.scripting.executeScript` | `background.js:13-19` | Only runs on install to inject content scripts into existing tabs, uses file reference not inline code |
| `document.createElement("script")` | `inject.js:2` | Injects the extension's own `contentscript.js` from web_accessible_resources |
| XSS-like character stripping | `background.js:235-261` | Sanitization of callback parameter, not injection |

## API Endpoints Table

| Endpoint | Type | Purpose |
|---|---|---|
| `kr.co.raon.touchenex` | Native Messaging | Communication with local TouchEn PC security native application |
| `https://clients2.google.com/service/update2/crx` | CWS Update | Standard Chrome Web Store update URL (in manifest) |

**No external HTTP/HTTPS endpoints are contacted by the extension code itself.** All communication goes through Native Messaging to the local application.

## Data Flow Summary

```
Web Page (banking site)
  │
  ├── Calls touchenex_nativecall(message, callback)  [contentscript.js - page context]
  │
  ├── DOM Event dispatch (__touchenex__rw_chrome_ext_{base64_url})
  │
  ├── inject.js (content script, isolated world) receives DOM event
  │     └── chrome.runtime.sendMessage(request) → background.js
  │
  ├── background.js validates request via checkRequest()
  │     └── port.postMessage(json) → Native App (kr.co.raon.touchenex)
  │
  ├── Native App responds → background.js receives via port.onMessage
  │     └── chrome.tabs.sendMessage(tabid, response)
  │
  ├── inject.js receives response via chrome.runtime.onMessage
  │     └── DOM Event dispatch (__touchenex__rw_chrome_ext_reply_{base64_url})
  │
  └── contentscript.js (page context) receives reply
        └── Calls page callback function with result
```

**Data collected:** Only data explicitly sent by the web page through the `touchenex_nativecall()` API (banking security parameters, license info, module commands). Tab URLs are sent to native app only for managed/registered tabs.

**Data sent externally:** None via network. All data goes to the locally-installed native application only.

## Overall Risk Assessment

**RISK: CLEAN**

This is a legitimate Korean banking/enterprise security extension by Raon Secure, a well-known Korean security company. The extension:

1. **Serves its stated purpose** as a bridge between web banking sites and local security software (keyboard encryption, anti-keylogging, endpoint security)
2. **Does not contact any external servers** -- all communication is via Native Messaging to a local application
3. **Does not collect or exfiltrate data** -- it only relays messages initiated by the web page
4. **Has no obfuscation** -- code is clean, readable, and straightforward
5. **Has no ad injection, tracking, or market intelligence SDKs**
6. **Has no remote config or kill switches** (beyond standard CWS auto-update)

The broad permissions (`*://*/*`, `nativeMessaging`, `scripting`) are invasive but **necessary and expected** for Korean banking security extensions that must be available on any site that integrates with TouchEn. The weak blocklist-based callback sanitization (VULN-001) and dynamic dispatch pattern (VULN-002) are minor code quality concerns but do not represent exploitable vulnerabilities in practice given the trust model (the page controls its own callbacks).

This is a standard Korean internet security component with ~9M users, consistent with mandatory banking security requirements in South Korea.
