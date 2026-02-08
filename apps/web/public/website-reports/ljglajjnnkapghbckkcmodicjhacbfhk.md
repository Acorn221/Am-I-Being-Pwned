# Vulnerability Report: Microsoft Power Automate

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Microsoft Power Automate |
| Extension ID | ljglajjnnkapghbckkcmodicjhacbfhk |
| Version | 2.61.0.32 |
| Manifest Version | 3 |
| User Count | ~10,000,000 |
| Publisher | Microsoft |

## Executive Summary

Microsoft Power Automate is a legitimate browser automation extension published by Microsoft. It acts as a bridge between the Power Automate for desktop application and the browser, enabling robotic process automation (RPA) workflows on web pages. The extension communicates exclusively via Chrome Native Messaging (`chrome.runtime.connectNative`) with the locally installed Power Automate desktop application (`com.microsoft.pad.messagehost`). It does not make any network requests (no fetch, XMLHttpRequest, WebSocket), does not access cookies/localStorage/storage APIs, and does not contain any telemetry, tracking SDKs, or data exfiltration logic.

The extension requires broad permissions (`<all_urls>`, `scripting`, `debugger`, `tabs`, `browsingData`, `nativeMessaging`, `webNavigation`) which are necessary for its intended purpose of browser automation -- injecting content/API scripts into arbitrary web pages, reading DOM elements, extracting data, simulating user interactions, and running JavaScript via the debugger protocol on behalf of the desktop application.

**No malicious behavior, no data exfiltration, no suspicious patterns detected.**

## Vulnerability Details

### VULN-001: Arbitrary JavaScript Execution via Debugger API (By Design)

| Field | Value |
|-------|-------|
| Severity | LOW (by design, not exploitable remotely) |
| File | `background.js` (lines 133-150, 381-398, 887-904, 1268-1285) |
| Verdict | **Not a vulnerability -- intended functionality** |

**Description:** The `onRunJavaScript` handler in all background script versions (V1-V4) attaches the Chrome debugger to a tab and executes arbitrary JavaScript via `Runtime.evaluate` with an `expression` parameter received from the native host.

```javascript
static onRunJavaScript(request) {
    return __awaiter(this, void 0, void 0, (function*() {
        if (!(yield BackgroundV3.attachDebuggerIfNeeded(request.tabId))) throw new Error("Can't attach debugger");
        return new Promise((resolve => {
            chrome.debugger.sendCommand({
                tabId: request.tabId
            }, "Runtime.evaluate", {
                expression: request.code
            }, (result => {
                chrome.debugger.detach({
                    tabId: request.tabId
                }, (() => {
                    resolve(`${result.result.value ?? result.result}`);
                }));
            }));
        }));
    }));
}
```

**Analysis:** This is a core RPA feature. The code to execute comes exclusively from the locally installed Power Automate desktop application via Native Messaging -- not from any remote server. An attacker would need to compromise the local machine first (at which point they already have full access anyway). The debugger permission causes Chrome to show a visible banner ("... started debugging this browser") which cannot be suppressed. This is standard behavior for RPA tools.

### VULN-002: Content Script Injection into All URLs (By Design)

| Field | Value |
|-------|-------|
| Severity | LOW (by design) |
| File | `background.js` (lines 963-977, 1749-1800) |
| Verdict | **Not a vulnerability -- intended functionality** |

**Description:** The extension injects content scripts (`content.v1.js`/`content.v2.js`) and API scripts (`api.v1.js`-`api.v4.js`) into arbitrary web page frames via `chrome.scripting.executeScript`, but only when the desktop application requests it via native messaging.

**Analysis:** Scripts are only injected on-demand when the desktop Power Automate application sends a command. The extension checks `canScriptsBeInjected()` to skip `chrome://`, `edge://`, and `about:` URLs. Injected content scripts only handle DOM queries (element selection, attribute reading, dimension measurement, history navigation) -- no data exfiltration or network activity.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `chrome.debugger` API usage | `background.js` | Required for RPA JavaScript execution on behalf of desktop app |
| `chrome.scripting.executeScript` | `background.js` | On-demand content script injection for page automation |
| `<all_urls>` host permission | `manifest.json` | RPA tool must automate any website the user targets |
| `browsingData` permission | `manifest.json` | Clear cookies/cache as part of automation flows |
| `Runtime.evaluate` with dynamic code | `background.js` | Receives code only from local native host, not from network |
| URL sanitization regexes | `background.js` (line 249) | Defensive sanitization blocking `javascript:`, `data:`, `vbscript:` URLs |
| `postMessage` in content.v2.js | `content.v2.js` (line 260) | Receives frame identifier for iframe tracking, no data sent out |

## API Endpoints Table

| Endpoint / Target | Type | Purpose |
|-------------------|------|---------|
| `com.microsoft.pad.messagehost` | Native Messaging | Local IPC with Power Automate desktop application |
| `https://clients2.google.com/service/update2/crx` | CWS Update | Standard Chrome Web Store auto-update URL |

**No remote API endpoints, no external network calls, no telemetry endpoints.**

## Data Flow Summary

```
Power Automate Desktop App
    |
    | (Native Messaging: com.microsoft.pad.messagehost)
    v
Background Service Worker (background.js)
    |
    | - LoadScriptsRequest: selects background/content/api script versions
    | - Tab management: GetTab, GetAllWindows, ActivateTab, CloseTab, etc.
    | - RunJavaScriptRequest: debugger-based JS execution
    | - Content script commands: DOM queries, element selection, data extraction
    |
    v
Content Scripts (content.v1.js / content.v2.js)
    |
    | - Receive commands via chrome.runtime port
    | - Execute DOM operations (querySelector, getBoundingClientRect, etc.)
    | - Return results back through port to background -> native host
    |
    v
API Scripts (api.v1-v4.js)
    |
    | - jQuery/Sizzle-based DOM manipulation
    | - Element attribute reading, CSS selector generation
    | - Page dimension measurement, zoom handling
    | - Data extraction from tables and structured content
    |
    v
Results returned to Power Automate Desktop App (via Native Messaging)
```

**Key observations:**
- All data flows are local: browser extension <-> desktop application via Native Messaging
- No data leaves the machine to any remote server
- No cookies, localStorage, or chrome.storage are read or written
- No telemetry, analytics, or tracking of any kind
- Strong CSP: `default-src 'self'` (no inline scripts, no remote resources)
- Content scripts are injected on-demand only, not declared in manifest for all pages

## Overall Risk Assessment

| Risk Level | **CLEAN** |
|------------|-----------|

**Justification:** This is a legitimate Microsoft-published RPA browser extension with ~10M users. Despite requesting broad permissions (`<all_urls>`, `debugger`, `scripting`, `browsingData`, `nativeMessaging`, `tabs`, `webNavigation`), every permission is justified by and necessary for its intended browser automation functionality. The extension:

1. Makes zero network requests -- all communication is via local Native Messaging
2. Contains no telemetry, tracking, or data collection code
3. Has no obfuscation beyond standard webpack bundling
4. Has a strict CSP (`default-src 'self'`)
5. Includes URL sanitization to prevent injection attacks
6. Only injects scripts when explicitly commanded by the local desktop application
7. Uses the debugger API with full Chrome UI notification (visible banner)

The broad permissions are invasive but entirely serve the extension's intended purpose of web automation. No malicious behavior or exploitable vulnerabilities were identified.
