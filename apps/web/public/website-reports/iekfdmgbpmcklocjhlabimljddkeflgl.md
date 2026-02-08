# Vulnerability Report: SentinelOne

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | SentinelOne |
| Extension ID | `iekfdmgbpmcklocjhlabimljddkeflgl` |
| Version | 0.2.0 |
| Manifest Version | 3 |
| Users | ~7,000,000 |
| Description | SentinelOne DeepVisibility plugin |
| Minimum Chrome Version | 91 |

## Executive Summary

SentinelOne is a legitimate enterprise endpoint security extension that serves as a browser telemetry component for SentinelOne's DeepVisibility product. The extension is extremely minimal (a single 151-line background.js service worker) and functions as a bridge between the browser and a locally-installed SentinelOne native messaging host (`com.sentinelone.browser.extension.host`).

The extension monitors all top-level and sub-frame navigation requests via `chrome.webRequest.onBeforeRequest` and forwards the URL, HTTP method, and browser type to the native messaging host. This is entirely consistent with endpoint detection and response (EDR) / extended detection and response (XDR) functionality -- providing network visibility to the SentinelOne agent running on the host machine.

No content scripts, no popup, no remote code loading, no obfuscation, no external network calls. The extension only communicates with the locally-installed native host application. **No vulnerabilities or malicious behavior identified.**

## Permissions Analysis

| Permission | Justification | Risk |
|-----------|---------------|------|
| `nativeMessaging` | Communicates with local SentinelOne agent via `com.sentinelone.browser.extension.host` | LOW -- Standard EDR pattern |
| `webRequest` | Monitors navigation URLs to provide browser telemetry to the EDR agent | LOW -- Read-only, no blocking |
| `alarms` | Manages inactivity timeout and reconnection backoff for native host connection | NONE |
| `*://*/*` (host_permissions) | Required for `webRequest` to observe all URLs | LOW -- Expected for EDR |

**CSP**: No custom CSP defined; defaults to MV3 strict CSP (no `eval`, no remote code).

## Vulnerability Details

### No Vulnerabilities Found

The extension is remarkably simple and well-scoped:

1. **No content scripts** -- Zero DOM interaction, no injection into web pages.
2. **No popup/UI** -- Purely background telemetry.
3. **No external network calls** -- All data goes to the local native messaging host only.
4. **No dynamic code execution** -- No `eval()`, no `Function()`, no `chrome.scripting.executeScript()`.
5. **No storage of sensitive data** -- No use of `chrome.storage`, `localStorage`, or cookies.
6. **No remote configuration** -- Behavior is fully determined by the local code.
7. **Read-only web request monitoring** -- Uses `onBeforeRequest` in non-blocking mode (no `blocking` in extraInfoSpec); cannot modify requests.

### Data Sent to Native Host

The only data transmitted is:
```javascript
port.postMessage({url: details.url, source: source_type, method: details.method || ""});
```
- `url`: The URL of `main_frame` and `sub_frame` navigations only (not XHR, images, scripts, etc.)
- `source`: Browser type string (`CHROME`, `EDGE`, `FIREFOX`, or `SAFARI`)
- `method`: HTTP method (GET, POST, etc.)

This is minimal, appropriate telemetry for an EDR product.

## False Positive Table

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| `*://*/*` host permission | manifest.json | Required for webRequest on all URLs -- standard EDR pattern |
| URL monitoring via webRequest | background.js:150-151 | Read-only observation of navigations, not request interception |
| nativeMessaging to external host | background.js:134 | Communication with locally-installed SentinelOne agent, not a C2 channel |

## API Endpoints Table

| Endpoint | Type | Purpose |
|----------|------|---------|
| `com.sentinelone.browser.extension.host` | Native Messaging | Local SentinelOne EDR agent communication |
| `https://clients2.google.com/service/update2/crx` | Update URL | Standard Chrome Web Store auto-update (manifest only) |

No external HTTP/HTTPS endpoints are contacted by the extension code.

## Data Flow Summary

```
Browser Navigation Event (main_frame/sub_frame)
    |
    v
chrome.webRequest.onBeforeRequest listener
    |
    v
handle_url_request() -- extracts URL, method, detects browser type
    |
    v
port.postMessage({url, source, method})
    |
    v
Native Messaging Host (com.sentinelone.browser.extension.host)
    |
    v
Local SentinelOne Agent (endpoint security software)
```

Connection management:
- Inactivity alarm disconnects native port after 1 minute of no activity
- Reconnection alarm limits retry attempts to every 1 minute after connection failure
- HELLO handshake validates the native host connection on connect

## Overall Risk: **CLEAN**

This is a legitimate, well-designed enterprise EDR browser extension from SentinelOne, a major cybersecurity vendor. The extension is minimal, transparent, contains no obfuscation, makes no external network calls, has no content scripts, and performs only the narrow function of forwarding navigation URLs to the locally-installed SentinelOne agent for deep visibility / threat detection purposes. The broad permissions (`webRequest` + `*://*/*`) are inherently required for this use case and are used in read-only mode. No vulnerabilities or malicious behavior detected.
