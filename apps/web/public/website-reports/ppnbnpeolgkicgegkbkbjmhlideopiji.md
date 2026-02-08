# Vulnerability Report: Microsoft Single Sign On

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Microsoft Single Sign On |
| Extension ID | ppnbnpeolgkicgegkbkbjmhlideopiji |
| Version | 1.0.11 |
| Manifest Version | 3 |
| Users | ~36,000,000 |
| Publisher | Microsoft Corporation |

## Executive Summary

This is Microsoft's official Single Sign-On (SSO) extension for Chrome. It facilitates authentication with Microsoft work/school accounts by bridging the browser with the native `com.microsoft.browsercore` native messaging host on the OS. The extension is minimal in scope: a content script listens for postMessage events on a specific hardcoded channel UUID to facilitate SSO handshakes, and the background service worker proxies those requests to the native messaging host for token operations.

The extension requests only `nativeMessaging` permission and runs content scripts on `https://*/*` with `all_frames: true` at `document_start`. While the broad content script injection scope and all-frames injection is notable, this is expected and necessary for an SSO extension that must intercept authentication flows across all HTTPS sites.

**No malicious behavior, data exfiltration, obfuscation, remote code execution, or key vulnerabilities were identified.** The codebase is small, clear, well-commented, and consistent with its stated purpose.

## Vulnerability Details

### 1. Broad Content Script Injection Scope
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| File | `manifest.json` (lines 25-32) |
| Verdict | **Expected for SSO functionality** |

```json
"content_scripts": [
    {
        "matches": ["https://*/*"],
        "all_frames": true,
        "js": ["content.js"],
        "run_at": "document_start"
    }
]
```

The content script runs on all HTTPS pages in all frames. This is necessary for SSO to work across any Microsoft-integrated site. The script itself is lightweight and only activates when it receives a postMessage with the specific channel UUID `53ee284d-920a-4b59-9d30-a60315b26836`.

### 2. postMessage Channel for SSO Communication
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| File | `content.js` (lines 4-167) |
| Verdict | **Acceptable design pattern with adequate validation** |

The content script uses `window.postMessage` with a hardcoded channel UUID for communication between the web page and the extension. Key mitigations:
- Messages are filtered by channel UUID (`53ee284d-920a-4b59-9d30-a60315b26836`)
- Source validation: `event.source != window` check rejects cross-origin messages
- The Handshake flow uses MessageChannel ports for subsequent communication, reducing exposure
- `event.stopImmediatePropagation()` prevents other extensions from intercepting handshake messages
- The native messaging host (`com.microsoft.browsercore`) performs its own sender origin validation via `request.sender = sender.origin`

### 3. Native Messaging to com.microsoft.browsercore
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| File | `background.js` (lines 14-16) |
| Verdict | **Expected SSO architecture** |

```javascript
chrome.runtime.sendNativeMessage(
    "com.microsoft.browsercore",
    request,
    function (response) { ... });
```

The background service worker proxies requests to the OS-level native messaging host. The sender origin is passed through for server-side validation. The `GetSupportedUrls` method is explicitly blocked (line 9), preventing URL enumeration. This is a standard Microsoft SSO architecture pattern.

### 4. Sender Origin Passed to Native Host
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| File | `background.js` (line 8) |
| Verdict | **Security feature, not a vulnerability** |

```javascript
request.sender = sender.origin;
```

The sender's origin is attached to every request forwarded to the native host, allowing the native side to enforce origin-based access control. This is a defense-in-depth measure.

## False Positive Table

| Pattern | Location | Reason Not Flagged |
|---------|----------|-------------------|
| `postMessage` usage | `content.js` | Legitimate SSO communication channel with UUID gating, source validation, and MessageChannel port isolation |
| `all_frames: true` | `manifest.json` | Required for SSO in embedded iframes (common in enterprise auth flows) |
| `https://*/*` match pattern | `manifest.json` | SSO must be available on any HTTPS site; extension is inert without matching postMessage |
| `document_start` run timing | `manifest.json` | SSO must be available early in page lifecycle for auth interception |
| `nativeMessaging` permission | `manifest.json` | Core functionality - bridging browser to OS-level authentication |
| `chrome.runtime.sendMessage` | `content.js` | Standard content-to-background communication for SSO flow |
| DOM manipulation (`createElement`, `appendChild`) | `content.js` (lines 28-36) | Legacy `CreateProviderAsync` path creates a DOM element to signal extension presence; scoped to specific channel-gated element |
| SKU parameter injection | `content.js` (lines 46-67) | Adds `x-client-xtra-sku` with extension version info for server telemetry; no PII |

## API Endpoints Table

| Endpoint / Target | Purpose | File |
|-------------------|---------|------|
| `com.microsoft.browsercore` (native messaging host) | OS-level SSO token broker | `background.js:15` |
| `https://www.office.com` | Opened on extension icon click | `background.js:50` |
| `https://clients2.google.com/service/update2/crx` | Standard Chrome extension auto-update URL | `manifest.json:2` |

## Data Flow Summary

1. **Web page** sends a `postMessage` on channel `53ee284d-920a-4b59-9d30-a60315b26836`
2. **Content script** (`content.js`) validates the message source and channel UUID
3. For **Handshake**: Responds via MessageChannel port with extension ID and version; subsequent requests flow through the port
4. For **SSO requests**: Content script forwards to background via `chrome.runtime.sendMessage`
5. **Background** (`background.js`) attaches `sender.origin` and forwards to `com.microsoft.browsercore` native host
6. **Native host** performs authentication operations and returns result
7. **Background** sends response back to content script, which relays to the web page

No data is sent to any remote server by the extension itself. All authentication is handled by the OS-level native messaging host. No telemetry, analytics, or tracking code is present in the extension.

## Overall Risk: **CLEAN**

This is a legitimate, minimal Microsoft SSO extension. The codebase is small (~245 lines total across 2 JS files), well-commented, and performs exactly its stated function: bridging web-based SSO requests to the OS-level Microsoft Browser Core native messaging host. There is no data exfiltration, no remote code loading, no obfuscation, no tracking SDKs, no ad injection, and no suspicious behavior. The broad content script scope and permissions are justified by the SSO use case. The extension has appropriate security measures including channel UUID gating, source validation, origin forwarding, and method filtering.
