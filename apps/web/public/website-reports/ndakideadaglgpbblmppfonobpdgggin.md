# Vulnerability Report: Mobility Print

## Metadata
| Field | Value |
|---|---|
| Extension Name | Mobility Print |
| Extension ID | `ndakideadaglgpbblmppfonobpdgggin` |
| Version | 1.4.4 |
| Author | PaperCut Software (support@papercut.com) |
| Manifest Version | 3 |
| User Count | ~11,000,000 |
| Analysis Date | 2026-02-08 |

## Executive Summary

Mobility Print is a legitimate enterprise printing extension developed by PaperCut Software, a well-known print management company. The extension enables Chrome OS and Chrome browser users to discover and print to printers on their local network or via PaperCut's cloud printing infrastructure. The extension uses mDNS for local printer discovery, WebRTC for cloud printing relay, and Google OAuth2 for GSuite authentication. All network communication is directed at organization-controlled print servers or PaperCut's own cloud infrastructure (`mp.cloud.papercut.com`). No content scripts are present. No data exfiltration, ad injection, proxy tunneling, or other malicious behavior was identified. Permissions are broad (`http://*/*`, `https://*/*`) but justified for communicating with arbitrary on-premise print servers that organizations deploy at varying hostnames/ports.

## Vulnerability Details

### INFO-01: Remote Logging Feature
- **Severity:** INFO
- **File:** `scripts/main.js` (lines 2369-2397)
- **Code:**
```javascript
chrome.storage.local.get('remoteLoggingURL', d => {
    if (d && d.remoteLoggingURL && d.remoteLoggingURL.startsWith('http')) {
      remoteLogging = d;
    }
});
// ...
fetch(`${remoteLogging.remoteLoggingURL}`, request).catch(e => { ... });
```
- **Verdict:** FALSE POSITIVE. This is a debug/diagnostic logging feature that must be explicitly configured via local storage. It is not enabled by default and requires manual activation (likely for IT admin troubleshooting). The URL must be explicitly set by the user/admin. Logs contain only extension operational info (print job status, errors), not user browsing data.

### INFO-02: Broad Host Permissions
- **Severity:** INFO
- **File:** `manifest.json` (lines 47-50)
- **Code:**
```json
"host_permissions": [
    "http://*/*",
    "https://*/*"
]
```
- **Verdict:** EXPECTED. The extension needs to communicate with customer-deployed Mobility Print servers at arbitrary hostnames and ports (e.g., `http://myhost.mydomain.com:9163`). There are no content scripts, so these permissions are only used for fetch/XHR to print servers and PaperCut cloud services. This is a legitimate use case for an enterprise printing tool.

### INFO-03: External Message Listener (BYOD Links)
- **Severity:** INFO
- **File:** `scripts/main.js` (lines 2603-2621)
- **Code:**
```javascript
chrome.runtime.onMessageExternal.addListener(function (request, sender, sendResponse) {
    if (request.link.href !== undefined) {
      saveBYODLinkHandler(request.link.href, sendResponse);
    }
});
```
- **Verdict:** EXPECTED. The externally_connectable manifest entry restricts this to only PaperCut's own extension ID and `mp.cloud.papercut.com` / `mp.cloud.papercut.software` domains. This is used for BYOD (Bring Your Own Device) printer link configuration.

### INFO-04: Local IP Address Collection
- **Severity:** INFO
- **File:** `scripts/main.js` (lines 1349-1361)
- **Code:**
```javascript
chrome.system.network.getNetworkInterfaces(interfaces => { ... });
```
- **Verdict:** EXPECTED. Local IP addresses are sent as `Local-Ip-Addresses` headers when discovering printers on the network. This is standard for network print discovery - the print server needs to know which subnet the client is on.

### INFO-05: WebRTC Usage (Cloud Printing)
- **Severity:** INFO
- **File:** `scripts/main.js` (lines 4472, 4221-4224)
- **Code:**
```javascript
this.connection = new RTCPeerConnection(createRTCConfig(iceConfig));
// ...
reasons: [chrome.offscreen.Reason.WEB_RTC],
justification: 'WebRTC for Mobility Cloud Print'
```
- **Verdict:** EXPECTED. WebRTC data channels are used for cloud printing relay through PaperCut's signaling server (`mp.cloud.papercut.com`). This allows printing to printers when not on the same network, a core feature of the product.

### INFO-06: Enterprise Device Attributes
- **Severity:** INFO
- **File:** `scripts/main.js` (lines 1437-1444)
- **Code:**
```javascript
chrome.enterprise.deviceAttributes.getDeviceAssetId(assetId => { ... });
```
- **Verdict:** EXPECTED. This is a Chrome OS enterprise API used in managed environments. The extension correctly checks for API availability before calling it.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| innerHTML | `scripts/index.js`, `scripts/login.js` | jQuery library internal DOM manipulation (standard jQuery usage) |
| `Function('return this')` | `scripts/offscreen.js` (line 2492) | core-js polyfill global `this` detection (standard polyfill pattern) |
| `navigator.userAgent.match` | `scripts/main.js` (line 1410) | Chrome OS version detection for compatibility logging |
| `atob`/`btoa` | `scripts/main.js` (lines 1998-2000, 4616-4619) | JWT token parsing and WebRTC session description encoding |
| `chrome.tabs.query` | `scripts/main.js` (line 2382) | Only used in remote logging to tag log messages with tab ID (debug feature) |

## API Endpoints Table

| Endpoint | Purpose | Method |
|---|---|---|
| `https://mp.cloud.papercut.com/*` | PaperCut Cloud Print API (signaling, sessions) | GET/POST |
| `https://mp.cloud.papercut.software/*` | PaperCut Cloud Print API (test/staging) | GET/POST |
| `https://www.googleapis.com/oauth2/v2/userinfo` | Google OAuth user info (email only) | GET |
| `https://accounts.google.com/o/oauth2/revoke` | Google token revocation | POST |
| `{printerHost}/printers` | Local printer discovery | GET |
| `{printerHost}/printers/{name}/jobs` | Print job submission | POST |
| `{printerHost}/server-config` | Server encryption config check | GET |
| `{printerHost}/public-key` | RSA public key for credential encryption | GET |
| `{printerHost}/auth-options` | Authentication options retrieval | GET |
| `{printerHost}/token` | Auth token retrieval (Basic Auth) | GET |
| `{pdHost}/deploy/login` | Print Deploy login | POST |
| `{pdHost}/deploy/printers` | Print Deploy printer listing | POST |
| `{pdHost}/deploy/config` | Print Deploy configuration | GET |
| `{pdHost}/deploy/oauth/session` | Print Deploy OAuth session | POST |

## Data Flow Summary

1. **Printer Discovery:** Extension uses mDNS (`chrome.mdns`) and/or managed policy-configured known hosts to discover Mobility Print servers on the local network. Sends local IP addresses as headers for subnet-aware discovery.
2. **Authentication:** Supports per-printer username/password auth (encrypted with server's RSA public key), Google Workspace SSO via `chrome.identity`, and PaperCut Print Deploy auth. Credentials are encrypted in transit.
3. **Print Job Submission:** Jobs are submitted either via HTTP(S) directly to local print servers or via WebRTC data channels through PaperCut's cloud signaling server for off-network printing.
4. **Cloud Print (Off-Network):** Uses WebRTC peer connections brokered through `mp.cloud.papercut.com` to relay print jobs when the user is not on the same network as the printer.
5. **Data Storage:** Auth tokens, printer preferences, and BYOD links stored in `chrome.storage.local`. Feature flags in local storage. Managed policy in `chrome.storage.managed`.
6. **No browsing data collection.** No content scripts. No history/bookmark/download access. No cookie access. No DOM manipulation on web pages.

## Overall Risk Assessment

**CLEAN**

This is a legitimate enterprise printing extension from PaperCut Software, a well-established print management vendor. The extension's broad host permissions are justified by its need to communicate with customer-deployed print servers at arbitrary network addresses. All network communication is directed exclusively at print infrastructure (local servers and PaperCut cloud). There are no content scripts, no browsing data collection, no ad injection, no proxy behavior, no SDK injection, and no obfuscation. The codebase is a clean webpack bundle of TypeScript/JavaScript with standard libraries (jQuery, core-js, aes-js for encryption). The extension performs exactly its advertised function: enabling printing from Chrome to Mobility Print servers.
