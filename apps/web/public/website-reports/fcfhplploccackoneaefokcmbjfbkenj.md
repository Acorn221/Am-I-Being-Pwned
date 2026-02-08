# Vulnerability Report: Free VPN for Chrome by 1clickVPN

## Metadata
| Field | Value |
|---|---|
| Extension Name | Free VPN for Chrome by 1clickVPN |
| Extension ID | `fcfhplploccackoneaefokcmbjfbkenj` |
| Version | 2.0.25 |
| Manifest Version | 3 |
| Approximate Users | ~8,000,000 |
| Files Analyzed | `background.bundle.js`, `popup.bundle.js`, `530.bundle.js`, `manifest.json` |

## Permissions

| Permission | Justification |
|---|---|
| `alarms` | Periodic sync and icon status updates |
| `webRequest` | Monitor request completion/errors for VPN diagnostics |
| `proxy` | Core VPN functionality - proxy settings management |
| `storage` | Persist VPN config, server list, user preferences |
| `unlimitedStorage` | Large storage for server lists / diagnostics |
| `webRequestAuthProvider` | Handle proxy authentication challenges |
| `*://*/*` (host) | Route all traffic through VPN proxy |
| `https://1clickvpn.net/api/` (host) | API calls to 1clickVPN servers |

## Executive Summary

This extension is a free VPN proxy that routes browser traffic through 1clickVPN's proxy servers. It performs standard VPN operations: proxy configuration via `chrome.proxy.settings`, server list synchronization, and proxy authentication handling.

**The primary concern is a browsing data collection mechanism** that captures metadata for every completed main-frame HTTP/HTTPS request and sends it to 1clickVPN's self-hosted Sentry instance (`astrid.1clickvpn.net`). This includes the full target URL, referrer URL, content type, user ID, tab foreground status, and timestamps. The feature is labeled "VPN Diagnostics / Quality Monitoring" in the UI and is **enabled by default** on first connect (set to `1` if `undefined`), though users can toggle it off.

No remote code execution, extension enumeration, residential proxy abuse, keylogging, cookie harvesting, ad injection, or market intelligence SDK was found.

## Vulnerability Details

### HIGH-1: Browsing Activity Collection via Sentry Abuse

**Severity:** HIGH
**Files:** `background.bundle.js`
**Category:** Privacy / Data Collection

**Description:**
The extension intercepts ALL main-frame HTTP/HTTPS requests via `chrome.webRequest.onBeforeSendHeaders` and `chrome.webRequest.onCompleted` listeners (registered with `urls: ["http://*/*", "https://*/*"]`), collecting:

- `targetUrl` - The full URL being visited
- `referrerUrl` - The referring page URL
- `userId` - Unique persistent identifier (UUID generated on install)
- `deviceTimestamp` - Precise millisecond timestamp
- `fileDate` - ISO date string
- `requestType` - Request type (e.g. `main_frame`)
- `contentType` - Response content-type header
- `statusCode` - HTTP status code
- `foreground` - Whether the tab is active (1) or background (0)

This data is sent to `https://astrid.1clickvpn.net/44` (their self-hosted Sentry instance) using `Nf.setContext("req", data)` followed by `Nf.captureMessage("onCompletedListener")` or `Nf.captureMessage("onErrorOccurredListener")`.

**Code (sendRequest):**
```javascript
key:"sendRequest",value:(e=c(i().mark((function e(t,n){
  var r,o,s,a;
  return i().wrap((function(e){
    // ...
    return e.next=2, chrome.storage.local.get("vpnDiagnostics");
    // if vpnDiagnostics is undefined OR == 1, proceed:
    if(void 0===(a=s.vpnDiagnostics)||1==+a){ /* continue */ }
    else return; // abort if explicitly set to 0
    Nf.setContext("req",t), Nf.captureMessage(n);
  }))
})))
```

**Code (onCompleted data assembly):**
```javascript
e.t10={
  fileDate: (new Date).toISOString(),
  deviceTimestamp: Date.now(),
  userId: this.storage.id,
  referrerUrl: c,
  targetUrl: u,
  requestType: l,
  contentType: p || null,
  statusCode: d,
  foreground: /* checkForeground result */
},
e.t0.sendRequest.call(e.t0, e.t10, "onCompletedListener")
```

**Gating mechanism:** The `vpnDiagnostics` storage flag defaults to `undefined`. On first VPN connect, the popup sets it to `1`:
```javascript
void 0===this.state.vpnDiagnostics && (
  this.setState({vpnDiagnostics:1}),
  chrome.storage.local.set({vpnDiagnostics:1})
)
```
The toggle checkbox shows as checked when value is `1` OR `undefined`:
```javascript
checked: 1===this.state.vpnDiagnostics || void 0===this.state.vpnDiagnostics
```

**Server-side sampling:** Sentry's `beforeSend` applies a 20% random sampling rate (`Math.random()<.2?e:null`), meaning approximately 20% of browsing events are actually transmitted.

**Verdict:** HIGH. While labeled as "diagnostics" with an opt-out toggle, the default-on collection of full browsing URLs (including sensitive URLs like banking, healthcare, etc.) for ~8M users is a significant privacy violation. The data is sent to the extension developer's own Sentry infrastructure, giving them a browsing history dataset. The "Quality Monitoring" label is misleading -- URL-level browsing data is not necessary for VPN quality monitoring (latency/throughput metrics would suffice).

### MEDIUM-1: Persistent User Tracking via UUID

**Severity:** MEDIUM
**Files:** `background.bundle.js`

**Description:**
On first install, a UUID is generated and stored permanently:
```javascript
key:"generateUUID",value:function(){
  return([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,(function(e){
    return(e^crypto.getRandomValues(new Uint8Array(1))[0]&15>>e/4).toString(16)
  }))
}
```
This ID is set as the Sentry user (`Nf.setUser({id:l.storage.id})`) and appended to all API requests (`?c=` + id). This enables cross-session tracking and correlating all browsing activity to a single user.

**Verdict:** MEDIUM. Persistent identifier enables long-term user tracking and is used to correlate browsing data collection from HIGH-1.

### LOW-1: Install Page / Update Page Tab Opening

**Severity:** LOW
**Files:** `background.bundle.js`

**Description:**
On install, the extension opens `https://1clickvpn.net/download-vpn`. On updates and Chrome updates, it opens an updates page with user ID:
```javascript
"install"===r ? (
  chrome.storage.local.set({accepted:1}),
  setTimeout(function(){ t.safeCreateTab({url: g + "/download-vpn", active:true}) }, 300)
) : ("chrome_update"===r || "update"===r && o!==chrome.runtime.getManifest().version)
  && e.openUpdatesPage()
```

The updates page passes the user ID: `g + "/update?type=modal&u=" + e.id`

**Verdict:** LOW. Common VPN extension behavior but confirms user tracking.

### INFO-1: "-noad" Proxy Node Selection for Premium Users

**Severity:** INFO
**Files:** `background.bundle.js`

**Description:**
When all servers have credentials (indicating premium status), the proxy node hostname is modified to add "-noad" suffix, suggesting free-tier users may be routed through ad-injecting proxy nodes:
```javascript
if(n.storage.servers.filter(function(e){if(e.credentials)return e}).length===n.storage.servers.length
   && !t.host.includes("-noad")){
  var c=t.host.split(".");
  var u=c[0];
  c.splice(0,1,"".concat(u,"-noad"));
  t.host=c.join(".");
}
```

**Verdict:** INFO. Suggests free-tier proxy nodes may inject ads at the network level. This is a server-side concern rather than an extension vulnerability, but notable for users.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `new Function("return this")` | `background.bundle.js` | Standard globalThis polyfill in webpack runtime |
| `innerHTML` / Proxy objects | `background.bundle.js` | Sentry Session Replay SDK (rrweb) DOM recording library -- bundled but not actively configured for session replay |
| `keydown` / `keypress` listeners | `background.bundle.js` / `popup.bundle.js` | Sentry breadcrumb/performance instrumentation, not keylogging |
| `document.cookie` references | `popup.bundle.js` | Sentry Session Replay network capture module (cookie header redaction) |
| `postMessage` | `background.bundle.js` | Standard webpack async chunk loading / Sentry Replay iframe communication |
| `WebSocket` references | `background.bundle.js` | Listed in Sentry's instrumentation target array, not actively used |
| `navigator.userAgent` | `background.bundle.js` | Sentry SDK environment detection for error reporting context |
| `fingerprint` | `background.bundle.js` / `popup.bundle.js` | Sentry event fingerprinting for error grouping, not browser fingerprinting |
| `createElement("script")` | `background.bundle.js` | Webpack dynamic chunk loading (`530.bundle.js`) |
| `XMLHttpRequest` instrumentation | `popup.bundle.js` | Sentry XHR breadcrumb tracking |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|---|---|---|---|
| `https://1clickvpn.net/api/v1/checks/auth?c={userId}` | GET | Check authentication / premium status | User ID |
| `https://1clickvpn.net/api/v1/servers/?c={userId}` | GET | Fetch VPN server list | User ID |
| `https://api.1clickvpn.net/api/v1/checks/ip/?c={userId}` | GET | Verify VPN connection / get connected country | User ID |
| `https://astrid.1clickvpn.net/44` | POST | Sentry error/event reporting | Full browsing metadata (see HIGH-1), errors, user ID |
| `https://1clickvpn.net/download-vpn` | Tab | Post-install welcome page | None |
| `https://1clickvpn.net/update?type=modal&u={userId}` | Tab | Post-update page | User ID |
| `https://1clickvpn.net/contact/` | Set | Uninstall survey URL | None |

## Data Flow Summary

1. **Install:** UUID generated, stored in `chrome.storage.local`, set as Sentry user ID
2. **Server Sync:** Every 10 minutes (`jf = 600000ms`), fetches server list and auth status from `1clickvpn.net` API with user ID
3. **VPN Connection:** Sets `chrome.proxy.settings` to `fixed_servers` mode with proxy server from server list. Auth handled via `webRequest.onAuthRequired`
4. **Auto-Proxy Mode:** Uses PAC script to selectively proxy blocked domains through VPN
5. **Browsing Data Collection (DEFAULT ON):** Every main-frame request is intercepted. On completion, metadata (URL, referrer, content-type, user ID, timestamp, foreground status) is sent to self-hosted Sentry at `astrid.1clickvpn.net`. 20% server-side sampling rate. Guarded by `vpnDiagnostics` flag (default: enabled)
6. **Error Reporting:** Proxy errors, connection failures, and operational errors reported to Sentry with request context

## Overall Risk: **HIGH**

The extension functions as a legitimate VPN proxy but includes a **default-enabled browsing data collection system** that captures full URLs and referrers for every page navigation, transmitted to the developer's Sentry infrastructure. With ~8 million users and 20% sampling, this represents a massive browsing history dataset. The "VPN Diagnostics" label is misleading as URL-level data is unnecessary for VPN quality monitoring. No malware, remote code execution, or overtly malicious behavior was found -- the risk is purely from the excessive, default-on data collection masquerading as diagnostics.
