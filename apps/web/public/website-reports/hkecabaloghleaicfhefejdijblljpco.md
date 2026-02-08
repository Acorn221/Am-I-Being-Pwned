# Vulnerability Report: Microsoft Bing Search for Chrome

## Metadata

| Field | Value |
|-------|-------|
| Extension Name | Microsoft Bing Search for Chrome |
| Extension ID | hkecabaloghleaicfhefejdijblljpco |
| Version | 1.0.0.19 |
| Manifest Version | 3 |
| Users | ~8,000,000 |
| Publisher | Microsoft |

## Executive Summary

This is an official Microsoft extension that sets Bing as the default search engine in Chrome. It is a relatively simple extension that: (1) overrides the default search provider to Bing, (2) sends installation/update/daily telemetry pings to Microsoft servers, (3) sets tracking cookies on bing.com for partner attribution, (4) shows a welcome/notification page on first search, and (5) uses declarativeNetRequest to rewrite search URL parameters for partner code tracking. The extension requests broad host permissions (`https://*/*`, `http://*/*`) but only uses them for cookie access on bing.com and browserdefaults.microsoft.com. The codebase is small, readable, and free of obfuscation. No malicious behavior, data exfiltration, keylogging, proxy infrastructure, or SDK injection was found. All network calls go exclusively to Microsoft-owned domains.

## Vulnerability Details

### 1. Broad Host Permissions (INFO)

| Field | Detail |
|-------|--------|
| Severity | INFO |
| File | `manifest.json` (lines 28-31) |
| Verdict | False Positive / Acceptable |

```json
"host_permissions": [
    "https://*/*",
    "http://*/*"
]
```

The extension requests access to all HTTP/HTTPS URLs. However, in practice these permissions are only used by the `cookies` permission to read/write cookies on `bing.com` and `browserdefaults.microsoft.com`. The `scripting` permission is used only to inject the first-search notification content script into Bing search result pages. No content scripts are registered in the manifest to run on arbitrary pages. This is overly broad but functionally benign -- a narrower host permission scope for `*.bing.com` and `*.microsoft.com` would be more appropriate.

### 2. Telemetry Ping with Machine ID (LOW)

| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `scripts/ping.js` |
| Verdict | Expected Behavior |

```javascript
function SendPingDetails(e) {
    // Collects: partner code, channel, machine ID (random GUID), OS version, browser version, extension version
    var s = "MI=" + t[MACHINE_ID] + "&LV=" + ExtensionVersion + "&OS=" + n + "&TE=37&" + c;
    i = i + "UD=" + (s = btoa(encodeURI(s))) + "&ver=2";
    fetch(i);
}
```

The extension sends daily pings and install/update pings to `go.microsoft.com/fwlink/?linkid=2243942` with base64-encoded telemetry data. The data includes a self-generated random GUID (not tied to any PII), extension version, OS version, browser version, partner code, and channel. This is standard Microsoft telemetry for tracking extension installation metrics. The machine ID is generated locally via `guid()` using `Math.random()` and stored in chrome.storage.

### 3. Instrumentation Tracking POST Request (LOW)

| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `scripts/ping.js` |
| Verdict | Expected Behavior |

```javascript
function getLoadData_InstrumentationTracking(e, t, r, n, a, o, i, c) {
    var s = {
        partnercode: e, os: operatingSystemVersion(), mkt: t,
        browser: getBrowserVersion(), xid: r, channel: n,
        machineid: o, browserVersion: ..., currenturl: c,
        eventId: i, bcex: a
    };
    fetch("https://browserdefaults.microsoft.com/api/hpinst/InstrumentationTracking", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(s)
    });
}
```

Sends instrumentation data to Microsoft's browserdefaults API. Called on install and first-search events. Includes the current URL (the extension URL on install, the first Bing search URL on FSN). This is standard telemetry and only fires on specific lifecycle events, not on every page visit.

### 4. Cookie Manipulation on bing.com (LOW)

| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `scripts/ping.js` |
| Verdict | Expected Behavior |

```javascript
chrome.cookies.set({url: bingUrl, domain: ".bing.com", name: "_SS", value: r, sameSite: "no_restriction", secure: true});
chrome.cookies.set({url: bingUrl, domain: ".bing.com", name: "_DPC", value: e.dpc});
chrome.cookies.set({url: bingUrl, domain: ".bing.com", name: "_NTPC", value: e[PARTNER_CODE] ? e[PARTNER_CODE] : defaultPC});
```

Sets multiple cookies on `.bing.com` for partner attribution (`_SS`, `_DPC`, `_NTPC`). Also reads a cookie from `browserdefaults.microsoft.com` to extract installation channel/partner information. All cookie operations are limited to Microsoft-owned domains and serve the legitimate purpose of attribution tracking.

### 5. Search URL Rewriting via declarativeNetRequest (LOW)

| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `scripts/ping.js` |
| Verdict | Expected Behavior |

```javascript
function addSearchRedirectRule(e, t, r, n) {
    var o = {
        id: e, priority: 1,
        action: {type: "redirect", redirect: {transform: {queryTransform: {
            addOrReplaceParams: [{key: "form", value: "BGGCDF"}, {key: "pc", value: t || r}]
        }}}},
        condition: {urlFilter: n, resourceTypes: ["main_frame"]}
    };
    chrome.declarativeNetRequest.updateDynamicRules({addRules: [o], removeRuleIds: [e]});
}
```

Rewrites Bing search URLs to add/replace `form` and `pc` query parameters for partner attribution. This only applies to URLs matching `*://*.bing.com/search?EID=MBSC&form=BGGCMF&pc=BG02*`. This is the core intended functionality of the extension.

### 6. Full-page Iframe Overlay on First Search (LOW)

| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `scripts/firstSearchNotificationContent.js` |
| Verdict | Expected Behavior (UX concern) |

```javascript
var firstSearchNotificationFrame = createIframe(firstSearchNotificationSource, "firstSearchNotification");
body.appendChild(firstSearchNotificationFrame);
// Creates a full-screen iframe overlay from bing.com
```

On the user's first Bing search after installation, the content script injects a full-page iframe overlay from `www.bing.com/browserextension/bingsearchplus/firstsearchoverlay`. This is a one-time notification to confirm the search provider change. The overlay is dismissed on window focus or click. While visually intrusive, it is a one-time occurrence from a first-party domain.

### 7. External Message Listener (INFO)

| Field | Detail |
|-------|--------|
| Severity | INFO |
| File | `scripts/firstSearchNotificationBackground.js` |
| Verdict | Expected Behavior |

```javascript
chrome.runtime.onMessageExternal.addListener(function(e, t, i) {
    if (t && t.url && t.url.toLocaleLowerCase().includes("https://browserdefaults.microsoft.com/")
        && "isExtensionEnabled" == e) {
        // responds with {isEnabled: "true"} after notification dismissed
    }
});
```

The extension accepts external messages from `browserdefaults.microsoft.com` and `www.bing.com` (as declared in `externally_connectable`). The only accepted message is `"isExtensionEnabled"` which returns a simple status boolean. The `onConnectExternal` listener from `bing.com` similarly only responds to `"pollExtensionStatus"`. These are tightly scoped and pose no security risk.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignment | `Welcomepage/scripts/json.js` | Sets localized text strings (`Step2a`, `Step1a`) from extension's own bundled JSON locale files. No user input involved. |
| Broad host_permissions | `manifest.json` | Used only for cookie access on Microsoft domains; no content scripts registered on arbitrary pages. |
| `btoa(encodeURI(...))` | `scripts/ping.js` | Base64-encodes telemetry for URL parameter transport; not obfuscation. |
| `importScripts` with error swallowing | `scripts/rootServiceWorker.js` | Catches errors from empty bundle files (background.bundle.js is 0 bytes); standard defensive coding. |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://go.microsoft.com/fwlink/?linkid=2243942` | GET | Telemetry ping (install/update/daily) | Base64-encoded: machine GUID, extension version, OS, browser version, partner code, channel |
| `https://go.microsoft.com/fwlink/?linkid=2249817` | GET (tab open) | Welcome/onboarding page after install | Partner code, browser, market, channel, machine ID in URL params |
| `https://browserdefaults.microsoft.com/api/hpinst/InstrumentationTracking` | POST | Install/FSN event instrumentation | Partner code, OS, market, browser, extension ID, channel, machine ID, current URL, event ID |
| `https://www.bing.com/browserextension/bingsearchplus/firstsearchoverlay` | GET (iframe) | First-search notification overlay | Market, language in URL params |
| `https://go.microsoft.com/fwlink/?linkid=2179704` | GET (iframe) | "Change it back" notification | Extension version, market in URL params |
| `https://go.microsoft.com/fwlink/?linkid=2138838` | GET (uninstall URL) | Feedback survey on uninstall | Extension ID, market, machine ID, browser in URL params |

## Data Flow Summary

1. **Installation**: Extension reads partner attribution cookie from `browserdefaults.microsoft.com`, generates a random machine GUID, stores partner code/channel/machine ID in `chrome.storage.local`, sets attribution cookies on `.bing.com`, sends install ping to Microsoft, opens welcome tab.

2. **Search Override**: Sets Bing as default search engine via `chrome_settings_overrides`. Uses `declarativeNetRequest` to rewrite Bing search URL parameters with partner tracking codes (`form`, `pc`).

3. **First Search**: On the first Bing search in Chrome (not Edge), injects a one-time full-page iframe notification from bing.com, then sends an FSN instrumentation event to Microsoft.

4. **Daily Ping**: Every 24 hours via `chrome.alarms`, sends a telemetry ping with the self-generated machine GUID, refreshes attribution cookies on bing.com, and updates the uninstall feedback URL.

5. **External Communication**: Responds to status polls from `bing.com` and `browserdefaults.microsoft.com` with a simple boolean indicating whether the extension is active and acknowledged.

6. **Data Storage**: All data stored locally in `chrome.storage.local`: machine ID (random GUID), partner code, channel, market, DPC (derived partner code). No PII is collected or transmitted.

## Overall Risk: **CLEAN**

This is a legitimate Microsoft first-party extension that performs its stated function (setting Bing as the default search engine) with standard telemetry and partner attribution tracking. The permissions are broader than necessary (all-hosts when only Microsoft domains are accessed), but the actual code behavior is tightly scoped to Microsoft-owned domains. There is no evidence of data exfiltration, keylogging, proxy infrastructure, SDK injection, extension enumeration, or any malicious behavior. All network communication goes exclusively to Microsoft endpoints. The codebase is small (~500 lines of readable JavaScript), unobfuscated, and straightforward.
