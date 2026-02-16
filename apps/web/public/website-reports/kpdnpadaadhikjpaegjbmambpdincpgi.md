# Vulnerability Report: WebStart+ New Tab

## Metadata
- **Extension ID**: kpdnpadaadhikjpaegjbmambpdincpgi
- **Extension Name**: WebStart+ New Tab
- **Version**: 1.0.0.0
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

WebStart+ New Tab is a new tab replacement extension that overrides the default Chrome new tab page with a remotely-hosted web page from `extn.webstart.page`. The extension implements user tracking by generating a unique machine ID and sending periodic "ping" requests to `ping.webstart.page` containing the machine ID, extension ID, version, and distribution channel information. Additionally, the content script uses `window.addEventListener("message")` without origin validation, creating a potential attack surface for cross-site scripting attacks from the hosted page.

While the extension's core functionality (replacing the new tab page) is legitimate and disclosed, the tracking behavior and security vulnerabilities raise privacy and security concerns that warrant a MEDIUM risk rating.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: scripts/content.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The content script registers a message event listener on line 43 without validating the origin of incoming postMessage events. While the script does respond with `postMessage(..., origin)` where origin is constructed from `window.location`, it accepts messages from ANY origin without validation.

**Evidence**:
```javascript
// scripts/content.js:43
window.addEventListener("message", fetchTopSites, false);

function fetchTopSites(eventData) {
    if (eventData.data.id == "fetchTopSites") {
        chrome.runtime.sendMessage({ data: "getTopSites" }, handleTopSitesResponse);
    }
}
```

The function checks `eventData.data.id` but never validates `eventData.origin`. Any page could send this message and trigger the top sites fetch.

**Verdict**: This is a legitimate security concern. While the content script only runs on `https://*.webstart.page/chrome*` (limiting the attack surface), the lack of origin validation means any iframe or window on that domain could trigger the top sites functionality. An attacker who compromises the remote page or injects an iframe could abuse this.

### 2. MEDIUM: User Tracking with Unique Machine ID

**Severity**: MEDIUM
**Files**: scripts/ping.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension generates a unique 32-character machine ID on first install and stores it persistently. This ID, along with the extension ID, version, and channel information, is sent to `http://ping.webstart.page/s/` on install, daily via alarms, and on update.

**Evidence**:
```javascript
// scripts/ping.js:120-128
function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    }
    var machineGUID = s4() + s4() + s4() + s4() + s4() + s4() + s4() + s4();
    machineGUID = machineGUID.toLocaleUpperCase();
    chrome.storage.local.set({ 'machineId': machineGUID });
    return machineGUID;
}

// scripts/ping.js:110-118
function SendPingDetails(status, vid, channel, machineId) {
    var pingURL = 'http://ping.webstart.page/s/?';
    var _vid = !vid ? defaultVID : vid;
    var mid = (machineId == undefined || machineId == "" || machineId == null) ? guid() : machineId;

    pingURL = pingURL + 's=' + status + '&vid=' + _vid + '&mid=' + mid + '&ex=' + ExtensionId + '&ver=' + ExtensionVersion + "&ch=" + channel;
    pingURL = encodeURI(pingURL);
    fetch(pingURL);
}
```

Ping parameters:
- `s`: status (1=install, 2=daily, 3=update)
- `vid`: vendor/version ID (from cookie or default "1")
- `mid`: unique machine ID
- `ex`: extension ID
- `ver`: extension version
- `ch`: distribution channel

**Verdict**: While usage analytics are common, the persistent unique machine ID enables long-term user tracking across installs and updates. The extension description does not disclose this tracking behavior. Additionally, the ping endpoint uses HTTP (not HTTPS), exposing the tracking data to network eavesdropping.

### 3. LOW: Remote Content Loading via Iframe

**Severity**: LOW
**Files**: scripts/loadPage.js, newTab.html
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The new tab page loads remote content from `https://extn.webstart.page/chrome/` via an iframe. The URL includes the extension ID, vendor ID, and channel as query parameters.

**Evidence**:
```javascript
// scripts/loadPage.js:2-6
var ExtensionId = chrome.runtime.id;
var extnUrl = "https://extn.webstart.page/chrome/?eid=" + ExtensionId;

chrome.storage.local.get(['vid', 'channel'], (items) => {
    extnUrl = extnUrl + "&vid=" + items.vid + "&ch=" + items.channel;
});

// newTab.html:6
<iframe id="tab-frame"></iframe>
```

**Verdict**: Loading remote content is the core functionality of a new tab replacement extension and is expected behavior. The use of HTTPS provides transport security. However, this does create a dependency on the remote server for the extension's functionality, and users should be aware that their browsing behavior (opening new tabs) is tracked via the URL parameters.

## False Positives Analysis

The ext-analyzer flagged `window.addEventListener("message")` as an attack surface issue, which is a TRUE POSITIVE. While the content script only runs on `https://*.webstart.page/chrome*`, the lack of origin validation in the message handler is a legitimate security concern.

The cookie access (`chrome.cookies.get`) is used to read distribution channel cookies from `defaults.webstart.page` domain during initial setup, which is legitimate for tracking the installation source but contributes to the tracking behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://ping.webstart.page/s/ | Usage tracking | Machine ID, extension ID, version, status, channel | MEDIUM - Persistent user tracking over unencrypted HTTP |
| https://defaults.webstart.page/ | Distribution channel detection | Cookie read only | LOW - Used during install to detect channel |
| https://extn.webstart.page/chrome/ | New tab content | Extension ID, vendor ID, channel | LOW - Core functionality, expected behavior |
| https://webstart.page/feedback.html | Uninstall feedback | Extension ID, vendor ID, machine ID | LOW - Standard uninstall survey |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension implements undisclosed user tracking with a persistent unique machine ID sent to remote servers on a daily basis. While new tab replacement extensions commonly include analytics, the use of a persistent cross-install tracking identifier and transmission over unencrypted HTTP raises privacy concerns. The postMessage handler vulnerability creates an attack surface where compromised remote content could potentially abuse the top sites API access.

The extension is not malicious in intent (it performs its stated function of providing a custom new tab page), but the combination of:
1. Undisclosed persistent user tracking
2. Unencrypted tracking data transmission (HTTP vs HTTPS)
3. PostMessage handler without origin validation
4. Remote content dependency with query parameter tracking

...collectively warrant a MEDIUM risk rating. Users should be aware that their usage is being tracked with a unique identifier, and the developer should implement origin validation on the message handler and switch to HTTPS for all tracking endpoints.
