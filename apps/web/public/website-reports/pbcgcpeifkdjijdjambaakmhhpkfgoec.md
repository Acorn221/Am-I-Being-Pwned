# Vulnerability Report: SYTools (pbcgcpeifkdjijdjambaakmhhpkfgoec)

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | SYTools |
| Extension ID | pbcgcpeifkdjijdjambaakmhhpkfgoec |
| Version | 26.1100.3 |
| Users | ~4,000,000 |
| Manifest Version | 3 |
| Description | Extension for tight integration between browser and applications built on the Wasaby platform (Russian: "Saby" / formerly "SBIS") |
| Publisher | Tensor (tensor.ru) - Russian enterprise software company |

## Executive Summary

SYTools is a legitimate enterprise integration extension built by Tensor (tensor.ru) for their Saby/SBIS business platform. The extension bridges the browser with locally-installed native applications ("SBIS Plugin") via Chrome's Native Messaging Host (NMH) protocol. Its permissions are broad but consistent with its stated purpose of deep browser-application integration.

The primary concern is an **ActivityMonitor** class (Linux only) that tracks ALL visited URLs (hostnames with timestamps) and transmits them to the local Saby Plugin application via NMH every 5 minutes. While this data only goes to the locally-installed companion app (not to a remote server directly from the extension), the companion app likely relays it to enterprise servers. This is a workplace surveillance feature, consistent with the extension's enterprise deployment context (SBIS is a major Russian business/accounting platform).

The extension also uses the `chrome.debugger` API for HAR recording (network traffic capture), but this is user-initiated and used for debugging support workflows.

No malware, obfuscation, remote code execution, or exfiltration to unauthorized endpoints was found. All domains are scoped to Tensor/Saby-owned infrastructure.

## Vulnerability Details

### MEDIUM: URL Activity Monitoring (Workplace Surveillance)

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| File | `deobfuscated/background.js` (lines 1856-2107) |
| Component | `ActivityMonitor` class |
| Verdict | Intentional enterprise feature, not malware |

**Description:** The `ActivityMonitor` class monitors ALL tab navigation events, window focus changes, and tab activations. It records hostname-level URL data (not full paths) with timestamps and sends this data every 5 minutes to the locally-installed "SBIS Plugin" via NMH using the RPC method `ActivityMonitor.UrlFromExtension`.

**Key code:**
```javascript
// Lines 1856-1861 - Configuration
const AM_SEND_INTERVAL_MS = 5 * 60 * 1000; // 5 minute interval

// Lines 1942-1950 - Registers listeners on ALL tab/window events
start() {
    chrome.tabs.onUpdated.addListener(this.onUpdatedListener);
    chrome.tabs.onActivated.addListener(this.onActivatedListener);
    chrome.windows.onFocusChanged.addListener(this.onFocusChangedListener);
    this.sendIntervalId = setInterval(() => this.sendUrls(), AM_SEND_INTERVAL_MS);
}

// Lines 2000-2011 - Sends URL data to local plugin
this._amService?.callMethod({
    moduleName: 'ActivityMonitor',
    query: JSON.stringify({
        method: 'ActivityMonitor.UrlFromExtension',
        params: {
            browser: 'chrome',
            urls: this._urlsToRecordSetTimestamp()
        }
    })
});
```

**Mitigating factors:**
- Only activates on **Linux** platforms (line 1919: `if (info.os.search('linux') > -1)`)
- Data goes to the locally-installed NMH application, not directly to a remote server
- Records only hostnames, not full URLs (line 2104: `punycode_1.default.toUnicode(urlObj.hostname)`)
- This is a known enterprise feature of the SBIS/Saby platform for workplace activity monitoring

### LOW: Debugger API Usage (HAR Recording)

| Field | Value |
|-------|-------|
| Severity | LOW |
| File | `deobfuscated/background.js` (lines 608-730) |
| Component | HAR recording via `chrome.debugger` |
| Verdict | Legitimate debugging tool, user-initiated |

**Description:** The extension uses `chrome.debugger.attach()` to capture network traffic and generate HAR files. This is user-initiated through the popup UI and used for support/debugging workflows. The `debugger` permission is powerful but used appropriately here.

### LOW: downloads.open Permission

| Field | Value |
|-------|-------|
| Severity | LOW |
| File | `deobfuscated/background.js` (lines 1260-1337) |
| Component | `RunDownloadedFile` class |
| Verdict | Legitimate - opens files downloaded from SBIS update servers only |

**Description:** The extension can open downloaded files, but only those matching the URL pattern `https://.*update.*(sbis\.ru)|(setty\.kz)|(papirus\.tm)/` (line 1803). This is scoped to the publisher's own update servers.

### INFO: Content Script Injection at document_start

| Field | Value |
|-------|-------|
| Severity | INFO |
| File | `deobfuscated/content.js`, `deobfuscated/injectExtensionId.js` |
| Verdict | Benign - sets detection flag |

**Description:** The content script injects a page-level script that sets `window.sbisPluginExtensionInfo = true`. This is a standard presence-detection mechanism for the companion web application. The content script also relays broadcast messages from background to the web page via `window.postMessage`.

### INFO: NMH Communication with Native App

| Field | Value |
|-------|-------|
| Severity | INFO |
| File | `deobfuscated/background.js` (lines 2744-2924) |
| Component | `NmhPort` class |
| Verdict | Expected behavior |

**Description:** The extension communicates with `ru.tensor.sbis_plugin_nmh` native messaging host. This is the core functionality - bridging browser and locally-installed Saby applications (Plugin, Admin, Screen, Cam).

## False Positive Table

| Finding | Reason for FP Classification |
|---------|------------------------------|
| `window.postMessage(message, '*')` in content.js line 168 | Only relays messages from extension background to same-origin web page; wildcard target is standard pattern for content script communication |
| `chrome.scripting.executeScript` in popup | Used for HAR download/upload in MAIN world; scoped to current tab; user-initiated |
| `chrome.runtime.connectNative()` | Legitimate NMH connection to companion application |
| `chrome.debugger.attach()` | User-initiated HAR recording feature, not surveillance |
| `closeStoreWindows()` function | Closes CWS/Opera store tabs showing this extension's page after install - UX convenience, not malicious |

## API Endpoints Table

| Endpoint | Purpose | Transport |
|----------|---------|-----------|
| `ru.tensor.sbis_plugin_nmh` | Native Messaging Host for Saby Plugin communication | NMH |
| `ActivityMonitor.UrlFromExtension` | Sends browsing history to local plugin (Linux only) | NMH RPC |
| `BrowserExtensionSupport.RegisterExtension` | Registers extension with local plugin, sends UserAgent + Chrome version | NMH RPC |
| `BrowserExtensionSupport.SetEventComplete` | Acknowledges notification events | NMH RPC |
| `ServiceInfoProvider.IsTrustedDomain` | Checks if a domain is trusted for notice display | NMH RPC |
| `BaseExtension.destroy` | Cleanup RPC call | NMH RPC |
| `/logreceiver/service/upload_har/` | HAR file upload to Saby cloud (relative URL, executes on Saby pages) | XHR POST |
| `/auth/service/` (ExternalClouds.GetInfo) | Gets allowed domains list (relative URL, executes on Saby pages) | fetch POST |
| `https://api.sbis.ru` | Hardcoded origin for NMH messages | NMH origin |

## Data Flow Summary

1. **Extension <-> Web Pages (Saby domains only):** Content script on Saby domains sets presence flag and relays broadcast messages via `postMessage`. Web pages connect to extension via `chrome.runtime.connectExternal()` (port-based long-lived connections).

2. **Extension <-> Native App (NMH):** All substantive communication goes through `ru.tensor.sbis_plugin_nmh`. The extension acts as a bridge between Saby web pages and locally-installed Saby Plugin applications. Messages are JSON-RPC formatted.

3. **URL Activity Tracking (Linux only):** ActivityMonitor captures hostname + timestamp data for ALL tabs (not just Saby domains) and sends it to local plugin every 5 minutes via NMH.

4. **HAR Recording (User-initiated):** Uses `chrome.debugger` to capture network traffic. HAR files can be downloaded locally or uploaded to the Saby cloud.

5. **App Connectivity Tracking:** Periodically pings local applications (Plugin, Admin, Screen, Cam) via NMH to check their availability and notify web pages.

## Overall Risk Assessment

| Risk Level | **CLEAN** |
|------------|-----------|

**Rationale:** SYTools is a legitimate enterprise integration extension from Tensor (a major Russian enterprise software company). While the ActivityMonitor URL tracking feature is a privacy concern, it is:
- A known enterprise workplace monitoring feature, consistent with the SBIS platform's intended use
- Only active on Linux platforms
- Transmits data only to the locally-installed companion application (not directly to remote servers from the extension)
- Records only hostnames, not full URLs or page content

All permissions (storage, tabs, nativeMessaging, alarms, scripting, downloads, downloads.open, notifications, debugger) are justified by the extension's functionality. Host permissions are tightly scoped to Tensor/Saby-owned domains. No obfuscation, no remote code execution, no unauthorized data exfiltration, no malicious behavior patterns detected. The extension serves its stated purpose of deep browser-enterprise application integration.
