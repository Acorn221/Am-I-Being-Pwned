# Vulnerability Report: Microsoft Bing Homepage & Search Engine

## Metadata
- **Extension ID**: cflanjgoamglnnocilcllegbbbfogfjc
- **Extension Name**: Microsoft Bing Homepage & Search Engine
- **Version**: 0.0.0.15
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is an official Microsoft browser extension that sets Bing as the default homepage and search engine. The extension performs telemetry and usage tracking by sending pings to Microsoft servers (`g.ceipmsn.com`), which is standard for Microsoft products. The extension uses `externally_connectable` to allow communication with Bing and Microsoft domains, which increases attack surface but is necessary for its stated functionality. The extension's behavior is transparent and aligned with its advertised purpose. While the extension has a low user rating (1.7/5), this appears to reflect user dissatisfaction with homepage/search hijacking rather than malicious behavior.

The extension collects basic telemetry data (extension version, browser version, OS, language, machine ID) and sends it to Microsoft's telemetry service. It also manages cookies and settings related to tracking codes for analytics purposes. All data collection is consistent with what users would expect from a Microsoft product.

## Vulnerability Details

### 1. LOW: externally_connectable Attack Surface

**Severity**: LOW
**Files**: manifest.json, firstSearchNotificationBackground.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension exposes external connectivity to `https://www.bing.com/*` and `https://browserdefaults.microsoft.com/*`. This allows web pages on these domains to send messages to the extension via `chrome.runtime.connect()` or `chrome.runtime.sendMessage()`. While limited to Microsoft-owned domains, this creates an attack surface if those domains are compromised or have XSS vulnerabilities.

**Evidence**:
```json
"externally_connectable": {
   "matches": [ "https://www.bing.com/*", "https://browserdefaults.microsoft.com/*" ]
}
```

```javascript
chrome.runtime.onConnectExternal.addListener((port) => {
    var url = "https://www.bing.com";
    if (port.name == "extensionStatusCheck" && port.sender && port.sender.url && port.sender.url.toLocaleLowerCase().includes(url)) {
        port.onMessage.addListener((message, port) => {
            if (message === "pollExtensionStatus") {
                chrome.storage.local.get("firstSearchNotificationDismissed", (items) => {
                    if (items.firstSearchNotificationDismissed) {
                        port.postMessage({isEnabled: "true"})
                    }
                });
            }
        });
    }
});
```

**Verdict**: This is a standard pattern for legitimate extensions that need to communicate with their web services. The extension validates the sender URL and limits functionality to non-sensitive status checks. Risk is minimal given Microsoft's security controls on these domains.

## False Positives Analysis

1. **Telemetry/Tracking**: The extension sends pings to `g.ceipmsn.com` with extension metadata, browser information, and a machine ID. This is standard telemetry for Microsoft products and is expected behavior for an official Microsoft extension.

2. **Cookie Manipulation**: The extension reads and sets cookies in the `.bing.com` domain to manage tracking codes (`_NTPC`, `_DPC`, `PCCode`, `channel`). This is necessary for the extension's core functionality of managing Bing search defaults and analytics.

3. **chrome.management Permission**: Used only to listen for the extension being enabled/disabled, not to manipulate other extensions. This is legitimate functionality.

4. **chrome.scripting Permission**: Used only to inject a first-search notification banner on Bing search results. The injected script is benign and only displays a notification overlay.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.bing.com | Search provider, homepage | User searches, cookies | Low - Expected functionality |
| browserdefaults.microsoft.com | Extension configuration | Extension ID, cookies | Low - Microsoft infrastructure |
| g.ceipmsn.com | Telemetry/ping endpoint | Extension metadata, browser version, OS, machine ID, language, status codes | Low - Standard Microsoft telemetry |

### Telemetry Data Structure
The ping sent to `g.ceipmsn.com` includes:
- Machine ID (randomly generated GUID)
- Extension version
- OS information
- Browser version
- Language
- Extension status codes (install=1, daily=2, update=3)
- Tracking codes (PC, channel, DPC)

All telemetry is non-sensitive browser metadata typical of Microsoft products.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate Microsoft extension that performs its advertised function of setting Bing as the default search engine and homepage. While it collects telemetry data and uses `externally_connectable`, these behaviors are:

1. **Expected**: Users installing a Microsoft Bing extension would reasonably expect Microsoft telemetry
2. **Transparent**: The extension's functionality aligns with its description
3. **Limited Scope**: Permissions are appropriate for the stated functionality
4. **Minimal Risk**: No sensitive data exfiltration, no code injection beyond benign notification banners, no credential harvesting

The low user rating (1.7/5) likely reflects user dissatisfaction with homepage/search engine hijacking rather than security concerns. The extension's behavior is consistent with typical first-party browser extensions from major tech companies.

The `externally_connectable` feature is the only notable attack surface, but it's restricted to Microsoft-owned domains and implements basic sender validation. Overall, this extension presents minimal security or privacy risk beyond what users would expect from a Microsoft product.
