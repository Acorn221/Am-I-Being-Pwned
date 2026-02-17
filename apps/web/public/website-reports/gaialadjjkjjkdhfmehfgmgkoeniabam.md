# Vulnerability Report: Microsoft Bing Search Engine

## Metadata
- **Extension ID**: gaialadjjkjjkdhfmehfgmgkoeniabam
- **Extension Name**: Microsoft Bing Search Engine
- **Version**: 0.0.0.14
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is an official Microsoft extension that sets Bing as the default search engine in Chrome. The extension is legitimate and performs its stated function transparently. It collects minimal telemetry data (browser version, extension version, locale, OS information) and sends daily usage pings to Microsoft's Customer Experience Improvement Program (CEIP) servers. The extension uses standard tracking parameters (PC codes, channel IDs) for attribution purposes, which is common practice for search engine distribution partnerships.

The code is clean, well-structured, and shows no signs of malicious behavior. The telemetry collection is limited to non-sensitive system information and usage statistics typical of Microsoft products. All network communications are to legitimate Microsoft domains.

## Vulnerability Details

### 1. LOW: Externally Connectable Attack Surface
**Severity**: LOW
**Files**: manifest.json, firstSearchNotificationBackground.js
**CWE**: CWE-284 (Improper Access Control)
**Description**: The extension declares `externally_connectable` with matches for `https://www.bing.com/*` and `https://browserdefaults.microsoft.com/*`, allowing these websites to communicate with the extension via `chrome.runtime.connect()`.

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

**Verdict**: This is a standard pattern for legitimate extensions that need to coordinate with their provider's website. The message handler has proper origin validation (checking sender.url) and only responds with a boolean status flag. It does not expose sensitive data or allow arbitrary command execution. This is acceptable for an official Microsoft extension communicating with Microsoft properties.

## False Positives Analysis

**Telemetry Collection**: The extension sends usage pings to `http://g.ceipmsn.com/8SE/44`, which is Microsoft's Customer Experience Improvement Program endpoint. While this involves data collection, it's limited to:
- Machine ID (randomly generated GUID, not tied to user identity)
- Extension version and name
- Browser version and language
- OS information
- Usage status codes (install, update, daily ping)
- PC/channel codes for distribution attribution

This is standard telemetry for official browser extensions and does not include browsing history, personal data, or sensitive information.

**Cookie Management**: The extension reads and writes cookies to `.bing.com` domain for tracking parameters (`_NTPC`, `_DPC`, `PCCode`, `channel`). This is part of the search provider attribution system and is disclosed in the extension's purpose (setting Bing as default search provider). The extension removes certain cookies after reading them to migrate settings to local storage.

**Search Provider Override**: The manifest includes `chrome_settings_overrides.search_provider` which changes the default search engine. This is the extension's primary stated purpose and is not malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.bing.com | Search provider | Search queries (user-initiated) | None - Expected behavior |
| https://browserdefaults.microsoft.com | Configuration | PC codes, channel IDs (cookies) | Low - Attribution tracking |
| http://g.ceipmsn.com | Telemetry (CEIP) | Extension version, browser version, OS, locale, machine ID, status codes | Low - Standard telemetry |
| https://go.microsoft.com/fwlink/?linkid=2138838 | Uninstall feedback | Extension ID, market, machine ID, browser type | Low - Feedback collection |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate, official Microsoft extension that performs its stated function (setting Bing as the default search engine) transparently. The telemetry collection is minimal and limited to non-sensitive system information and usage statistics, which is standard practice for Microsoft products. The externally_connectable configuration is properly restricted to Microsoft domains and the message handler has appropriate origin validation.

The LOW risk rating is assigned due to:
1. The externally_connectable attack surface, which could theoretically be exploited if the allowed Microsoft domains were compromised
2. Minor privacy considerations around telemetry collection, though this is disclosed through Microsoft's standard privacy policies

No security vulnerabilities or undisclosed privacy practices were identified. The extension does not collect browsing history, personal information, or credentials. All network communications are to legitimate Microsoft endpoints.

For users who trust Microsoft services, this extension presents minimal risk. Users concerned about telemetry can consider alternative search provider extensions or browser-native settings.
