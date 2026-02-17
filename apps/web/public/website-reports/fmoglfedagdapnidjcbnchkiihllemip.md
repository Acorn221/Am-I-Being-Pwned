# Vulnerability Report: KeyController Plugin

## Metadata
- **Extension ID**: fmoglfedagdapnidjcbnchkiihllemip
- **Extension Name**: KeyController Plugin
- **Version**: 3.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

KeyController Plugin is a native messaging extension designed for digital signature workflows, specifically for the IVSign KeyController system. The extension monitors all browser navigation events and communicates with a local native host application (`com.ivnosys.ivsign.keycontroller.url`). While the extension has a legitimate enterprise use case (digital signature and authentication), it collects comprehensive browsing data including all URLs visited, tab activity, and window focus events, which are sent to the native application. The extension requests broad host permissions (`*://*/*`) to monitor all web traffic, raising moderate privacy concerns for users who may not fully understand the scope of monitoring.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring
**Severity**: MEDIUM
**Files**: service_worker.js, backgroundv2.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension monitors and transmits all browsing activity to a native application, including:
- All URLs visited across all sites via `webRequest.onBeforeRequest` and `webRequest.onSendHeaders`
- Tab activation and deactivation events
- Window focus changes
- Tab removal events

**Evidence**:
```javascript
// Monitors all web requests
www.webRequest.onBeforeRequest.addListener(
    beforeRequests,
    { urls: ["*://*/*"], types: ["main_frame", "sub_frame"] },
);

// Sends URL data to native host
send(bName + ":url:" + window.id + ":" + info.tabId + ":" + btoa(info.url) + ":" + Date.now());

// Tracks tab activation
www.tabs.onActivated.addListener((activeInfo) => {
    send(bName + ":active:" + activeInfo.windowId + ":" + activeInfo.tabId + ":" + Date.now());
});
```

**Verdict**: The extension's stated purpose is "Allow to sign filtering by URL", which suggests this monitoring is necessary for its digital signature functionality. However, the broad scope of data collection (all URLs, not just signature-related sites) and the fact that data is sent to a local native application (not fully auditable from the extension alone) presents a moderate privacy risk. Users should be fully aware that all browsing activity is being monitored.

### 2. LOW: Overly Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `*://*/*` host permissions, granting access to all websites, when it may only need access to specific domains related to digital signature services.

**Evidence**:
```json
"host_permissions": [
    "https://*/",
    "*://*/*"
]
```

**Verdict**: While the extension includes a URL filtering mechanism (`bannedUrls` and `urlPerm()` function) that can exclude certain domains (default: "clave", "izenpe"), the manifest-level permissions are overly broad. This is common for enterprise monitoring tools but represents a principle of least privilege violation.

## False Positives Analysis

1. **Native Messaging**: The use of `nativeMessaging` permission and communication with `com.ivnosys.ivsign.keycontroller.url` is legitimate for this extension's stated purpose of integrating with digital signature software.

2. **URL Encoding**: The use of `btoa()` to base64-encode URLs before transmission is not obfuscation for malicious purposes, but rather a standard encoding practice for transmitting URLs safely through message channels.

3. **No Code Obfuscation**: The code is clean, readable, and contains Spanish comments indicating legitimate development ("Iniciar conexión al cargar el script" = "Start connection when loading the script").

4. **Filtering Mechanism**: The extension includes logic to filter certain URLs based on configuration received from the native host, suggesting some level of user control over what gets monitored.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host: `com.ivnosys.ivsign.keycontroller.url` | Local native application communication | All browsing URLs (base64-encoded), tab IDs, window IDs, timestamps, browser events | MEDIUM - Data stays local but comprehensive monitoring |

**Note**: This extension does NOT communicate with any external web servers. All data is sent to a local native application via Chrome's native messaging API.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
KeyController Plugin is a legitimate enterprise tool for digital signature workflows (IVSign/IVNosys product), but it collects comprehensive browsing data including all URLs visited, which presents moderate privacy concerns. The extension:

**Legitimate Use Case:**
- Clear association with IVNosys IVSign digital signature software
- Uses native messaging to communicate with local application (not remote servers)
- Includes URL filtering capability controlled by the native application
- No evidence of malicious code or hidden functionality

**Privacy Concerns:**
- Monitors ALL browsing activity across all websites by default
- Sends complete URL history, tab activity, and window focus events to native application
- Requests overly broad `*://*/*` host permissions
- Users may not fully understand the scope of monitoring when installing

**Recommendation**: This extension should only be used in enterprise contexts where comprehensive browser monitoring is required and disclosed. Individual users should understand that all browsing activity is monitored when this extension is active. The extension would benefit from:
1. More granular host permissions limited to signature-related domains
2. Clearer privacy disclosures in the description
3. Visual indicators when monitoring is active
4. User-configurable URL filtering in the extension UI (not just via native host)
