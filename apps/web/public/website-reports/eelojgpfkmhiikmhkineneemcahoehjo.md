# Vulnerability Report: Symantec Extension

## Metadata
- **Extension ID**: eelojgpfkmhiikmhkineneemcahoehjo
- **Extension Name**: Symantec Extension
- **Version**: 15.7.00207.01003
- **Users**: ~700,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

This is an enterprise Data Loss Prevention (DLP) extension from Symantec/Broadcom that monitors all user browsing activity and print operations, transmitting this data to a native host application (com.symantec.dlp) for policy enforcement. The extension tracks active URLs, window focus changes, tab updates, and captures full page HTML content when users attempt to print. While this represents comprehensive monitoring that would be highly concerning in a consumer context, it is a disclosed enterprise security tool designed for corporate environments where such monitoring is expected and typically consented to.

The extension has legitimate enterprise use but raises significant privacy concerns if installed without user knowledge or outside of managed corporate environments.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring and Data Transmission

**Severity**: MEDIUM
**Files**: background.js, ContentScript.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**:

The extension monitors all user browsing activity through multiple mechanisms:

1. **Active URL Tracking**: Captures the URL of the currently active tab whenever:
   - A tab becomes active (onActivated listener)
   - A tab's URL changes (onUpdated listener)
   - Window focus changes (onFocusChanged listener)

2. **Full Browser State Collection**: Gathers URLs from ALL open tabs across all windows when:
   - Any tab is closed (onTabRemoved listener)
   - Any window is closed (onWindowRemoved listener)

3. **Print Content Capture**: The content script monitors print operations and captures the full HTML content of the page body when users attempt to print:
   ```javascript
   var bodyHtmlTextContent = '';
   for (i = 0; i < x.length; i++) {
       bodyHtmlTextContent += x[i].outerHTML;
   }
   SendPrintOperationDetailsToAgent(bodyHtmlTextContent);
   ```

4. **Native Host Communication**: All collected data is transmitted to a native application via nativeMessaging:
   ```javascript
   port_ = chrome.runtime.connectNative('com.symantec.dlp');
   port_.postMessage({"ACTIVE_URL" : tab.url});
   port_.postMessage({"RUNNING_URLS" : urls});
   port_.postMessage({"PRINT_OPERATION":array});
   ```

**Evidence**:

From background.js:
```javascript
onActiveTab: function (activeInfo) {
    chrome.tabs.get (activeInfo.tabId, function (tab) {
        console.log ("ACTIVE_URL: " + tab.url);
        port_.postMessage ({"ACTIVE_URL" : tab.url});
    })
}

onTabRemoved: function (tabsId, removeInfo) {
    var urls = [];
    chrome.windows.getAll({ populate: true }, function(windowList) {
        for (var i = 0; i < windowList.length; i++) {
            for (var j = 0; j < windowList[i].tabs.length; j++) {
                urls.push(windowList[i].tabs[j].url);
            }
        }
        port_.postMessage ({"RUNNING_URLS" : urls});
    })
}
```

From ContentScript.js:
```javascript
function SendPrintOperationDetailsToAgent(PrintContent) {
    var array = {};
    array["URL"] = GetURL();
    array["PRINT_CONTENT"] = PrintContent;
    chrome.runtime.sendMessage({"PRINT_OPERATION":array});
}
```

**Verdict**:

This is a legitimate enterprise DLP tool operating as designed. The monitoring capabilities are extensive but disclosed in the extension description ("Extension works along with Symantec Information Security product for protecting data based on company policy"). In corporate/enterprise environments where such tools are deployed by IT administrators, this behavior is expected and typically part of acceptable use policies.

However, if this extension were to be installed on personal devices without clear consent, or if the native host application were compromised or malicious, the monitoring capabilities would represent a severe privacy violation. The extension provides complete visibility into user browsing behavior and content being printed.

The MEDIUM risk rating reflects that this is an enterprise monitoring tool with disclosed purpose, but the comprehensive nature of data collection warrants attention.

## False Positives Analysis

1. **Native Messaging to DLP Application**: Communication with com.symantec.dlp native host is the core functionality, not malicious data exfiltration. This is how enterprise DLP solutions enforce data loss prevention policies.

2. **Management Permission Usage**: The extension monitors management events (onDisabled, onUninstalled) for logging purposes, not for malicious extension enumeration or anti-detection. The commented-out code suggests potential features to re-enable extensions, but these are not active.

3. **All URLs Permission**: Required for the DLP tool to monitor browsing across all domains as part of its security policy enforcement function.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host: com.symantec.dlp | Local native application communication | Active URLs, all open tab URLs, print content (HTML), window focus state | MEDIUM - Enterprise monitoring tool, data stays local to native host |

Note: No external network endpoints detected. All data transmission is to the local native messaging host application installed on the user's machine as part of the Symantec DLP product suite.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise security tool from a reputable vendor (Symantec/Broadcom) that operates as designed for Data Loss Prevention purposes. The extension's monitoring capabilities are comprehensive and include:
- Real-time tracking of all browsing URLs
- Collection of all open tabs/windows state
- Capture of full page HTML content during print operations
- Transmission of all data to native host application

The MEDIUM rating is assigned because:

**Mitigating Factors:**
- Disclosed purpose in extension description
- Legitimate enterprise use case for DLP/information security
- Data transmitted only to local native host (not external servers)
- Published by reputable enterprise security vendor
- Typically deployed in managed corporate environments with user consent via policy

**Concerns:**
- Extremely broad monitoring permissions (<all_urls>, tabs, management)
- Comprehensive visibility into user browsing behavior
- Captures sensitive content (HTML of pages being printed)
- Could be highly invasive if installed without user knowledge
- Low rating (1.2/5) suggests user dissatisfaction with the monitoring

This extension should only be installed in corporate/enterprise environments where such monitoring is expected, disclosed, and authorized by appropriate policies. Installation on personal devices or without clear user consent would be inappropriate and potentially violate privacy expectations.
