# Vulnerability Report: Liquidware Browser Monitor

## Metadata
- **Extension ID**: fcdgffmdaoiofonjahbdpglcdodgkaii
- **Extension Name**: Liquidware Browser Monitor
- **Version**: 1.3.2
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Liquidware Browser Monitor is a legitimate enterprise monitoring tool developed by Liquidware Labs for their Stratusphere UX product. The extension collects detailed browsing telemetry including open tab URLs, tab titles, installed extensions, and system idle state, then transmits this data to a native host application (lwl-chrome-monitor.exe) running on the corporate endpoint. This data collection is extensive and would be concerning in a consumer context, but it is intentional functionality for enterprise endpoint monitoring and user experience analytics in managed corporate environments.

The extension operates transparently within its stated purpose as an enterprise monitoring solution. While it collects sensitive browsing data, this is the core functionality expected from a corporate monitoring tool deployed by IT administrators.

## Vulnerability Details

### 1. MEDIUM: Extensive Browsing Data Collection and Transmission

**Severity**: MEDIUM
**Files**: background.js, offscreen.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**:

The extension collects comprehensive browsing activity data and transmits it to a native messaging host application. The collected data includes:

1. **Tab Information** (via `sendTabInfo()`):
   - All open tab URLs (encoded)
   - Tab titles
   - Active/inactive status
   - Window organization

2. **Extension Information** (via `sendExtensionInfo()`):
   - Names of all installed browser extensions
   - Extension versions
   - Extension types
   - Extension permissions
   - Enabled/disabled status

3. **System Idle State** (via `sendIdleInfo()`):
   - Current user activity state (active/idle/locked)
   - Time since last state change

This data is collected every minute (configurable via native host) and sent to the native messaging host identified as `com.lwl.chrome.monitor`.

**Evidence**:

```javascript
// background.js - Data collection functions
async function sendTabInfo() {
    let windowList = null;
    await chrome.windows.getAll(
        {populate : true}
    ).then((ret) => {
        windowList = ret;
    });
    // Send to offscreen for XML formatting
    const xmlTabs = await chrome.runtime.sendMessage({
        type: 'get-tab-stats',
        target: OFFSCREEN_TARGET,
        data: windowList
    });
    return xmlTabs;
}

async function sendExtensionInfo() {
    let info = null;
    await chrome.management.getAll().then((ret) => {
        info = ret;
    });
    // Send to offscreen for XML formatting
    const xmlExt = await chrome.runtime.sendMessage({
        type: 'get-extension-stats',
        target: OFFSCREEN_TARGET,
        data: info
    });
    return xmlExt;
}
```

```javascript
// offscreen.js - Tab data XML formatting
async function getTabStats(windowList) {
    for (var i = 0; i < windowList.length; i++) {
        for (var j = 0; j < windowList[i].tabs.length; j++) {
            const tab = windowList[i].tabs[j];
            var TabNode = document.createElement("tab");
            // Collects tab ID, title, active state, and URL
            var Node = document.createElement("url");
            var niceurl = encodeURI(tab.url);
            Node.appendChild(document.createTextNode(niceurl));
            TabNode.appendChild(Node);
        }
    }
}
```

```javascript
// background.js - Transmission to native host
function sendNativeMessage(data) {
    if (port == null) {
        doSetupSteps();
    }
    if (data && data.length > 0) {
        let finalXml;
        if (browserType) {
            finalXml = `<summaryReport><browserType>${browserType}</browserType>${data}</summaryReport>`;
        }
        port.postMessage(finalXml);
    }
}
```

**Verdict**:

This behavior is **EXPECTED** for an enterprise monitoring tool. The extension explicitly identifies itself as "Liquidware's Stratusphere™ UX browser monitor" and is designed for corporate IT departments to monitor user experience metrics on managed endpoints. The data collection aligns with the extension's stated purpose.

However, this is rated as MEDIUM severity because:
- The data collected is highly sensitive (complete browsing history in real-time)
- Users in enterprise environments may not be fully aware of the extent of monitoring
- The extension requires explicit deployment by IT administrators (not user-installed)
- The use of `nativeMessaging` permission ensures it can only communicate with pre-installed native applications

In a consumer context, this would be HIGH/CRITICAL, but for enterprise endpoint monitoring software deployed by administrators, MEDIUM is appropriate.

## False Positives Analysis

Several patterns that might appear suspicious in typical extensions are legitimate here:

1. **Extension Enumeration via `chrome.management.getAll()`**: This appears in the `extension_enumeration` flag category, but it's core functionality for an enterprise monitoring tool that tracks installed software on corporate endpoints.

2. **Comprehensive Tab Access**: While the extension has `tabs` permission and reads all URLs/titles, this is the intended purpose of a browser monitoring solution for user experience analytics.

3. **Native Messaging**: The use of `nativeMessaging` to send data to a local application is appropriate for enterprise software that integrates with endpoint management systems.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host: `com.lwl.chrome.monitor` | Local native messaging host | XML-formatted browsing data (tabs, extensions, idle state) | LOW (requires pre-installed native app) |

No external network endpoints were identified. All data transmission occurs locally via Native Messaging API to the `com.lwl.chrome.monitor` native host application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Liquidware Browser Monitor is a legitimate enterprise monitoring tool that performs exactly as designed. The extensive data collection (browsing history, installed extensions, user activity state) would be highly concerning in a consumer extension, but is expected and appropriate for corporate endpoint monitoring software.

The MEDIUM rating reflects:
- **Legitimate Use Case**: Enterprise UX monitoring is a valid business purpose
- **Transparent Functionality**: The extension name and description clearly indicate its monitoring purpose
- **Deployment Model**: Requires IT administrator installation via enterprise policy (not user-installed from Chrome Web Store)
- **No Deception**: Code is clean, well-commented, and copyright-marked by Liquidware Labs
- **Local-Only Communication**: Uses Native Messaging to communicate with local endpoint agent, not external servers
- **Configurable Sampling**: Native host can adjust collection interval (default 1 minute)

**Concerns**:
- Employees may not fully understand the extent of monitoring
- Collects complete browsing history including potentially personal use on corporate devices
- No apparent user controls or opt-out mechanisms (by design for enterprise monitoring)

**Recommendation**: This extension is safe for its intended enterprise use case. Organizations deploying it should ensure proper disclosure to employees regarding the scope of monitoring in accordance with privacy laws and employment agreements.
