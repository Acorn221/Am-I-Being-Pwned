# Vulnerability Report: Symantec Extension

## Metadata
- **Extension ID**: egaejpfbkjamgheoingidhokbfnidlpi
- **Extension Name**: Symantec Extension
- **Version**: 1.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate enterprise Data Loss Prevention (DLP) extension from Symantec that monitors file upload activities on all websites and communicates with a native host application. The extension intercepts paste, drop, and file selection events across all web pages to collect metadata about files being uploaded (filename, last modified timestamp, and URL). This information is then forwarded to a native application (`com.symantec.dlp`) that presumably enforces corporate data policies. While the extension has broad monitoring capabilities that would be concerning in a consumer context, it is operating as designed for enterprise security monitoring.

The extension is rated MEDIUM risk due to its extensive monitoring capabilities and lack of transparency for end users who might not be aware of the level of monitoring, but it is not malicious software.

## Vulnerability Details

### 1. MEDIUM: Enterprise File Upload Monitoring

**Severity**: MEDIUM
**Files**: ChromeContentScript.js, ChromeBackgroundScript.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension monitors all file interactions (paste, drag-and-drop, file input changes) across every website the user visits. It collects file metadata including filenames, last modified timestamps, and the URL where the action occurred, then sends this data to a native host application via `chrome.runtime.connectNative()`.

**Evidence**:

Content script monitors three event types globally:
```javascript
function addDLPEventListeners() {
  document.addEventListener("paste", onPaste, !0);
  document.addEventListener("drop", onDrop, !0);
  document.addEventListener("change", onChange, !0)
}
```

File metadata collection:
```javascript
function SendFileDetailsToAgent(b) {
  var a = {};
  a.URL = getURL();
  a.FILE = [];
  for (const [c, d] of b.entries()) a.FILE.push({
    name: c,
    time: parseInt(d)
  });
  chrome.runtime.sendMessage({
    FILE_UPLOAD: a
  });
  wait(500)
}
```

Background script forwards to native host:
```javascript
onMessageFromCS: function(d) {
  null !== port_ && port_.postMessage(d)
}
```

Native messaging connection:
```javascript
port_ = chrome.runtime.connectNative("com.symantec.dlp")
```

The background script also monitors active tabs and sends URL information:
```javascript
onActiveTab: function(d) {
  null !== port_ && chrome.tabs.get(d.tabId, function(a) {
    port_.postMessage({
      ACTIVE_URL: a.url
    })
  })
}
```

**Verdict**: This is legitimate enterprise DLP functionality. The extension is designed to monitor and prevent sensitive data exfiltration in corporate environments. However, it represents a privacy concern if deployed without user consent or awareness, as it monitors all file-related activity across all websites. The data is sent to a local native application rather than to remote servers, which is appropriate for enterprise monitoring.

## False Positives Analysis

The following patterns might appear suspicious but are legitimate for an enterprise DLP extension:

1. **Global event listeners on `<all_urls>`** - Required to monitor file upload activities across all websites
2. **File metadata collection** - This is the core purpose of DLP software; it needs to track what files are being uploaded
3. **Native messaging** - DLP extensions communicate with local enforcement agents rather than remote servers
4. **Broad permissions** (`<all_urls>`, tabs, scripting) - Necessary for comprehensive monitoring in enterprise environments
5. **Content script injection on install** - Ensures monitoring is active on already-open tabs

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| com.symantec.dlp (Native) | Local DLP agent | File metadata (name, timestamp), URLs | Low - local only |

No external network endpoints detected. All communication is with a local native messaging host.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise security tool from Symantec designed for Data Loss Prevention. The extension functions as designed by monitoring file upload activities and reporting to a local DLP agent. The MEDIUM rating reflects:

1. **Appropriate for intended use**: In a corporate environment with user consent and awareness, this is standard enterprise security software
2. **Privacy implications**: The extension has extensive monitoring capabilities across all websites, tracking all file interactions
3. **Transparency concerns**: End users may not be fully aware of the extent of monitoring
4. **No remote exfiltration**: Data stays local, sent only to the native host application
5. **Legitimate vendor**: Symantec is a well-known enterprise security vendor

**Recommendation**: This extension should only be deployed in managed enterprise environments where:
- Users are informed about the monitoring
- The organization has legitimate data protection requirements
- Deployment is controlled through enterprise policy (not voluntary user installation)

If found on a personal device or installed without user awareness, it would represent a significant privacy concern and should be removed.
