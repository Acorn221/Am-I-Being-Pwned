# Vulnerability Report: Forcepoint One Endpoint for Edge

## Metadata
- **Extension ID**: fdaccoenpeidencmkohekgeelmhiaoji
- **Extension Name**: Forcepoint One Endpoint for Edge
- **Version**: 2.0.85.1
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Forcepoint One Endpoint for Edge is a legitimate enterprise Data Loss Prevention (DLP) browser extension developed by Forcepoint (a well-known cybersecurity company). The extension operates as part of a comprehensive endpoint security solution that monitors and controls data exfiltration through the browser. It communicates exclusively with a local native application running on localhost (ports 55296 and 55053) to enforce corporate data security policies.

While the extension exhibits behavior that would be highly concerning in a consumer context—including monitoring all web traffic, capturing form inputs on print events, intercepting file uploads, and tracking browsing activity—this is expected and disclosed functionality for an enterprise DLP solution. The extension requires administrative deployment and works in conjunction with endpoint security software, making it appropriate for corporate environments where data loss prevention is a legitimate security requirement.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Data Monitoring and Collection
**Severity**: MEDIUM
**Files**: background.js, content.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension implements extensive monitoring of user activity including form inputs, file uploads, web requests, and browsing history. All monitored data is sent to a local native application for policy evaluation.

**Evidence**:

Content script captures form inputs on print events:
```javascript
// content.js
window.onbeforeprint = function (event) {
    var content = "MyInputFieldValues, ";
    var values = [];
    var inputFields = document.getElementsByTagName('textarea');
    for (var i = 0; i < inputFields.length; i++) {
        values.push(inputFields[i].value);
    }
    inputFields = document.getElementsByTagName('input');
    for (var i = 0; i < inputFields.length; i++) {
        values.push(inputFields[i].value);
    }
    var content = content + values.join();
    chrome.runtime.sendMessage(content, function (response) {
        console.log(response);
    });
};
```

Background script intercepts all web requests and file uploads:
```javascript
// background.js
chrome.webRequest.onBeforeRequest.addListener(
    requestCallbackBeforeRequest,
    {urls: ["<all_urls>"]},
    ["blocking", "requestBody"]
);

// Sends browsing activity to local DSE
function SendDetailsUrlVisit(details) {
    var myRequest = new XMLHttpRequest();
    myRequest.open("POST", DSE_BASE_URL + mySessionID, true);
    myRequest.setRequestHeader("X-Visited-Url", details.url.substr(0,2083));
    myRequest.setRequestHeader("X-Method", details.method);
    myRequest.setRequestHeader("X-TimeStamp", details.timeStamp);
    myRequest.send("This is a GET request");
}
```

**Verdict**: In a consumer context, this would be CRITICAL severity due to extensive data collection without user consent. However, as an enterprise DLP tool with disclosed functionality, this is expected behavior. Rated MEDIUM because the extension has appropriate permissions for its purpose, communicates only with localhost, and is designed for managed enterprise deployments. Users should be aware that this extension provides comprehensive monitoring capabilities to IT administrators.

### 2. MEDIUM: Local File Access Monitoring
**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension monitors access to local files (file:/// protocol) and sends file paths and activity to the native application. This includes PDF files and other local content.

**Evidence**:
```javascript
// background.js
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status == "loading") {
        if (typeof tab.url != "undefined") {
            if (tab.url.indexOf("file:///") != -1) {
                tabToUrl[tabId] = tab.url;
                SendUrl(tab.url, "0"); // the tab just changed url
            }
        }
    }
});

// Monitors local PDF files
if (tab.url.indexOf("file:///") != -1 && tab.url.indexOf(".pdf") != -1) {
    tabToUrl[tabId] = tab.url;
    downloadEntity = createDownload('PrintEvent', tab.url, tab.title);
    downloadEntity.downloadFile();
}
```

**Verdict**: While monitoring local file access could expose sensitive file paths and usage patterns, this is a designed feature of enterprise DLP solutions. The extension requires the "file:///" permission which must be explicitly granted. However, users should be aware that local file access is being logged when this extension is active.

### 3. LOW: Cloud Storage Service Monitoring
**Severity**: LOW
**Files**: background.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension implements specific monitoring for popular cloud storage services (Google Drive, OneDrive, SharePoint) to intercept file uploads and downloads from these platforms.

**Evidence**:
```javascript
// Specific handlers for cloud services
function get_sharepoint_file_path(uri) { ... }
function get_onedrive_personal_file_path(uri) { ... }
function is_google_drive_batch_file_upload(requestHeaders) { ... }

// Monitors cloud storage URLs
if (tab.url.indexOf("my.sharepoint.com") != -1) {
    downloadEntity = createDownload('OneDriveForBusiness', tab.url, tab.title);
    downloadEntity.downloadFile();
}
else if (tab.url.indexOf("docs.google") != -1) {
    downloadEntity = createDownload('GoogleDrive', tab.url, tab.title);
    downloadEntity.downloadFile();
}
```

**Verdict**: This is standard DLP functionality designed to prevent data exfiltration through cloud storage services. The monitoring is transparent to administrators deploying the solution and aligns with the extension's stated purpose.

## False Positives Analysis

Several patterns that would typically indicate malicious behavior are actually legitimate for this enterprise DLP extension:

1. **Comprehensive web request interception** - Required for DLP policy enforcement
2. **Form input capture** - Necessary to prevent sensitive data from being printed or copied
3. **Native messaging** - Essential for communication with the local Forcepoint endpoint agent
4. **Blocking web requests** - Core DLP functionality to prevent policy violations
5. **All URLs permission** - Required to monitor data exfiltration across all websites

The extension communicates exclusively with localhost endpoints:
- `http://127.0.0.1:55296/EdgeExt/` - Main DSE (Data Security Engine) endpoint
- `http://127.0.0.1:55053/` - Temporary file endpoint

No external data exfiltration occurs; all communication is with the local native application.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:55296/EdgeExt/ | Main DSE communication | Web requests, file uploads, URLs, form data, browsing history | LOW (localhost only) |
| http://127.0.0.1:55053/ | Temporary file transfer | File contents for scanning | LOW (localhost only) |

Both endpoints are localhost-only, meaning no data leaves the user's machine through the extension itself. The native application may send data to enterprise servers, but that is outside the scope of this browser extension analysis.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise security tool from Forcepoint, a reputable cybersecurity vendor. The extension implements comprehensive data monitoring capabilities that would be extremely concerning in a consumer extension, but are expected and appropriate for an enterprise DLP solution.

**Why MEDIUM and not CLEAN:**
- The extension collects extensive user data including form inputs, browsing history, file uploads, and local file access
- This level of monitoring creates significant privacy implications that users should be aware of
- The extension requires careful deployment and configuration in enterprise environments

**Why MEDIUM and not HIGH/CRITICAL:**
- All communication is with localhost endpoints only (no external data exfiltration by the extension)
- The extension is designed for managed enterprise deployments with IT oversight
- The functionality is disclosed and expected for a DLP solution
- Requires administrative installation and explicit permission grants
- Developed by a well-established security vendor (Forcepoint)

**Recommendations:**
- Should only be deployed in managed enterprise environments
- Users should be informed about the monitoring capabilities
- Not appropriate for personal/consumer use
- Requires the companion native Forcepoint application to function
- Enterprise administrators should ensure proper data handling policies are configured in the backend Forcepoint system
