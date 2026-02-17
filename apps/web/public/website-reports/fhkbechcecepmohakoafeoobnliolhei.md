# Vulnerability Report: McAfee DLP Endpoint Extension

## Metadata
- **Extension ID**: fhkbechcecepmohakoafeoobnliolhei
- **Extension Name**: McAfee DLP Endpoint Extension
- **Version**: 2021.09.21.1
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

The McAfee DLP (Data Loss Prevention) Endpoint Extension is a legitimate enterprise security product designed to monitor and prevent unauthorized data uploads from corporate environments. The extension intercepts all browsing activity, file upload attempts, and POST request payloads, forwarding this data to a native McAfee DLP agent running on the host machine via native messaging.

While this is not malware, it represents a significant privacy impact as it monitors all user activity across all websites, captures page text content, intercepts file metadata and upload attempts, and inspects POST request bodies. This level of monitoring is expected and disclosed for enterprise DLP solutions, but end users should be aware that all browsing activity is being monitored when this extension is installed.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing and Data Upload Monitoring

**Severity**: MEDIUM
**Files**: background.js, content.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension monitors all user browsing activity and data uploads, sending this information to a native host application.

**Evidence**:

**Background.js - Active URL Tracking:**
```javascript
chrome.tabs.onActivated.addListener(function (activeInfo) {
    chrome.tabs.get(activeInfo.tabId, function (tab) {
        if (tab.url) {
            port.postMessage({ 'activeurl': { 'id': tab.id.toString() + "-" + tab.windowId.toString(), 'url': tab.url } });
        }
    });
});

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.url && tab.active) {
        port.postMessage({ 'activeurl': { 'id': tabId.toString() + "-" + tab.windowId.toString(), 'url': changeInfo.url } });
    }
});
```

**Background.js - POST Request Interception:**
```javascript
chrome.webRequest.onBeforeRequest.addListener(function (details) {
    let msg = { "url": details.url, "files": [] };
    if ('requestBody' in details && 'raw' in details.requestBody) {
        details.requestBody.raw.forEach(element => {
            if ('file' in element) {
                msg.files.push(element.file)
            }
        });
    }

    if (0 == msg.files.length) {
        if (details.method == "POST" || details.method == "PUT" || details.method == "PATCH") {
            let payload = JSON.stringify(details);
            if (details.requestBody && details.requestBody.raw) {
                for (var i = 0; i < details.requestBody.raw.length; ++i) {
                    if (details.requestBody.raw[i].bytes) {
                        var dv = new DataView(details.requestBody.raw[i].bytes);
                        for (var j = 0; j < dv.byteLength; ++j) {
                            payload += (String.fromCharCode(dv.getInt8(j)));
                        }
                    }
                }
            }
            requestsMap.set(details.requestId, payload);
        }
    }
    return { cancel: false };
}, { urls: ["<all_urls>"] }, ["requestBody"]);

chrome.webRequest.onSendHeaders.addListener(function (details) {
    var payload = requestsMap.get(details.requestId);
    if (payload) {
        for (var i = 0; i < details.requestHeaders.length; i++) {
            if (details.requestHeaders[i].name == "Content-Type") {
                if (details.requestHeaders[i].value == "application/x-www-form-urlencoded") {
                    payload = decodeURIComponent(payload);
                }
                break;
            }
        }
        port.postMessage({ 'post': { 'url': details.url, 'payload': payload } });
    }
}, { urls: ["<all_urls>"] }, ["requestHeaders"]);
```

**Content.js - File Upload Monitoring:**
```javascript
function cacheFile(file) {
    var fName = file.name;
    var fSize = file.size;
    var fModification = file.lastModified;
    pageFiles.add(file)
    chrome.runtime.sendMessage({ 'inputfile': { name: fName, size: fSize, modification: fModification } });
}

document.addEventListener('change', function (e) {
    actOnInputFile(e);
    if (e.target && e.target.files) {
        for (let i = 0; i < e.target.files.length; i++) {
            cacheFile(e.target.files[i]);
        }
    }
}, true);
```

**Content.js - Page Text Extraction:**
```javascript
chrome.extension.onMessage.addListener(
    function (msg, sender, sendResponse) {
        if (msg.pagetext) {
            sendResponse({ 'pagetext': { 'id': msg.pagetext.id, 'text': document.body.innerText } });
        }
    }
);
```

**Verdict**: This is a legitimate enterprise DLP product functioning as designed. The monitoring capabilities are extensive but appropriate for data loss prevention in corporate environments. The extension clearly identifies itself as "McAfee DLP Endpoint Extension" with the stated purpose to "monitor address bar URL and helps to protect corporate data uploads." The data is sent to a local native application (`com.mcafee.dlp_native_messaging_host`) rather than directly to external servers, which is the expected architecture for enterprise DLP solutions.

However, this represents a MEDIUM risk from a privacy perspective because:
1. All browsing URLs are monitored and logged
2. All POST/PUT/PATCH request bodies are captured
3. All file upload attempts (including file metadata) are intercepted
4. Page text content can be extracted on demand
5. The extension runs on all websites (`*://*/*`) and all frames

## False Positives Analysis

The following patterns might appear suspicious but are legitimate for an enterprise DLP tool:

1. **Broad permissions** - The `*://*/*` host permission and `webRequest` permission are required to monitor all web traffic for data exfiltration attempts
2. **POST body interception** - Capturing form submissions and API calls is necessary to detect sensitive data uploads
3. **File monitoring** - Tracking file uploads (including drag-and-drop and Shadow DOM file inputs) is core DLP functionality
4. **Native messaging** - Communication with a local host application is the standard architecture for enterprise security products
5. **Content script on all frames** - Required to monitor file inputs and page content across all iframes

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native messaging host: `com.mcafee.dlp_native_messaging_host` | Local McAfee DLP agent | Active URLs, POST/PUT/PATCH payloads, file metadata, page text (on demand), navigation events | MEDIUM - All data stays local but represents comprehensive monitoring |

**Note**: No external network endpoints are contacted directly by the extension. All data is sent to the local native messaging host, which is part of the McAfee DLP product suite installed on the machine.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise Data Loss Prevention product from McAfee that functions exactly as described. The extension is not malware and does not exhibit deceptive behavior. However, it receives a MEDIUM risk rating due to the significant privacy impact of its monitoring capabilities:

**Why MEDIUM and not CLEAN:**
- Monitors 100% of browsing activity (all URLs visited)
- Intercepts and inspects all POST/PUT/PATCH request bodies
- Captures file upload metadata across all websites
- Can extract page text content on demand
- Runs with all_frames on all URLs
- 300,000+ users may not fully understand the extent of monitoring

**Why MEDIUM and not HIGH:**
- This is disclosed enterprise monitoring, not hidden data collection
- Extension clearly identifies itself as a DLP product
- Data is sent to local native agent, not directly to external servers
- Appropriate for its stated purpose (corporate data protection)
- Published by legitimate vendor (McAfee LLC)

**Recommendation**: This extension is appropriate for managed corporate environments where DLP monitoring is required and disclosed. End users in personal/home environments should be aware that installing this extension means all browsing activity and data uploads are being monitored by the McAfee DLP system.
