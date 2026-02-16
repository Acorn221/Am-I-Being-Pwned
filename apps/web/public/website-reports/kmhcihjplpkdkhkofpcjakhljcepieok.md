# Vulnerability Report: Forcepoint Endpoint for Windows

## Metadata
- **Extension ID**: kmhcihjplpkdkhkofpcjakhljcepieok
- **Extension Name**: Forcepoint Endpoint for Windows
- **Version**: 2.0.82.1
- **Users**: ~100,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Forcepoint Endpoint for Windows is a legitimate enterprise Data Loss Prevention (DLP) and security monitoring extension designed to work with Forcepoint's endpoint security software. The extension intercepts all web requests (POST/PUT), including file uploads and form submissions, and forwards them to a local DLP service running on 127.0.0.1 for policy-based content inspection and blocking.

While the extension exhibits behavior that would be considered highly invasive in consumer contexts (intercepting all POST/PUT requests, capturing form input values on print, accessing page content via pageCapture), this is expected and disclosed functionality for enterprise DLP software. The data is sent only to localhost services (not external servers), and the extension is designed for enterprise deployments where IT administrators install it on managed endpoints.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Web Request Interception and Data Access

**Severity**: MEDIUM
**Files**: background.js, content.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension intercepts all POST and PUT requests across all URLs, extracts request bodies (including file uploads and form data), and sends them to a localhost DLP service for policy enforcement. Additionally, it captures form input and textarea values when the user attempts to print a page.

**Evidence**:

Content script captures form values on print:
```javascript
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

Background script intercepts all POST/PUT requests:
```javascript
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        if ((chromeExtensionON == true)&& (details.method == "POST" || details.method == "PUT"))
        {
            request_map_cache[details.requestId] = details.requestBody;
        }
        return {cancel: false};
    },
    {urls: ["<all_urls>"]},
    ["blocking", "requestBody"]);

chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        if (chromeExtensionON == false || (details.method != "POST" && details.method != "PUT"))
        {
            return {cancel: false};
        }
        // ... extracts and sends data to localhost DLP service
        QueryDSEForBlock(myRequest, str);
        if (cpsResultAnswer == "BLOCK")
        {
            cpsResultAnswer = "ALLOW";
            wsResultMapCache[msgHash] = new Date().getTime();
            return {cancel: true};
        }
        return {cancel: false};
    },
    {urls: ["<all_urls>"]},
    ["blocking", "requestHeaders"]);
```

Communication with localhost DLP service:
```javascript
const DSE_BASE_URL = "http://127.0.0.1:55296/ChromeExt/"
const DSE_TMP_FILE_URL = "http://127.0.0.1:55053/"

function QueryDSEForBlock(myRequest, str) {
    try {
        myRequest.send(str);
    }
    catch (e) {
        chromeExtensionON = false;
    }
    if (myRequest.readyState == 4) {
        if (myRequest.status == 200) {
            cpsResultAnswer = myRequest.responseText; // "ALLOW" or "BLOCK"
        }
    }
}
```

Native messaging for session ID:
```javascript
chrome.runtime.sendNativeMessage("com.forcepoint.usersessionidprovider",
    { "sessionid" : "Requesting Session ID" }, onSidResponse);
```

**Verdict**: This behavior is expected and disclosed for enterprise DLP software. The extension is designed to monitor and potentially block data exfiltration attempts based on corporate policies. The data is sent to localhost services only (127.0.0.1), not to external servers. However, this represents significant monitoring capabilities that users should be aware of.

## False Positives Analysis

The following patterns appear invasive but are legitimate for this extension type:

1. **Intercepting all POST/PUT requests**: Standard DLP functionality to prevent sensitive data leakage through web uploads and form submissions.

2. **Capturing form input values on print**: Necessary to enforce DLP policies on printed content, as printing can be a data exfiltration vector.

3. **Native messaging**: Used to obtain the Windows session ID for proper user identification in multi-user environments.

4. **Blocking requests**: The extension can block requests (return {cancel: true}) based on DLP policy decisions from the localhost service.

5. **Special handling for cloud storage services**: The extension includes specific parsers for Google Drive, OneDrive, SharePoint, LinkedIn uploads, etc., to extract filenames and content for policy enforcement.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:55296/ChromeExt/ | DLP policy enforcement service | HTTP headers, request bodies, file upload content, form data | LOW - Localhost only |
| http://127.0.0.1:55053/ | Temporary file storage for DLP scanning | File content, multipart form data | LOW - Localhost only |
| Native Message: com.forcepoint.usersessionidprovider | Session ID provider | Session ID request | LOW - Local IPC |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise DLP extension from Forcepoint, a well-known cybersecurity vendor. The extension's invasive monitoring capabilities are expected and disclosed functionality for enterprise security software. Key factors in the risk assessment:

**Mitigating Factors**:
- All data is sent to localhost services (127.0.0.1) only, not external servers
- Extension is designed for enterprise deployments with IT administrator control
- Behavior is consistent with disclosed DLP/security monitoring functionality
- Extension requires companion native application/service to function
- Specific to Windows platforms (as indicated by the name)

**Concerning Factors**:
- Intercepts all POST/PUT requests across all domains
- Captures form input values including potentially sensitive user data
- Has broad permissions (webRequest, webRequestBlocking, pageCapture, nativeMessaging, all URLs)
- Can block user actions based on policy decisions
- Content script runs on all URLs

**Conclusion**: The MEDIUM risk rating reflects that while this is legitimate enterprise software with expected DLP functionality, it represents significant monitoring and data access capabilities that constitute a privacy concern. Users should be aware this extension is monitoring their web activity, and it should only be installed in enterprise/managed environments where such monitoring is disclosed and accepted. For home/personal use, this would be inappropriate, but for enterprise deployments with proper disclosure, this is standard security software.
