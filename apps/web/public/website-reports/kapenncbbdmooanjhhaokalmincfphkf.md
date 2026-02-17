# Vulnerability Report: OpenText Documentum Client Manager

## Metadata
- **Extension ID**: kapenncbbdmooanjhhaokalmincfphkf
- **Extension Name**: OpenText Documentum Client Manager
- **Version**: 0.0.1.7
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

OpenText Documentum Client Manager is a legitimate enterprise extension designed to enhance functionality for OpenText Documentum D2, xCP, Webtop, and eRoom clients. The extension acts as a bridge between web-based Documentum applications and a native desktop application for content transfer operations. While the extension serves a legitimate enterprise purpose, it exhibits concerning privacy and security behaviors including systematic cookie harvesting across all websites and automatic download/installation of native binaries without explicit user consent.

The extension requests broad host permissions (`http://*/*`, `https://*/*`) and harvests cookies from all visited websites, forwarding them to a native messaging host. It also automatically downloads and installs native applications when not found on the system. These behaviors are typical for enterprise document management tools but represent elevated privacy and security risks, particularly if deployed outside of managed corporate environments.

## Vulnerability Details

### 1. MEDIUM: Unrestricted Cookie Harvesting Across All Websites

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension systematically harvests all cookies from any website the user visits and forwards them to a native messaging application. When the content script sends a message to the background page, the background script retrieves ALL cookies for the current tab's URL and includes them in messages sent to the native application.

**Evidence**:
```javascript
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if(sender.tab && request && request.eventType && request.app_name) {
        chrome.cookies.getAll({url: sender.tab.url}, function(cookies){
            request.tabId = sender.tab.id;
            request.cookies = {};
            for( var i = 0; i < cookies.length; i++){
                var currentCookie = cookies[i];
                var cookieName = currentCookie.name;
                request.cookies[cookieName] = currentCookie.value;
            }
            var daemon = getDaemon(request);
            if (daemon !== null){
                daemon.postMessage(request);  // Sends cookies to native app
            }
        });
    }
});
```

**Verdict**: This behavior is concerning because it harvests cookies from ALL websites (not just Documentum sites) and forwards them to a native application. While this may be necessary for the extension's stated purpose of integrating with Documentum systems, the broad scope creates a significant privacy risk. Users may not expect their cookies from unrelated websites to be collected and sent to a native application. The extension should ideally restrict cookie harvesting to only Documentum-related domains.

### 2. MEDIUM: Automatic Download and Installation of Native Applications

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension automatically downloads native application installers without explicit user consent when the native messaging host is not found. The download URL is provided dynamically via the `app_installer_url` parameter in messages from the content script, and the extension downloads the file with `saveAs: false`, meaning the download happens silently without a save dialog.

**Evidence**:
```javascript
function nativeAppNotInstalled(nativePortDisconnectedReason){
    return (nativePortDisconnectedReason.indexOf('host not found') !== -1)
}

function installNativeApplication(request){
    if(request['app_installer_url']){
        var options = {
            url: request['app_installer_url'],
            saveAs: false  // Silent download without user prompt
        };
        chrome.downloads.download(options, function(downloadId){
            localStorage.nativeAppDownloadID = downloadId;
        });
        downloadingNativeApp = true;
    }
}

portObj.port.onDisconnect.addListener(function() {
    var nativePortDisconnectedReason = chrome.runtime.lastError.message;
    if(nativeAppNotInstalled(nativePortDisconnectedReason)){
        installNativeApplication(request);  // Auto-downloads installer
    }
    // ...
});
```

**Verdict**: This automatic download behavior is risky for several reasons: (1) The installer URL comes from web page content via the `app_installer_url` parameter, which could potentially be controlled by a malicious website if the content script logic is exploited. (2) There's no integrity checking (hash verification) of the downloaded binary. (3) The download happens silently without user notification. (4) While the extension doesn't automatically execute the installer, users may unknowingly run malicious code if they execute the downloaded file. This behavior is acceptable only in controlled enterprise environments with proper safeguards.

### 3. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests host permissions for all HTTP and HTTPS sites (`http://*/*`, `https://*/*`), which is broader than necessary for a Documentum-specific tool. The content script is injected into all websites and attempts to detect Documentum applications, but this creates unnecessary attack surface.

**Evidence**:
```json
"host_permissions": [
   "http://*/*",
   "https://*/*"
],
"content_scripts": [{
   "all_frames": true,
   "js": [ "contentScript.js" ],
   "matches": [ "http://*/*", "https://*/*" ]
}]
```

**Verdict**: While the extension does attempt to limit its active functionality to detected Documentum sites (D2, Webtop, xCP, eRoom) using application detection logic, it still runs on every website visited. This increases the attack surface and privacy exposure. A more secure approach would be to use optional permissions and allow users to explicitly grant access to their Documentum domains. However, for an enterprise deployment where Documentum URLs may vary across different installations, this broad permission model may be a necessary design choice.

## False Positives Analysis

**Native Messaging for Enterprise Integration**: The use of native messaging and communication with a local daemon is expected and legitimate for enterprise document management tools that need to interact with desktop file systems and local applications. This is not malicious behavior.

**Cookie Access for SSO**: Harvesting cookies may be necessary for single sign-on (SSO) integration between the browser and the native application in Documentum environments. However, the scope should ideally be limited to Documentum domains only.

**Content Script Detection Logic**: The content script includes extensive detection logic for different Documentum application types (D2, Webtop, xCP, eRoom) by examining script tags and DOM elements. This is legitimate feature detection, not malicious fingerprinting.

**Dynamic Event Dispatching**: The extension creates custom DOM elements and dispatches custom events to communicate with the Documentum web application. This is a standard pattern for browser extension-to-webpage communication and is not malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Messaging Host | Communication with local Documentum daemon | Cookies, tab ID, event data, origin | MEDIUM - Sends sensitive cookie data to native application |
| Dynamic Installer URLs | Downloads native app installers when not found | N/A (download only) | MEDIUM - URL provided dynamically, no integrity check |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise extension for OpenText Documentum integration, but it exhibits privacy and security concerns that warrant a MEDIUM risk rating:

**Reasons for MEDIUM (not HIGH/CRITICAL)**:
1. The extension serves a legitimate enterprise purpose and is published by a known enterprise software vendor (OpenText)
2. Cookie harvesting and native messaging are necessary for the extension's document management functionality
3. The extension includes detection logic to limit active functionality to Documentum applications
4. No evidence of data exfiltration to external servers - communication is limited to local native messaging

**Concerns preventing CLEAN/LOW rating**:
1. Systematic cookie harvesting from ALL websites (not just Documentum domains) creates significant privacy exposure
2. Automatic download of native binaries without explicit user consent and without integrity verification
3. The installer URL is provided dynamically from web content, creating potential security risks
4. Overly broad host permissions increase attack surface unnecessarily

**Recommendation**: This extension should only be deployed in managed enterprise environments where IT administrators can control and monitor its behavior. For general users outside of enterprise Documentum deployments, the privacy and security risks outweigh the benefits. The extension would benefit from limiting cookie access to specific Documentum domains and implementing integrity checks for downloaded binaries.
