# Vulnerability Report: Trend Micro Toolbar for Enterprise

## Metadata
- **Extension ID**: iiipkionnkhdcficbbpionjlfmnjgnlg
- **Extension Name**: Trend Micro Toolbar for Enterprise
- **Version**: 0.0.0.22
- **Users**: ~3,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Trend Micro Toolbar for Enterprise is a legitimate corporate security tool designed for enterprise Data Loss Prevention (DLP) and web reputation filtering. The extension monitors file uploads/downloads across major cloud storage providers (Google Drive, OneDrive, Dropbox, Gmail, Yahoo, Outlook) and tracks web browsing activity. All collected data is sent to a native host application (`com.trendmicro.chrome.dlp`) for analysis and policy enforcement.

While this is a legitimate enterprise monitoring solution, it collects extensive user data including Chrome user emails, cloud storage account information, file hashes, browsing URLs, and file paths. This represents significant privacy implications for end users, though this behavior is expected and disclosed for enterprise DLP solutions. The extension is rated MEDIUM risk due to its broad data collection scope and reliance on external native messaging for policy decisions.

## Vulnerability Details

### 1. MEDIUM: Extensive User Data Collection for Corporate Monitoring

**Severity**: MEDIUM
**Files**: ddr.js, ddr_bg.js, background.js, wtp.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects comprehensive user activity data including:
- Chrome user email addresses via `chrome.identity.getProfileUserInfo` and `identity.email` permission
- Cloud storage account information (Google, OneDrive, Dropbox account usernames)
- File upload/download metadata (file names, SHA-1 hashes, timestamps, paths)
- Full browsing URLs on all websites
- Cloud storage folder paths and file locations

**Evidence**:

From `ddr_bg.js`:
```javascript
async function getChromeUser() {
    const email = await new Promise((resolve, reject) => {
        chrome.identity.getProfileUserInfo(function (userInfo) {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError.message);
                return reject(chrome.runtime.lastError.message);
            }
            resolve(userInfo.email);
        });
    });
    return email
}

export async function collateDownloadData(rawData) {
    var dataInfo = {
        FileHash: "",
        BrowserType: "chrome",
        Type: "download",
        URI: storageInfo[4],
        BrowserUser: await getChromeUser(),
        User: storageInfo[2],
        Provider: storageInfo[1],
        From: storageInfo[0],
        To: rawData[0].filename,
        Timestamp: generateTimestamp()
    };
    await sendNativeMessage(message);
}
```

From `ddr.js`:
```javascript
async function handleFiles(files) {
    for (let i = 0; i < files.length; i++) {
        let file = files[i];
        let hashHex = await generateSHA1HashFromFile(file)
        chrome.runtime.sendMessage({fileName: file.name, hash: hashHex.toString()});
    }
}

function getAccountUser(url) {
    if (hasUrl(url, 'drive.google.com')) {
        googleAccount = document.querySelector('.gb_B.gb_Za.gb_0');
    }
    if (hasUrl(url, 'dropbox')) {
        // Extracts email from Dropbox page scripts
        dropboxAccount = jsonData?._viewer_properties?._user_data?.[0]?.email;
    }
    if (hasUrl(url, 'sharepoint')) {
        oneDriveAccount = document.getElementById("O365_MainLink_Me")
    }
}
```

**Verdict**: This is expected behavior for an enterprise DLP/monitoring tool. However, the broad scope of data collection (email addresses, cloud account info, file hashes, full URLs) represents significant privacy implications. Users should be aware this extension provides comprehensive corporate monitoring of their browsing and file activity.

### 2. MEDIUM: Native Messaging Dependency for Security Decisions

**Severity**: MEDIUM
**Files**: utils.js, wtp.js, wtp_bg.js, background.js
**CWE**: CWE-471 (Modification of Assumed-Immutable Data)
**Description**: The extension relies on a native messaging host (`com.trendmicro.chrome.dlp`) for all security policy decisions including web reputation filtering and DLP enforcement. If the native host is compromised or misconfigured, the extension's security posture is entirely controlled by external processes.

**Evidence**:

From `utils.js`:
```javascript
async function ensurePortConnectNative() {
    if (port == null) {
        const hostName = "com.trendmicro.chrome.dlp";
        console.log("Connecting to native messaging host " + hostName);
        const nativePort = chrome.runtime.connectNative(hostName);
        nativePort.onMessage.addListener(onNativeMessage);
    }
}

export async function sendNativeMessage(message) {
    await ensurePortConnectNative();
    console.log("Message sent to native app: ", message);
    port.postMessage(message);
}
```

From `wtp.js`:
```javascript
var sending = chrome.runtime.sendMessage({
    "type": "wtpData",
    "params": {url:document.location.href}
},function(response) {
    handleResponse(response);
});

function handleResponse(message) {
    // Blocks page based on native app response
    if(document.contentType == "application/xml") {
        window.location.replace(chrome.runtime.getURL('block_page.html'));
    } else {
        var htmlObj = document.getElementsByTagName("html")[0];
        htmlObj.innerHTML = message.databc;
        window.stop();
    }
}
```

**Verdict**: The extension's security functionality is entirely dependent on the native messaging host. The extension sends every URL visited to the native app and blocks pages based on the response. This architecture introduces a single point of failure and requires trust in the native application's security and proper configuration.

## False Positives Analysis

The following patterns appear concerning but are legitimate for this extension type:

1. **Data "exfiltration" to native messaging**: The extension sends extensive user data (emails, file hashes, URLs, account info) to the native host. This is the core functionality of an enterprise DLP tool and is expected behavior.

2. **Broad host permissions**: The extension requires `http://*/*` and `https://*/*` to monitor all web activity. This is necessary for comprehensive web reputation filtering and DLP monitoring across all websites.

3. **Identity permission usage**: Collection of Chrome user emails via `identity.email` and `chrome.identity.getProfileUserInfo` is disclosed functionality for corporate user tracking and audit trails.

4. **Content script injection on document_start**: The `wtp.js` content script runs at `document_start` with `all_frames: true` to perform web reputation checks before pages load. This is standard for URL filtering extensions.

5. **Web accessible resources wildcard**: The manifest exposes all resources via `web_accessible_resources: ["*"]`. While overly permissive, this appears to support the block page functionality and locale files.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native messaging host: `com.trendmicro.chrome.dlp` | Enterprise DLP policy server | File hashes, user emails, URLs, cloud account info, timestamps, file paths | MEDIUM - All data sent to local native application for policy enforcement |

**Note**: The extension does NOT communicate with external web servers. All data is sent to a local native messaging host application for processing.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Trend Micro Toolbar for Enterprise is a legitimate corporate security tool with an extensive data collection footprint. The MEDIUM risk rating reflects:

**Positive factors:**
- Legitimate enterprise use case for DLP and web filtering
- No external network communication (all data goes to local native app)
- Clean code with no obfuscation
- Standard enterprise monitoring practices
- By Trend Micro, a reputable security vendor

**Risk factors:**
- Collects highly sensitive user data: email addresses, cloud account credentials, file metadata, browsing history
- Complete reliance on native messaging host for security decisions
- Very broad permissions (`<all_urls>`, identity, downloads, scripting)
- Feature is disabled by default (`enableFeature = false`) but can be remotely enabled via native messaging
- Web accessible resources wildcard could enable extension fingerprinting
- 3 million users likely unaware of the full extent of corporate monitoring

**Recommendation**: This extension is appropriate for enterprise environments with disclosed employee monitoring policies. However, individual users should be fully informed about the comprehensive data collection before installation. Organizations should ensure proper security of the native messaging host application, as it controls all policy decisions and receives sensitive user data.
