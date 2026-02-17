# Vulnerability Report: Browser Security Plus

## Metadata
- **Extension ID**: mhkgegcmcapcgmnnloigolapjkajgfmd
- **Extension Name**: Browser Security Plus
- **Version**: 2.30
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Browser Security Plus is an enterprise browser management extension developed by ManageEngine that provides comprehensive monitoring and control capabilities for organizational browser deployments. The extension communicates with a native host application (com.manageengine.browserrouter) to enforce policies around web access, downloads, uploads, and browser settings. While this extension has legitimate enterprise use cases for IT administrators to manage and secure corporate browsers, it implements extensive surveillance and data collection capabilities that raise privacy concerns if users are unaware of its full functionality.

The extension collects browsing history, tracks web activity timing (web metering), monitors downloads/uploads, harvests browser privacy settings, and extracts page content. All collected data is transmitted to the native host application for centralized management. The extension also implements URL filtering, download/upload blocking, and can block or override website access based on administrator-configured policies.

## Vulnerability Details

### 1. MEDIUM: postMessage Without Origin Validation
**Severity**: MEDIUM
**Files**: js/filepicker.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The file picker hook script registers multiple `window.addEventListener("message")` handlers without validating the origin of incoming messages. This creates a potential for cross-origin attacks where malicious websites could send crafted messages to interfere with the extension's upload filtering functionality.

**Evidence**:
```javascript
// js/filepicker.js:42
window.addEventListener("message", onDecision);

// js/filepicker.js:86
window.addEventListener("message", onDecision);
```

The handlers check `event.source !== window` but do not validate `event.origin`, allowing any frame within the same window context to send messages.

**Verdict**: While this is a security weakness, the impact is limited because the message handlers only control file picker allow/block decisions and cannot be used to exfiltrate data or execute arbitrary code. In the enterprise context where this extension is deployed with administrative control, the risk is reduced but still present.

### 2. MEDIUM: Comprehensive User Activity Surveillance
**Severity**: MEDIUM
**Files**: js/historyCollector.js, js/webMetering.js, js/data-extractor.js, js/downloadManager.js, js/uploadmanager.js, js/browserSettings.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension implements extensive monitoring of user browsing activity and transmits this data to the native host application. This includes browsing history, web metering (time spent on sites), download/upload activity, page content extraction, and browser privacy settings.

**Evidence**:

1. **Browsing History Collection** (historyCollector.js):
```javascript
historyObject.url = HistoryItem.url;
historyObject.domain = `${protocol}//${hostname}`;
historyObject.lastVisitTime = a.getTime();
this.port.postHistoryItem(historyObject, null);
```

2. **Web Activity Timing** (webMetering.js):
```javascript
webHistory[tabId][url] = {
    firstAccessed: tab.lastAccessed,
    title: tab.title
};
this.port.posttabWebHistoryUpdate(dataToPost, null);
```

3. **Page Content Extraction** (data-extractor.js):
```javascript
return {
    'text': getText(),
    'title': getTitle().trim(),
    'metaKeywords': getMetaKeywords().trim(),
    'metaDescription': getMetaDescription().trim(),
    'url':window.location.href
};
```

4. **Browser Settings Surveillance** (browserSettings.js):
```javascript
chrome.privacy.services.passwordSavingEnabled.get({}, function(details) {...});
chrome.privacy.websites.thirdPartyCookiesAllowed.get({}, function(cookie) {...});
this.port.postBrowserSettings(chrome_settings);
```

5. **Download/Upload Monitoring** (downloadManager.js, uploadmanager.js):
```javascript
this.port.postDownloadCreation(downloadItem, this.responseHandler.bind(this));
this.port.postUploadData(UploadObject, tabId, url, callback);
```

**Verdict**: This level of surveillance is expected for enterprise browser management software and is disclosed in the extension's description ("Manage Google Chrome using Browser Security Plus extension"). However, it represents a significant privacy concern if users are not fully aware of the extent of monitoring. The extension's low 1.6 rating suggests user dissatisfaction, potentially related to these monitoring capabilities. The data collection is proportionate to the stated enterprise management purpose but requires proper user notification and consent.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension's stated enterprise management purpose:

1. **Extension Enumeration**: The extension uses `chrome.management.getAll()` to inventory installed extensions, which is a standard feature of enterprise browser management tools to ensure compliance with organizational policies.

2. **Native Messaging**: Communication with the native host application (com.manageengine.browserrouter) is the core architectural pattern for enterprise extensions that need to integrate with central management systems.

3. **File Picker Hooking**: The monkey-patching of `window.showOpenFilePicker()` and `window.showDirectoryPicker()` is necessary to implement upload filtering policies, a legitimate enterprise DLP (Data Loss Prevention) feature.

4. **Content Script Injection at document_start**: Running content scripts early is necessary to intercept file upload attempts before they occur.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| com.manageengine.browserrouter (native host) | Central management system communication | Browsing history, web metering data, download/upload events, browser settings, page content, extension inventory | Medium - All user activity is transmitted to the native host application |

Note: This extension uses native messaging rather than HTTP endpoints. All data flows to the local native host application, which likely forwards data to ManageEngine's centralized management server.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Browser Security Plus is a legitimate enterprise browser management extension from ManageEngine, a reputable IT management software vendor. The extension's functionality aligns with its stated purpose of providing centralized browser control and monitoring for organizations. However, several factors contribute to a MEDIUM risk classification:

**Mitigating Factors:**
- Legitimate enterprise software from established vendor (ManageEngine)
- Functionality is appropriate for stated purpose (enterprise browser management)
- Extension description discloses management capabilities
- Requires native host application installation (IT administrator control)
- No evidence of malicious behavior or unauthorized data exfiltration
- No code execution vulnerabilities or credential theft mechanisms

**Concerning Factors:**
- Extensive user surveillance including browsing history, web activity timing, and page content extraction
- postMessage handlers lack origin validation (security weakness)
- Very low user rating (1.6/5) suggests user dissatisfaction, potentially due to monitoring
- Broad permissions including management, privacy, downloads, scripting, and <all_urls>
- Browser privacy settings are monitored and transmitted
- Web metering tracks time spent on all websites

**Conclusion:**

This extension should only be installed in enterprise environments where users have been properly notified about the monitoring capabilities and have provided appropriate consent (or where such monitoring is legally permitted under employment agreements). For individual users who installed this extension outside of an organizational context, the extensive surveillance represents a significant privacy concern and the extension should be removed. The MEDIUM rating reflects that while the functionality is legitimate for its intended enterprise use case, the privacy implications are substantial and require proper disclosure and consent mechanisms.
