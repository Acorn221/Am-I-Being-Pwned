# Vulnerability Report: Inkscape editor for draws and graphics

## Metadata
- **Extension ID**: bcapjlfjbmaijdinncieppinamjgljog
- **Extension Name**: Inkscape editor for draws and graphics
- **Version**: 3.0.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension presents itself as an "Inkscape editor for draws and graphics" providing vector graphics editing capabilities. However, analysis reveals significant privacy concerns: the extension monitors all tab navigation activity and exfiltrates visited URLs to the offidocs.com backend. The extension tracks every URL a user visits (except those already on offidocs.com) and sends this browsing history to a remote server, encoding the URLs in hexadecimal format. While the extension does provide legitimate functionality through integration with the OffiDocs cloud service, the undisclosed URL tracking represents a high-severity privacy violation that most users would not expect from a graphics editing tool.

The extension assigns each user a unique random identifier stored in chrome.storage.local and uses this to track browsing activity. All visited URLs are sent to the backend via fetch requests to determine if they should be opened in the Inkscape editor interface, but this means the vendor receives a complete log of the user's browsing history.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing History Exfiltration

**Severity**: HIGH
**Files**: websecure.js, service_worker.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension monitors all tab navigation events and exfiltrates visited URLs to offidocs.com without meaningful user disclosure. Every time a user switches tabs or navigates to a new page, the URL is captured and sent to the backend.

**Evidence**:

In `websecure.js` lines 20-29, the extension registers listeners for all tab activation and update events:
```javascript
chrome.tabs.onActivated.addListener(function(activeInfo) {
    activeTabId = activeInfo.tabId;
    getTabInfo(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    getTabInfo(tabId);
});
```

The `getTabInfo` function (lines 4-13) extracts the URL from every tab:
```javascript
function getTabInfo(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
            urlx = tab.url;
            extractimage(urlx);
            lastUrl = tab.url;
        }
    });
}
```

The `extractimage` function (lines 59-109) then sends this URL to the remote server:
```javascript
async function extractimage(urlxx) {
    // ... generates/retrieves username ...
    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloadinkscapex_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un);
    // ... processes response ...
}
```

The URL is hex-encoded via `bin2hex()` (lines 112-121) and transmitted along with a unique user identifier. This creates a server-side log of all browsing activity tied to a specific user ID.

**Verdict**: This is a high-severity privacy violation. While the extension needs to detect image URLs for its legitimate functionality, there is no meaningful disclosure that ALL visited URLs are being sent to a third-party server. The "tabs" permission is used far more broadly than users would expect for a graphics editing tool. The behavior could be legitimate if properly disclosed and opt-in, but as implemented it constitutes undisclosed tracking.

### 2. MEDIUM: Remote Configuration and Content Injection

**Severity**: MEDIUM
**Files**: popup.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension loads dynamic content from offidocs.com and injects it into the popup interface without integrity verification.

**Evidence**:

In `popup.js` lines 95-115, the extension fetches and directly renders remote content:
```javascript
xhr1.open('GET', 'https://www.offidocs.com/media/system/app/checkdownloadinkscaper_2_nav.php?u=' + username, true);
xhr1.onload = function (e) {
    if (xhr1.readyState === 4) {
        if (xhr1.status === 200) {
            var response1 = xhr1.responseText;
            listfilesx.innerHTML = "<p>List of image files detected in this webpage. Click to edit:</p> " + response1;
        }
    }
};
```

The server response is directly inserted into innerHTML without sanitization or integrity checks. While this appears to be expected functionality for displaying detected files, it creates a trust dependency on the remote server.

**Verdict**: Medium severity. If the offidocs.com backend were compromised or malicious, it could inject arbitrary content into the extension interface. However, this is within the expected trust model for a cloud-integrated application.

## False Positives Analysis

The static analyzer flagged the code as "obfuscated," but examination shows this is standard minified JavaScript libraries (jQuery, elfinder) and not malicious obfuscation. The core extension logic is clearly readable.

The extension's use of the `tabs` permission and URL monitoring could theoretically be justified for detecting editable image files in web pages, but the implementation goes beyond what's necessary - it tracks ALL URLs, not just those containing images.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.offidocs.com/media/system/app/checkdownloadinkscapex_2_nav.php | Check if URL should be opened in editor | Hex-encoded URL, user ID | HIGH - receives all browsing history |
| www.offidocs.com/media/system/app/checkdownloadinkscaper_2_nav.php | Get list of detected files | User ID | LOW - legitimate functionality |
| www.offidocs.com/media/system/app/resetlool.php | Initialize cloud session | Username, URL path | LOW - legitimate functionality |
| www.offidocs.com/phpextensions/connector.php | File management interface | Username, service ID | LOW - legitimate functionality |
| www.offidocs.com/community/preprefile.php | Cloud storage access | Username | LOW - legitimate functionality |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While the extension provides legitimate vector graphics editing functionality through the OffiDocs cloud platform, it engages in undisclosed browsing history collection. The extension monitors every tab navigation event and sends visited URLs to the backend server, creating a comprehensive log of user browsing activity. This goes far beyond what users would reasonably expect from a graphics editing tool.

The privacy violation is particularly concerning because:
1. The extension description makes no mention of URL tracking or browsing monitoring
2. The "tabs" permission could be justified for detecting editable images, but the implementation captures ALL URLs regardless of content
3. Each user is assigned a persistent identifier that ties browsing history to a specific user
4. The data is sent to a third-party server without user control or visibility

While not overtly malicious, this represents a significant undisclosed privacy violation that warrants a HIGH risk rating. Users installing a graphics editor would not expect their complete browsing history to be transmitted to the vendor's servers.

**Recommendation**: Users should be aware that this extension tracks all visited URLs and sends them to offidocs.com. Consider alternatives that provide similar functionality without the privacy implications, or use this extension only in isolated browser profiles for specific editing tasks.
