# Vulnerability Report: Gimp online - image editor and paint tool

## Metadata
- **Extension ID**: omebobahbkampglebglkoagddjnjbhle
- **Extension Name**: Gimp online - image editor and paint tool
- **Version**: 3.0.5
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This Chrome extension provides access to GIMP (GNU Image Manipulation Program) online through the OffiDocs platform. The extension monitors all browser tab activity and automatically sends visited URLs to offidocs.com servers to identify image files that can be edited with GIMP. While a disclosure notice is present in the UI footer stating "Please be aware that this GIMP extension gathers the URLs you browse on our servers. This is to identify internet image files that can be edited using our GIMP online service," the collection is overly broad and occurs automatically without per-visit consent.

The extension collects browsing URLs from all tabs (excluding offidocs.com URLs and non-HTTP URLs), hex-encodes them, and transmits them to offidocs.com servers along with a randomly generated username identifier. This allows the remote server to track user browsing activity across all websites. The extension also provides a toggle to disable this "Detect files" feature.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Passive Browsing History Collection

**Severity**: MEDIUM
**Files**: websecure.js, popup.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension monitors all tab navigation events and automatically transmits visited URLs to offidocs.com servers. While there is a disclosure notice in the UI and a toggle to disable the feature, the collection happens passively without user interaction for each URL.

**Evidence**:

websecure.js (lines 4-23):
```javascript
function getTabInfo(tabId) {
      chrome.tabs.get(tabId, function(tab) {
            if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
                    urlx =  tab.url;

                    urltobecollectedwithoutsearchquery = "";
                    if ( urlx  && urlx.indexOf("?xtr") > 0 )
                    {
                        urltobecollectedwithoutsearchquery =   urlx.substring(0, urlx.indexOf("?xtr") );
                    }
                    else {
                        urltobecollectedwithoutsearchquery =   urlx;
                    }
                    extractimage(urltobecollectedwithoutsearchquery);


                    lastUrl = tab.url;
            }
      });
}

chrome.tabs.onActivated.addListener(function(activeInfo) {
        activeTabId = activeInfo.tabId;
        getTabInfo(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
        getTabInfo(tabId);
});
```

websecure.js (lines 70-109) - URL exfiltration:
```javascript
async function extractimage(urlxx) {
    const offidocs_key = "offidocs_key";
    var datax = { username: null,  offidocscloud: null };
    var username = "";
    var offidocscloud = "";
    let storageResult = await chrome.storage.local.get([offidocs_key]);
    if (offidocs_key in storageResult) {
            datax = storageResult[offidocs_key]
    }

    if ( datax.username ) {
        username = datax.username;
    }
    else {
        username = "" + randomString(10) + "".toLowerCase();
        datax.username = username;
    }
    if ( datax.offidocscloud ) {
        offidocscloud = datax.offidocscloud;
    }
    else {
        offidocscloud = "1";
        datax.offidocscloud = "1";
    }

    var un = username;
    if ( datax.offidocscloud == "0")
        return;

    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloadgimp_h_z_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un);
}
```

The bin2hex function converts URLs to hexadecimal encoding before transmission (lines 112-121).

**Verdict**: This is a MEDIUM severity issue because:
1. **Disclosed but excessive**: There is a disclosure notice in the UI footer (index.html line 133), and the feature can be toggled off
2. **Overly broad collection**: The extension collects ALL browsing URLs, not just URLs containing images
3. **Passive tracking**: Collection happens automatically on every tab change/update without user interaction
4. **User identifier**: A random username is generated and associated with browsing data, enabling cross-session tracking
5. **Legitimate purpose with overreach**: While detecting image URLs for editing is a stated purpose, collecting all URLs (including text-only pages, forms, etc.) exceeds what's necessary

## False Positives Analysis

1. **tabs permission**: Required for the extension's stated purpose of detecting image files in browsing
2. **storage permission**: Required for storing user preferences (username, toggle state)
3. **External requests to offidocs.com**: Expected as this is the service provider
4. **Toggle feature**: The extension does provide a "Detect files" checkbox to disable URL collection
5. **File manager functionality**: The elFinder integration and file management features are legitimate for a GIMP online extension

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.offidocs.com/media/system/app/checkdownloadgimp_h_z_2_nav.php | Submit browsed URL for image detection | hex-encoded URL, username | MEDIUM - Tracks all URLs visited |
| www.offidocs.com/media/system/app/checkdownloadgimp_b_h_2_nav.php | Retrieve browsing history | username | MEDIUM - Retrieves tracked URLs |
| www.offidocs.com/media/system/app/checkdownloadgimp_b_h_l_2_nav.php | Get images from specific URL | hex-encoded URL, username | LOW - Retrieves detected images |
| www.offidocs.com/media/system/app/checkdownloadgimp_delete_x_2_nav.php | Delete URL from history | hex-encoded URL, username | LOW - User control feature |
| www.offidocs.com/media/system/app/resetlool.php | Initialize GIMP session | username, URL path | LOW - Service initialization |
| www.offidocs.com/phpextensions/connector.php | File manager backend | username, service ID | LOW - File operations |
| www.offidocs.com/community/preprefile.php | Access file area | username | LOW - User file access |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension is assigned a MEDIUM risk level because it collects browsing URLs on all tabs and sends them to offidocs.com servers. While the extension includes a disclosure notice and provides a toggle to disable tracking, the default behavior is to passively monitor and transmit all browsing activity. The collection is broader than necessary for the stated purpose (identifying image files), as it captures all URLs regardless of content type.

The extension does provide user controls (toggle switch, delete function) and transparency (UI disclosure), which prevents it from being rated HIGH. However, the automatic collection of browsing history across all websites exceeds what most users would expect from an image editor extension, warranting the MEDIUM classification.

Key mitigating factors:
- Explicit disclosure in the UI
- User toggle to disable tracking
- Ability to delete collected URLs
- No evidence of malicious intent beyond the stated purpose

Key concerns:
- Overly broad data collection (all URLs, not just image URLs)
- Passive tracking without per-visit consent
- Persistent user identifier enables cross-session tracking
- 200,000 users potentially affected
