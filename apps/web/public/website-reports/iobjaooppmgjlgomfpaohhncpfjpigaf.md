# XLS Editor - Security Vulnerability Report

## Extension Metadata
- **Extension Name:** XLS Editor
- **Extension ID:** iobjaooppmgjlgomfpaohhncpfjpigaf
- **Version:** 2.15.2
- **User Count:** ~80,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-07

## Executive Summary

XLS Editor is a Chrome extension that provides spreadsheet editing functionality by integrating with offidocs.com cloud services. The extension exhibits **CRITICAL privacy violations** through aggressive browsing behavior tracking. It monitors ALL tab navigation events and sends complete URLs of every website the user visits to a remote server without adequate disclosure or consent. This constitutes pervasive surveillance of user browsing activity.

The extension automatically intercepts file downloads from web pages and redirects users to offidocs.com for editing, creating a potential privacy and security risk. While the extension does not exhibit traditional malware behaviors (no cookie theft, no credential harvesting, no ad injection), the comprehensive URL tracking represents a severe privacy violation.

## Vulnerability Details

### V1: Pervasive Browsing Activity Surveillance
**Severity:** CRITICAL
**CWE:** CWE-359 (Exposure of Private Information)

**Location:** `websecure.js` (lines 5-114)

**Evidence:**
```javascript
function getTabInfo(tabId) {
      chrome.tabs.get(tabId, function(tab) {
            if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
                    //console.log(" Changed tab.url " + tab.url);
                    urlx =  tab.url;
                    extractaudio(urlx);
                    lastUrl = tab.url;
            }
      });
}

chrome.tabs.onActivated.addListener(function(activeInfo) {
        activeTabId = activeInfo.tabId;
        getTabInfo(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
        //if(activeTabId == tabId) {
            getTabInfo(tabId);
        //}
});
```

The `extractaudio()` function (misleadingly named) sends every URL visited to offidocs.com:
```javascript
async function extractaudio(urlxx) {
    // ... retrieves username from storage ...

    if ( datax.offidocscloud == "0")
        return;  // User can disable via checkbox

    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloadxlseditorx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un + "&s=" + servicexx);

    if (cfgv.status === 200) {
        let fbv = await cfgv.text();
        var nbv = fbv;
        if ( nbv.indexOf("302") !== -1 )   {
               var ybv = 'https://www.offidocs.com/media/system/app/view_edit_xlseditor_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
                //chrome.tabs.create({ url: ybv });
               chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
        }
    }
}
```

**Analysis:**
1. The extension monitors EVERY tab activation and update event
2. For every URL change (except offidocs.com itself), it sends the complete URL to `checkdownloadxlseditorx_2_nav.php`
3. URLs are hex-encoded and transmitted with a user tracking identifier
4. The server responds with "302" if it detects an editable file, triggering automatic tab redirection
5. This creates a complete browsing history surveillance system

**Verdict:** CRITICAL VIOLATION
- **Data Collected:** Complete browsing history (all URLs visited)
- **Transmission:** Real-time to offidocs.com servers
- **User Control:** Can be disabled via "Detect files" checkbox (default: enabled)
- **Disclosure:** Insufficient - not clearly disclosed in privacy policy
- **Justification:** Ostensibly to detect downloadable XLS files, but monitors ALL URLs indiscriminately

### V2: Automatic Tab Hijacking/Redirection
**Severity:** HIGH
**CWE:** CWE-610 (Externally Controlled Reference to a Resource in Another Sphere)

**Location:** `websecure.js` (lines 102-106)

**Evidence:**
```javascript
if ( nbv.indexOf("302") !== -1 )   {
       var ybv = 'https://www.offidocs.com/media/system/app/view_edit_xlseditor_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
       chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
}
```

**Analysis:**
When the remote server detects a file URL (e.g., link to .xls file), it responds with "302" indicator, triggering the extension to automatically redirect the current tab to offidocs.com. This hijacks user navigation without explicit consent at the moment of redirection.

**Verdict:** HIGH RISK
- Automatic tab redirection based on remote server decision
- User loses control of navigation
- Could be exploited if offidocs.com server is compromised

### V3: User Tracking with Persistent Identifiers
**Severity:** HIGH
**CWE:** CWE-359 (Exposure of Private Information)

**Location:** `websecure.js` (lines 37-56), `popup.js` (lines 3-34)

**Evidence:**
```javascript
// Generate or retrieve persistent username
if ( datax.username ) {
    username = datax.username;
}
else {
    username = "" + randomString(10) + "".toLowerCase();
    datax.username = username;
}
```

All requests include this identifier:
```javascript
'https://www.offidocs.com/media/system/app/checkdownloadxlseditorx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un
```

**Analysis:**
The extension creates a persistent random identifier stored in `chrome.storage.local` that tracks the user across all browsing sessions. This identifier is sent with every URL tracking request, enabling offidocs.com to build comprehensive browsing profiles linked to individual users.

**Verdict:** HIGH RISK
- Persistent cross-session tracking
- Enables long-term browsing profile creation
- No option to reset or disable identifier

### V4: Modified Third-Party Library with Additional Tracking
**Severity:** MEDIUM
**CWE:** CWE-506 (Embedded Malicious Code)

**Location:** `js/elfinder.min.js` (lines 4595-4672)

**Evidence:**
The extension includes elFinder 2.0 rc1, a legitimate file manager library, but has injected custom code at the end:
```javascript
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.offidocs.com/phpextensions/userext.php?username=' + username, true);
xhr1.onload = function(e) {
  if (xhr1.readyState === 4) {
    if (xhr1.status === 200) {
      // Custom file opening logic that sends requests to offidocs.com
      urly = 'https://www.offidocs.com/editfile.php?service=' + response1 + '&username=' + username + '&filepath=' + bin2hex(urlxx) + '&hex=11';
      window.open(urly);
    }
  }
};
xhr1.send();
```

**Analysis:**
The developer has modified the open-source elFinder library by appending custom code that integrates with offidocs.com backend. While not inherently malicious, this makes it difficult to audit and could hide additional tracking/surveillance code within the large minified library file.

**Verdict:** MEDIUM RISK
- Modified open-source library reduces transparency
- Additional network requests embedded in library code
- Harder to detect changes through code review

## False Positives

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| `Function()` in jQuery | jquery.min.js:505 | BENIGN | Standard jQuery JSON parsing fallback |
| `eval()` in jQuery UI | jquery-ui.min.js:3918 | BENIGN | jQuery UI datepicker inline settings parsing |
| XMLHttpRequest usage | popup.js, elfinder.min.js | EXPECTED | Legitimate API communication for file operations |
| `chrome.tabs.update` in popup | websecure.js:105 | MALICIOUS | Used for automatic tab redirection - not benign |

## API Endpoints and Data Flows

### Primary Surveillance Endpoint
| Endpoint | Method | Purpose | Data Sent | Frequency |
|----------|--------|---------|-----------|-----------|
| `https://www.offidocs.com/media/system/app/checkdownloadxlseditorx_2_nav.php` | GET | URL tracking | `filepath` (hex-encoded URL), `u` (user ID), `hex=1`, `s` (service) | Every tab navigation |

### File Management Endpoints
| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://www.offidocs.com/media/system/app/checkdownloadxlseditorr_2_nav.php` | GET | List detected files | `u` (username) |
| `https://www.offidocs.com/media/system/app/resetlool.php` | GET | Initialize session | `username`, `urlpathx` |
| `https://www.offidocs.com/phpextensions/connector.php` | POST | elFinder backend | File operations, `username`, `service` |
| `https://www.offidocs.com/editfile.php` | GET | Open editor | `service`, `username`, `filepath`, `hex` |

### User Tracking Data Flow
```
User navigates to URL
    ↓
chrome.tabs.onUpdated event fires
    ↓
getTabInfo() extracts tab.url
    ↓
extractaudio(url) called
    ↓
URL hex-encoded + username appended
    ↓
fetch() to checkdownloadxlseditorx_2_nav.php
    ↓
offidocs.com receives: full browsing history + user ID
    ↓
Server responds with 302 if file detected
    ↓
Extension redirects tab to offidocs.com
```

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "storage",  // Used to store persistent user ID
  "tabs"      // Used to monitor all tab navigation
]
```

**Assessment:**
- **storage**: JUSTIFIED - Needed for user preferences and tracking ID
- **tabs**: OVER-PRIVILEGED - Used for comprehensive surveillance, not just file detection
  - Extension has access to ALL tab URLs, not just file downloads
  - No host permissions declared, but monitors all websites via tabs API

### Missing Security Headers
- **Content Security Policy (CSP):** Not declared - defaults to MV3 standards
- **externally_connectable:** Not declared - no external website communication
- **web_accessible_resources:** Not declared - no resources exposed to web pages

## Data Flow Summary

### Data Collection
1. **Browsing History:** Every URL visited (except offidocs.com) sent to remote server
2. **User Identifier:** Persistent random ID generated and stored locally
3. **File Access Patterns:** Which files user attempts to open/edit
4. **Session Data:** Timestamps, service identifiers, file paths

### Data Transmission
- **Protocol:** HTTPS (encrypted in transit)
- **Frequency:** Real-time on every tab navigation
- **Destination:** offidocs.com servers
- **Retention:** Unknown (server-side)

### User Control
- **Opt-out Available:** Yes - "Detect files" checkbox in popup
- **Default State:** Enabled (surveillance active by default)
- **Data Deletion:** No mechanism provided
- **Transparency:** Poor - behavior not clearly disclosed

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

### Risk Factors
1. **Pervasive Surveillance:** Monitors and transmits every URL visited
2. **Persistent Tracking:** Uses unique identifier for long-term profiling
3. **Insufficient Disclosure:** Privacy implications not adequately communicated
4. **Automatic Behavior:** Tab hijacking without per-incident consent
5. **Large User Base:** 80,000+ users affected

### Severity Breakdown
- **CRITICAL Issues:** 1 (browsing surveillance)
- **HIGH Issues:** 2 (tab hijacking, user tracking)
- **MEDIUM Issues:** 1 (modified library)
- **LOW Issues:** 0

### Mitigating Factors
- User can disable tracking via checkbox
- HTTPS encryption used for transmission
- No evidence of credential theft or cookie harvesting
- No ad injection or content script manipulation
- Legitimate business purpose (file editing service)

### Recommendation
**REMOVE or REQUIRE SIGNIFICANT MODIFICATION**

This extension should be:
1. Removed from Chrome Web Store for privacy violations, OR
2. Required to implement privacy-preserving file detection (e.g., local pattern matching instead of server-side URL transmission), AND
3. Required to display prominent privacy disclosure about URL tracking on install, AND
4. Required to make tracking opt-in instead of opt-out, AND
5. Required to provide mechanism for users to delete collected data

The current implementation constitutes surveillance software that collects comprehensive browsing histories under the guise of a file editing tool. While the underlying service may be legitimate, the implementation violates user privacy expectations and creates significant security/privacy risks.

## Technical Deep Dive: How URL Tracking Works

### Step-by-Step Flow
1. **User installs extension** → Random 10-character username generated and stored
2. **User visits any website** → `chrome.tabs.onActivated` and `onUpdated` listeners fire
3. **websecure.js processes event** → Extracts `tab.url` via `chrome.tabs.get()`
4. **URL filtering** → Skips if URL contains "offidocs" or not HTTP(S)
5. **URL hex-encoding** → Converts URL to hex string via `bin2hex()`
6. **Network request** → `fetch('https://www.offidocs.com/.../checkdownloadxlseditorx_2_nav.php?filepath=<HEX_URL>&u=<USER_ID>')`
7. **Server processing** → offidocs.com receives URL, checks for editable files
8. **Response parsing** → Extension checks if response contains "302"
9. **Conditional redirect** → If "302" found, redirects current tab to offidocs.com editor

### Example Tracking Request
```
User visits: https://example.com/documents/report.xlsx
    ↓
Hex encoded: 68747470733a2f2f6578616d706c652e636f6d2f646f63756d656e74732f7265706f72742e786c7378
    ↓
Request: https://www.offidocs.com/media/system/app/checkdownloadxlseditorx_2_nav.php?filepath=68747470733a2f2f6578616d706c652e636f6d2f646f63756d656e74732f7265706f72742e786c7378&hex=1&u=abc123xyz7&s=
    ↓
Server logs: User abc123xyz7 visited https://example.com/documents/report.xlsx
```

This pattern repeats for EVERY page the user visits, building a complete surveillance log.
