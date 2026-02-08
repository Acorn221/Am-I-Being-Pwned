# LibreOffice Editor - Security Analysis Report

## Extension Metadata

- **Extension Name**: LibreOffice Editor
- **Extension ID**: bdomjcpneblellajjhgfdlnmjfofflop
- **User Count**: ~60,000 users
- **Manifest Version**: 3
- **Version**: 3.1.6
- **Developer**: offidocs.com

## Executive Summary

LibreOffice Editor is a Chrome extension that provides online document editing capabilities through integration with the offidocs.com service. The extension exhibits **MEDIUM risk** security concerns primarily due to:

1. **Aggressive URL monitoring** - Background service worker tracks all user navigation across websites
2. **Privacy concerns** - All visited URLs are transmitted to offidocs.com servers without explicit user consent
3. **Automatic tab hijacking** - Extension can automatically redirect users when office documents are detected
4. **Unencrypted user tracking** - Random user IDs stored and sent with all browsing activity
5. **XSS via innerHTML** - Direct HTML injection from remote server responses

While the extension does not exhibit overtly malicious behavior (no credential harvesting, no ad injection, no cryptocurrency mining), its surveillance-like monitoring of all user browsing activity and automatic URL transmission represents a significant privacy violation.

## Vulnerability Details

### 1. Comprehensive URL Surveillance (HIGH Severity)

**File**: `websecure.js` (lines 5-32)

**Code**:
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
```

**Behavior**:
- Background service worker monitors ALL tab navigation events
- Every URL visited is captured (except offidocs.com itself)
- URLs are immediately sent to `extractaudio()` function which transmits to remote server
- No explicit permission warning to users about URL monitoring

**Verdict**: This is invasive surveillance. The extension monitors every website a user visits and transmits this data to offidocs.com servers. While the stated purpose is to detect office documents, the implementation captures ALL browsing activity.

**Severity**: HIGH - Violates user privacy expectations and Chrome Web Store policies

---

### 2. Automatic URL Exfiltration and Tab Hijacking (HIGH Severity)

**File**: `websecure.js` (lines 60-117)

**Code**:
```javascript
async function extractaudio(urlxx) {
    // ... get username ...

    // Send current URL to offidocs.com server
    let cfgv = await fetch('https://www.offidocs.com/media/system/app/checkdownloadlibreofficex_2_nav.php?filepath=' + bin2hex(urlxx) + '&hex=1&u=' + un + "&s=" + servicexx);

    if (cfgv.status === 200) {
        let fbv = await cfgv.text();
        var nbv = fbv;
        if ( nbv.indexOf("302") !== -1 )   {
               var ybv = 'https://www.offidocs.com/media/system/app/view_edit_libreoffice_nav.php?filepath=' + bin2hex(urlxx) + '&u=' + un;
                chrome.tabs.update(chrome.tabs.getCurrent().id, {url: ybv});
        }
    }
}
```

**Behavior**:
- Every visited URL is hex-encoded and sent to offidocs.com servers
- Server responds with potential file detection status
- If server returns "302", extension AUTOMATICALLY redirects current tab to offidocs.com
- User's browsing session is interrupted without explicit consent

**Data Transmitted**:
- Full URL of every page visited (via `filepath` parameter)
- User tracking ID (via `u` parameter)
- Service identifier (via `s` parameter)

**Verdict**: This creates a complete browsing history log on offidocs.com servers. The automatic tab redirection is intrusive and could be weaponized if the backend were compromised.

**Severity**: HIGH - Privacy violation, potential for abuse

---

### 3. XSS via Direct innerHTML Injection (MEDIUM Severity)

**File**: `popup.js` (lines 66-85, 96-118)

**Code**:
```javascript
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.offidocs.com/media/system/app/checkdownloadxlseditorr_2_nav.php?u=' + username, true);
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

**Behavior**:
- Remote server response directly injected into DOM via `innerHTML`
- No sanitization or validation of server response
- If offidocs.com backend compromised, arbitrary JavaScript could execute in extension context

**Verdict**: While the domain is under developer control, this is still poor security practice. Extension context has elevated privileges and should not trust server responses implicitly.

**Severity**: MEDIUM - Requires backend compromise but could lead to extension context code execution

---

### 4. User Tracking Without Explicit Consent (MEDIUM Severity)

**File**: `websecure.js` (lines 37-43), `popup.js` (lines 3-34)

**Code**:
```javascript
// websecure.js - generates random tracking ID
username = "" + randomString(10) + "".toLowerCase();
chrome.storage.sync.set({'username': username.toLowerCase()}, function() { });

// popup.js - creates persistent tracking
if ( datax.username ) {
    username = datax.username;
}
else {
    username = "" + randomString(10) + "".toLowerCase();
    datax.username = username;
}
```

**Behavior**:
- Extension generates random 10-character "username" on first install
- ID stored persistently in chrome.storage.local and chrome.storage.sync
- This ID sent with EVERY URL the user visits
- No privacy policy disclosure in extension

**Verdict**: Creates persistent cross-session tracking identifier sent with all browsing activity. Users are not informed this is happening.

**Severity**: MEDIUM - Privacy violation under GDPR/CCPA

---

### 5. Overly Broad Tab Monitoring Permissions (MEDIUM Severity)

**File**: `manifest.json` (lines 23-26)

**Code**:
```json
"permissions": [
    "storage",
    "tabs"
]
```

**Behavior**:
- `tabs` permission allows reading ALL tab URLs without additional user consent
- No host permissions specified, but tabs API alone provides URL access
- Combined with background service worker, enables continuous monitoring

**Verdict**: The `tabs` permission is necessary for the extension's stated functionality (detecting office documents in tabs), but the implementation is overly aggressive in HOW it uses this permission. There's no rate limiting, no user control, and no transparency.

**Severity**: MEDIUM - Legitimate permission used inappropriately

---

### 6. Remote Config Vulnerability (LOW Severity)

**File**: `websecure.js` (lines 94-100)

**Code**:
```javascript
if ( servicexx == "" ) {
    let response = await fetch('https://www.offidocs.com/media/system/app/resetlool.php?username=' + username + '&urlpathx=/phpextensions/userext.php');
     if (response.status === 200) {
                let data = await response.text();
                servicexx = data;
     }
}
```

**Behavior**:
- Extension fetches "service" identifier from remote server
- This value used in subsequent API calls
- If server compromised, could redirect extension traffic to malicious endpoints

**Verdict**: Remote configuration is a common pattern but creates dependency on server security. If offidocs.com compromised, attacker could redirect all extension traffic.

**Severity**: LOW - Requires backend compromise

---

### 7. Dynamic Iframe Injection (LOW Severity)

**File**: `popup.js` (lines 138-156, 189-207, 240-258)

**Code**:
```javascript
var iframe = document.createElement('iframe');
iframe.id ="login_banner";
iframe.width = "100%";
iframe.height = "600px";
iframe.src = 'https://www.offidocs.com/media/system/app/view_ext.php?myServerhost='+response1+'&urlpathx=/createe-doc.php&service=' + response1 + '&username=' + username + '&filepath=&extx=doc';

img = document.getElementById('login_banner');
img.parentNode.insertBefore(iframe, img);
img.parentNode.removeChild(img);
```

**Behavior**:
- Extension popup dynamically creates iframes pointing to offidocs.com
- Iframe URLs constructed from server responses
- Could be used to phish users if backend compromised

**Verdict**: This is standard practice for web apps but creates trust dependency on offidocs.com. No CSP restrictions on iframe sources in manifest.

**Severity**: LOW - Standard pattern, requires backend compromise

## False Positive Analysis

| Pattern | Files | Verdict |
|---------|-------|---------|
| jQuery AJAX | `js/jquery.min.js` | **FALSE POSITIVE** - Standard jQuery library (v1.x or 2.x), legitimate XMLHttpRequest usage |
| jQuery UI | `js/jquery-ui.min.js` | **FALSE POSITIVE** - Standard jQuery UI library, legitimate DOM manipulation |
| elFinder | `js/elfinder.min.js` | **FALSE POSITIVE** - Open-source file manager library (https://github.com/Studio-42/elFinder), legitimate file operations |
| `innerHTML` in popup.js | lines 73, 103 | **TRUE POSITIVE** - Directly injects server response without sanitization |
| URL hex encoding (`bin2hex`) | websecure.js | **LEGITIMATE BUT SUSPICIOUS** - Used to encode URLs before transmission, but still constitutes privacy violation |

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `offidocs.com/media/system/app/checkdownloadlibreofficex_2_nav.php` | Check if URL contains office document | URL (hex), username, service ID | HIGH - Full browsing history |
| `offidocs.com/media/system/app/resetlool.php` | Get service identifier | username | MEDIUM - User tracking |
| `offidocs.com/media/system/app/checkdownloadxlseditorr_2_nav.php` | List detected files in current page | username | LOW - Only when popup opened |
| `offidocs.com/phpextensions/connector.php` | File manager backend | username, service ID | LOW - Only when file manager used |
| `offidocs.com/phpextensions/userext.php` | Get user extension info | username | LOW - Only when file operations performed |
| `offidocs.com/community/preprefile.php` | File list interface | username | LOW - Only when popup opened |

## Data Flow Summary

```
User visits website
    ↓
chrome.tabs.onUpdated event fires
    ↓
websecure.js captures URL
    ↓
extractaudio() function called
    ↓
URL hex-encoded and transmitted to:
  https://www.offidocs.com/.../checkdownloadlibreofficex_2_nav.php
    ↓
Server checks for office documents
    ↓
If document detected (server returns "302"):
  → Tab automatically redirected to offidocs.com editor
    ↓
All activity tied to persistent tracking ID stored in chrome.storage
```

**Data Exposure**: Every URL visited by user is transmitted to offidocs.com servers along with persistent tracking identifier.

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
- No overtly malicious behavior (no malware, no ad injection, no credential theft)
- Extension does provide legitimate functionality (online office editing)
- However, implementation is invasive and privacy-violating
- All user browsing activity monitored and transmitted without clear disclosure
- Automatic tab redirection is intrusive
- Chrome Web Store policy violations likely present

**User Impact**:
- Complete browsing history exposed to third-party (offidocs.com)
- Persistent cross-session tracking
- Potential for unexpected tab hijacking
- No user control over monitoring behavior

**Recommendations for Users**:
1. Uninstall if not actively using office editing features
2. If needed, only enable when specifically editing documents
3. Be aware all URLs visited while extension enabled are sent to offidocs.com
4. Review offidocs.com privacy policy (if available)

**Recommendations for Developer**:
1. Implement user consent dialog for URL monitoring
2. Add toggle in options page to disable auto-detection
3. Sanitize all server responses before DOM injection
4. Add clear privacy policy disclosure
5. Implement rate limiting on URL transmission
6. Consider content script injection only on pages with detected office docs instead of background monitoring
7. Add CSP to manifest restricting iframe sources

## Compliance Issues

- **GDPR**: Persistent tracking ID without consent, no privacy policy
- **CCPA**: User browsing data collection without disclosure
- **Chrome Web Store Policy**: "Single Purpose" violation (office editing + surveillance)
- **Chrome Web Store Privacy Policy**: Inadequate disclosure of data collection practices

## Conclusion

LibreOffice Editor provides legitimate document editing functionality but implements it through privacy-invasive surveillance mechanisms. The extension monitors all user browsing activity and transmits every URL visited to offidocs.com servers. While not malicious in the traditional sense (no malware payload, no credential theft), this behavior constitutes a significant privacy violation and likely violates Chrome Web Store policies regarding data collection and disclosure.

The extension should be rated **MEDIUM risk** due to privacy violations, but users requiring office editing functionality may still use it with awareness of the surveillance implications.
