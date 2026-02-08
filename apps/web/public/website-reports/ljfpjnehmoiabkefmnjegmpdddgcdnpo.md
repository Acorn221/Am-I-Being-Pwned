# Vulnerability Report: User Agent Switcher, URL sniffer

## Extension Metadata
- **Extension ID**: ljfpjnehmoiabkefmnjegmpdddgcdnpo
- **Extension Name**: User Agent Switcher, URL sniffer
- **Version**: 0.9.4.3
- **Users**: ~70,000
- **Manifest Version**: 3
- **Homepage**: https://iblogbox.com/chrome/useragent/

## Executive Summary

User Agent Switcher is a legitimate browser extension that allows users to modify their User-Agent string and monitor HTTP requests. The extension exhibits **MEDIUM risk** due to automatic external navigation on install and a remote-hosted options page that could potentially be weaponized for phishing, though no active malicious behavior was detected. The core functionality uses standard Chrome APIs appropriately.

## Vulnerability Details

### 1. Automatic External Navigation on Install
**Severity**: MEDIUM
**Files**: `js/bg.js` (lines 119-126)
**Code**:
```javascript
chrome.runtime.onInstalled.addListener(async function(details){
    await load_resource_all();
    if(details && details.reason=='install'){ //install, update, chrome_update
        if(navigator.language!="ja"){
            open_newtab('https://iblogbox.com/chrome/useragent/alert.php',true);
            localStorage["installcheck2"]=(new Date()).getTime();
        }
    }
```

**Description**: On installation, the extension automatically opens an external URL (`https://iblogbox.com/chrome/useragent/alert.php`) for non-Japanese users without user consent. This domain is controlled by the developer.

**Risk**: If the developer's domain is compromised or the developer turns malicious, this could be used for:
- Phishing attacks
- Tracking installation events
- Drive-by malware downloads
- Affiliate fraud

**Verdict**: SUSPICIOUS - While common in free extensions, automatic navigation to external sites on install violates user expectations and creates attack surface.

---

### 2. Remote-Hosted Options Page
**Severity**: MEDIUM
**Files**: `js/ui/options.js` (lines 60-64)
**Code**:
```javascript
chrome.extension.sendRequest({type:'get_bgstorage'}, function(r) {
    if(r && r.bgdata && r.bgdata.g_extensionid){
        location.href='https://iblogbox.com/chrome/useragent/option/v0.9.3.6.php?g_extensionid='+r.bgdata.g_extensionid;
    }
});
```

**Description**: The extension's options page (`options.html`) is a stub that immediately redirects to a remote PHP page hosted on `iblogbox.com`, passing the extension ID as a URL parameter.

**Risk**:
- Remote page can inject arbitrary JavaScript
- Phishing via fake options UI
- Data exfiltration through form submissions
- No content security policy enforcement on remote page
- Extension ID leakage to third-party server

**Verdict**: SUSPICIOUS - Remote options pages are not inherently malicious but create significant trust dependencies and attack surface. If the remote server is compromised, attackers gain full control over the options interface.

---

### 3. Overly Broad Permissions
**Severity**: LOW
**Files**: `manifest.json` (lines 29-30)
**Code**:
```json
"host_permissions": ["<all_urls>"],
"permissions": ["storage", "webRequest", "declarativeNetRequest"]
```

**Description**: The extension requests `<all_urls>` host permissions combined with `webRequest` and `declarativeNetRequest`, allowing it to intercept and modify all HTTP traffic.

**Risk**: While required for the advertised functionality (User-Agent switching), these permissions could be abused for:
- Cookie theft
- Session hijacking
- Traffic interception
- Ad injection
- Request redirection

**Verdict**: ACCEPTABLE - Permissions are appropriate for the stated functionality. The extension does NOT abuse these permissions in the current codebase - it only modifies User-Agent headers as advertised.

---

### 4. Content Script on Developer Domain
**Severity**: LOW
**Files**: `manifest.json` (lines 22-27)
**Code**:
```json
"content_scripts": [{
    "all_frames": true,
    "js": [ "js/option.js"],
    "matches": [ "*://iblogbox.com/chrome/useragent/option/*"]
}]
```

**Description**: The extension injects `option.js` into all frames on `iblogbox.com/chrome/useragent/option/*`. This grants the remote options page privileged access to extension APIs via `chrome.extension.sendRequest`.

**Risk**: If the developer's website is compromised, attackers could inject malicious JavaScript that has access to the extension's background APIs, potentially:
- Exfiltrating extension storage data
- Modifying extension settings
- Triggering malicious actions via the extension

**Verdict**: SUSPICIOUS - This creates a bidirectional trust relationship where both the extension trusts the website AND the website can control the extension.

---

## False Positives

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| `fetch(chrome.runtime.getURL(...))` | `js/bg.js:25, 79` | Loading local extension resources (manifest, i18n files), not external network calls |
| `chrome.webRequest.onBeforeSendHeaders` | `js/bg.js:447-526` | Legitimate header modification for User-Agent switching - core advertised functionality |
| `chrome.declarativeNetRequest.updateSessionRules` | `js/bg.js:604` | MV3-compliant User-Agent modification API, replaces deprecated webRequest blocking |
| `localStorage['transv2']` | `js/bg.js:127-130` | Migration logic from MV2 to MV3, not data exfiltration |

---

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://iblogbox.com/chrome/useragent/alert.php` | Post-install notification | None (GET request) | LOW - Likely analytics/tracking |
| `https://iblogbox.com/chrome/useragent/option/v0.9.3.6.php` | Remote options page | Extension ID (`g_extensionid`) | MEDIUM - Extension enumeration + remote code execution capability |
| `https://atomurl.net/myip` | User-initiated IP check | None | CLEAN - Third-party service linked from popup |
| `https://iblogbox.com/devtools/js/` | Developer tools link | None | CLEAN - User-initiated navigation |

---

## Data Flow Summary

### Data Collection
- **User-Agent Configurations**: Stored locally in `chrome.storage.local`
- **Request Logs**: When "URL sniffer" feature is enabled, logs HTTP request metadata (URL, method, timestamp, headers) in memory (max 300 entries)
- **Extension ID**: Sent to `iblogbox.com` when accessing options page
- **Install Timestamp**: Stored in `localStorage["installcheck2"]` on first install

### Network Communication
- **Outbound**:
  - Install event: Navigation to `iblogbox.com/chrome/useragent/alert.php`
  - Options page: Loads remote content from `iblogbox.com`
- **No Analytics SDKs**: No Sentry, Google Analytics, or third-party tracking libraries detected
- **No Persistent Tracking**: No user identifiers, hashed fingerprints, or telemetry beyond install timestamp

### Privilege Boundaries
- Content script on `iblogbox.com` has bidirectional message passing with background script
- No content scripts injected into user-visited pages (legitimate use of permissions)
- User-Agent modifications are session-scoped (cleared on browser restart for MV3 compliance)

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

### Justification
1. **No Active Malware**: Extension performs its advertised functionality (User-Agent switching) without exfiltrating data or injecting ads
2. **Concerning Architecture**: Remote options page + content script on developer domain creates significant attack surface if developer site is compromised
3. **Automatic Navigation**: Unsolicited navigation to external sites on install is user-hostile and could be weaponized
4. **Legitimate Permissions**: Broad permissions are justified by functionality and not currently abused

### Recommendations
- **For Users**: Exercise caution. The extension works as advertised but has architectural choices that create trust dependencies on `iblogbox.com`
- **For Platform**: Flag automatic navigation on install as policy violation. Remote options pages should be discouraged in favor of local HTML
- **For Developer**: Migrate options page to local HTML to improve user trust and security posture

### Comparison to Similar Extensions
This extension follows common patterns in User-Agent switcher extensions (e.g., using `declarativeNetRequest` for header modification). The remote options page is unusual but not unique. The automatic install navigation is less common and more concerning.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
