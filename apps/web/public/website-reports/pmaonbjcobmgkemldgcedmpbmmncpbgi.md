# Security Analysis Report: Ubuntu free online linux server

## Extension Metadata
- **Extension ID**: pmaonbjcobmgkemldgcedmpbmmncpbgi
- **Extension Name**: Ubuntu free online linux server
- **Version**: 1.3.5
- **User Count**: ~60,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

**Overall Risk Level: HIGH**

This extension presents **significant privacy and security concerns** by systematically collecting and transmitting all browsing URLs to third-party servers. The extension monitors tab activity across all websites (excluding onworks.net domains) and sends every URL visited to `www.onworks.net` servers without meaningful user consent. While the extension discloses this behavior in its UI footer, the implementation creates substantial privacy risks including:

1. **Comprehensive browsing surveillance** - Every URL visited is transmitted to external servers
2. **Potential for sensitive data exposure** - URLs may contain authentication tokens, session IDs, personal information, or search queries
3. **Minimal user control** - The "Detect enabled" toggle only affects redirects, not data collection
4. **Hex-encoded URL transmission** - URLs are converted to hex format before transmission, obscuring the data flow

The extension's stated purpose is to detect files that can be managed via OnWorks' Ubuntu file manager, but the implementation captures far more data than necessary for this functionality.

## Vulnerability Details

### 1. CRITICAL: Comprehensive Browsing History Exfiltration

**Severity**: CRITICAL
**Files**: `w.js` (lines 4-101), `s.js` (lines 2-4)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension monitors all tab activations and updates, extracting URLs from every webpage visited and transmitting them to external servers. This occurs automatically in the background without explicit per-URL user consent.

**Code Evidence**:
```javascript
// w.js lines 21-30
chrome.tabs.onActivated.addListener(function(activeInfo) {
    activeTabId = activeInfo.tabId;
    gti(activeTabId);
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    gti(tabId);
});

// w.js lines 4-13
function gti(tabId) {
    chrome.tabs.get(tabId, function(tab) {
        if ( ( tab.url.indexOf("onworks") == -1 ) && ( tab.url.indexOf("http") !== -1 ) && ( lastUrl != tab.url) )  {
            urlx =  tab.url;
            reporturlscannedandrecorded = urlx;
            extractf(reporturlscannedandrecorded);
            lastUrl = tab.url;
        }
    });
}
```

**Attack Vector**:
- Extension monitors `chrome.tabs.onActivated` and `chrome.tabs.onUpdated` events
- For every tab change/update, if URL contains "http" and doesn't contain "onworks", the URL is captured
- URLs are passed to `extractf()` which transmits them to remote servers

**Data Flow**:
1. User visits any website (e.g., `https://gmail.com/mail/u/0/#inbox`)
2. Tab update event triggers → `gti()` called
3. URL extracted → passed to `extractf()`
4. URL hex-encoded via `b2x()` → transmitted to OnWorks servers
5. Server responds, potentially triggering browser redirection

**Privacy Impact**:
- **Search queries**: URLs like `https://www.google.com/search?q=sensitive+medical+condition`
- **Session tokens**: URLs containing authentication parameters
- **Private identifiers**: Account IDs, document IDs, email subjects in URLs
- **Banking/financial sites**: URL patterns revealing financial activity
- **Healthcare**: URLs from medical portals or telehealth platforms

**Verdict**: This is a clear privacy violation. While disclosed in the UI footer, the implementation captures comprehensive browsing history and transmits it to third-party servers. The hex encoding obscures URLs but provides no security - servers receive plaintext URLs. This level of surveillance is disproportionate to the stated file management purpose.

### 2. HIGH: Hex-Encoded URL Transmission to Third-Party Server

**Severity**: HIGH
**Files**: `w.js` (lines 63-115)
**CWE**: CWE-201 (Information Exposure Through Sent Data)

**Description**:
URLs are converted to hex encoding and transmitted to `www.onworks.net` servers via GET requests, creating a permanent server-side record of user browsing activity.

**Code Evidence**:
```javascript
// w.js lines 88-89
let fgvt = await fetch('https://www.onworks.net/media/system/app/runos/c-ubuntux-2x.php?url=' + b2x(urlxx) + '&hex=1&u=' + un);

// w.js lines 106-115 - Hex encoding function
function b2x (bin) {
  var i = 0, l = bin.length, chr, hex = ''
  for (i; i < l; ++i) {
    chr = bin.charCodeAt(i).toString(16)
    hex += chr.length < 2 ? '0' + chr : chr
  }
  return hex
}
```

**Example Transmission**:
- Original URL: `https://example.com/sensitive-path?token=abc123`
- Hex-encoded: `68747470733a2f2f6578616d706c652e636f6d2f73656e73697469766...`
- Transmitted as: `https://www.onworks.net/media/system/app/runos/c-ubuntux-2x.php?url=68747470733a2f2f6578616d706c652e636f6d...&hex=1&u=[user_id]`

**Concerns**:
1. **Server-side logging**: URLs are likely logged in web server access logs permanently
2. **No encryption benefit**: Hex encoding provides no security - it's trivially reversible
3. **User tracking**: Each request includes unique user ID (`u=` parameter) enabling cross-session tracking
4. **Third-party data sharing**: No guarantees about OnWorks' data retention, sharing, or security practices

**Verdict**: HIGH risk. Hex encoding creates false sense of privacy while enabling comprehensive user tracking and URL collection by third parties.

### 3. MEDIUM: Automatic Browser Redirection Based on Remote Server Response

**Severity**: MEDIUM
**Files**: `w.js` (lines 90-97)
**CWE**: CWE-601 (URL Redirection to Untrusted Site)

**Description**:
Based on responses from OnWorks servers, the extension can automatically redirect the user's current tab to different URLs without explicit user action.

**Code Evidence**:
```javascript
// w.js lines 90-97
if (fgvt.status === 200) {
    let dsx = await fgvt.text();
    var tgbh6 = dsx;
    if ( tgbh6.indexOf("302") !== -1 )   {
        var cvfgbh = 'https://www.onworks.net/media/system/app/runos/intro-ubuntu-os.php?url=' + b2x(urlxx) + '&u=' + un;
        //chrome.tabs.create({ url: cvfgbh });
        chrome.tabs.update(chrome.tabs.getCurrent().id, {url: cvfgbh});
    }
}
```

**Attack Vector**:
1. User visits a webpage
2. Extension sends URL to OnWorks server
3. If server response contains "302", extension redirects current tab to OnWorks domain
4. Redirection includes original URL (hex-encoded) in query parameters

**Concerns**:
- **User experience disruption**: Automatic redirects interrupt browsing without consent per-instance
- **Phishing potential**: If OnWorks servers compromised, redirects could lead to malicious sites
- **URL hijacking**: User's intended destination replaced with OnWorks intermediary page

**Mitigation**: The "Detect enabled" toggle in the UI can disable this behavior by setting `apkononline = "0"`, which causes `extractf()` to return early (line 86).

**Verdict**: MEDIUM risk. While redirects are confined to OnWorks domains and user can disable, the automatic nature and remote control aspect pose usability and security concerns.

### 4. MEDIUM: Persistent User Tracking via Unique Identifiers

**Severity**: MEDIUM
**Files**: `w.js` (lines 37-43, 63-81), `apar.js` (lines 4-24)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension generates and persists unique user identifiers across sessions, enabling long-term tracking of user activity by OnWorks servers.

**Code Evidence**:
```javascript
// w.js lines 37-43
if ( chrome.storage.sync.get('usercx', function (obj) { })  ) {
    usercx = chrome.storage.sync.get('usercx', function (obj) { });
}
else {
   usercx = "" + ranSX(10) + "".toLowerCase();
   chrome.storage.sync.set({'usercx': usercx.toLowerCase()}, function() { });
}

// w.js lines 50-58 - Random ID generation
function ranSX(len, charSet) {
    charSet = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var ranSX = '';
    for (var i = 0; i < len; i++) {
        var rxDD = Math.floor(Math.random() * charSet.length);
        ranSX += charSet.substring(rxDD,rxDD+1);
    }
    return ranSX.toLowerCase();
}
```

**Tracking Mechanism**:
- 10-character random alphanumeric ID generated on first install
- Stored in `chrome.storage.sync` (syncs across user's Chrome instances)
- Also stored in `chrome.storage.local` under `apkon_key` structure
- Sent with every URL transmission as `&u=[user_id]` parameter

**Privacy Implications**:
- **Cross-device tracking**: Using `storage.sync` means same ID follows user across devices
- **Long-term profiling**: Persistent ID enables building comprehensive browsing profiles
- **No anonymization**: All URLs linked to single persistent identifier
- **No expiration**: ID persists indefinitely unless extension uninstalled

**Verdict**: MEDIUM risk. While common in extensions, persistent tracking combined with comprehensive URL collection creates significant privacy exposure.

### 5. LOW: Inadequate Content Security Policy

**Severity**: LOW
**Files**: `manifest.json`
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)

**Description**:
The manifest does not define a Content Security Policy (CSP), relying on Chrome's default CSP for extensions. This provides basic protection but lacks explicit restrictions.

**Observation**:
```json
// manifest.json - No CSP defined
{
  "manifest_version": 3,
  "name" : "__MSG_title__",
  "version": "1.3.5",
  "permissions": ["storage", "tabs"],
  "background": {
    "service_worker": "s.js"
  }
}
```

**Impact**:
- Manifest v3 enforces stricter defaults (no `eval()`, no inline scripts in extension pages)
- Current code does not use eval or dynamic code execution
- However, jQuery versions used (3.3.1 in popup, older in js/jquery.min.js) may have known vulnerabilities

**Verdict**: LOW risk given MV3 protections, but explicit CSP would be best practice.

## False Positives

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| jQuery eval references | jquery-3.3.1.min.js, js/jquery.min.js | False Positive | Standard jQuery functionality, not executed in extension context for dynamic code |
| XMLHttpRequest in jQuery | Multiple jQuery files | False Positive | Standard HTTP library, used for AJAX - not inherently malicious |
| Function() constructor | js/jquery.min.js:505 | False Positive | jQuery JSON parsing fallback, not used for arbitrary code execution |
| elfinder.min.js complexity | js/elfinder.min.js | False Positive | Legitimate file manager library for UI, not analyzed in detail |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://www.onworks.net/media/system/app/runos/c-ubuntux-2x.php` | URL scanning/detection | Hex-encoded URL, user ID | HIGH - Browsing surveillance |
| `https://www.onworks.net/media/system/app/runos/intro-ubuntu-os.php` | Redirect destination | Hex-encoded URL, user ID | MEDIUM - User redirection |
| `https://www.onworks.net/media/system/app/runos/c-ubuntu-2r.php` | File listing | User ID | LOW - File retrieval |
| `https://www.onworks.net/myfiles.php` | File manager access | Username, online status | LOW - User-initiated access |
| `https://www.onworks.net/runos/create-os.html` | OS launcher | OS selection parameters | CLEAN - User-initiated navigation |

## Data Flow Summary

```
User browses web
    ↓
Tab activation/update event fired
    ↓
w.js gti() captures tab URL (if not onworks.net)
    ↓
extractf() called with URL
    ↓
URL converted to hex via b2x()
    ↓
fetch() sends to onworks.net with user ID
    ↓
Server responds (potentially with "302" signal)
    ↓
If "302" detected → tab redirected to OnWorks intro page
    ↓
OnWorks server logs: user ID + URL + timestamp
```

**Data Retention**: Unknown - depends on OnWorks server logging practices
**Third-party Access**: Unknown - OnWorks privacy policy not analyzed
**User Control**: Limited - "Detect enabled" toggle prevents redirects but unclear if it prevents URL transmission (code suggests it does at line 86)

## Permissions Analysis

| Permission | Usage | Justified | Notes |
|------------|-------|-----------|-------|
| `storage` | Store user ID, settings | Yes | Required for persistence |
| `tabs` | Monitor tab changes, capture URLs | Questionable | Overly broad for file detection - could use activeTab with user gesture |

**Concern**: `tabs` permission grants access to all URLs across all tabs without user gesture requirement. A more privacy-preserving approach would use `activeTab` permission with user-initiated actions.

## Disclosure Assessment

The extension **does disclose** data collection in its UI:

> "Note: This extension collects your browsed URLs in our servers in order to detect the Internet browsed files that could be managed by our Ubuntu file manager (My files) for you."

**Location**: `index.html` line 112 (footer)

**Adequacy**: Partial disclosure
- ✅ States URLs are collected
- ✅ States data sent to "our servers"
- ❌ Doesn't explain hex encoding (may mislead users about privacy)
- ❌ Doesn't mention persistent user ID tracking
- ❌ Doesn't specify data retention period
- ❌ Doesn't explain which URLs (answer: nearly all except onworks.net)
- ❌ Not shown during installation (only visible in extension popup)

## Recommendations

1. **For Extension Developer**:
   - Switch to `activeTab` permission instead of `tabs` - require user click before URL access
   - Implement client-side file detection instead of server-side URL transmission
   - Add clear opt-in consent flow during first run
   - Provide data deletion mechanism for collected URLs
   - Publish transparent privacy policy specifying data retention
   - Consider using `declarativeNetRequest` for file interception vs. URL monitoring

2. **For Users**:
   - **Uninstall if privacy-sensitive**: This extension should not be used by individuals with privacy concerns
   - If keeping: Regularly toggle off "Detect enabled" when browsing sensitive sites
   - Be aware: All URLs (except onworks.net) are transmitted to third-party servers
   - Consider: Alternative file management solutions that don't require browsing surveillance

3. **For Chrome Web Store**:
   - Review against "User Data Privacy" policy - comprehensive URL collection may violate spirit of data minimization
   - Verify disclosure adequacy - users may not understand scope of data collection
   - Assess if functionality justifies invasive permissions

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
- **Critical privacy violation**: Comprehensive browsing history exfiltration
- **Broad user impact**: 60,000 users affected
- **Minimal user control**: Surveillance occurs automatically by default
- **Sensitive data exposure**: URLs often contain personal/confidential information
- **Third-party data custody**: No control over OnWorks' data practices
- **Long-term tracking**: Persistent user IDs enable profiling

**Mitigating Factors**:
- Disclosure present in UI (though inadequate)
- User can disable "Detect enabled" toggle
- No evidence of malicious payload injection
- Redirects limited to OnWorks domains
- No evidence of credential theft or content injection

**Conclusion**: While the extension's stated purpose (Ubuntu file management) may be legitimate, the implementation employs surveillance techniques that are disproportionate to the functionality and create substantial privacy risks. The extension should be considered HIGH RISK for privacy-conscious users and organizations. The comprehensive URL collection pattern resembles tracking/market intelligence behavior seen in other flagged extensions, though here it's disclosed rather than hidden.

## Malware Classification: NO

This extension is **not malware** in the traditional sense - it does not:
- Inject malicious scripts
- Steal credentials directly
- Install backdoors
- Execute arbitrary remote code
- Encrypt/ransom data

However, it **does engage in privacy-invasive surveillance** that may violate user expectations despite disclosure. Classification: **Potentially Unwanted Program (PUP)** or **Grayware** due to aggressive data collection practices.
