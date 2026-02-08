# Vulnerability Report: Web Site blocker

## Metadata
- **Extension ID**: aoabjfoanlljmgnohepbkimcekolejjn
- **Extension Name**: Web Site blocker
- **Version**: 1.4.1
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Web Site blocker is a productivity extension designed to help users block distracting websites. The extension implements its core functionality through declarativeNetRequest rules, content scripts, and local storage for configuration. After comprehensive analysis, the extension demonstrates **clean security behavior** with no malicious code patterns detected. It operates entirely locally without external network communication, uses appropriate permissions for its functionality, and handles user data responsibly.

**Overall Risk Level: CLEAN**

The extension serves its intended purpose of blocking distracting websites through legitimate browser APIs without exhibiting suspicious behavior.

## Vulnerability Analysis

### 1. Network Communication & Data Exfiltration
**Severity**: N/A
**Status**: CLEAN
**Files**: All JavaScript files analyzed

**Findings**:
- No fetch() or XMLHttpRequest calls detected in extension code
- No API endpoints or external domains contacted
- No data exfiltration mechanisms present
- All data stored and processed locally using chrome.storage.local
- Update URL points to standard Google CWS update mechanism only

**Verdict**: Extension operates entirely offline with no network communication.

---

### 2. Permissions Analysis
**Severity**: LOW
**Status**: CLEAN
**Files**: manifest.json

**Declared Permissions**:
- `tabs` - Used to manage and query tabs for blocking functionality
- `contextMenus` - Provides right-click menu to block/unblock sites
- `storage` - Stores user's blocked site list and configuration
- `declarativeNetRequest` - Core blocking mechanism for iframe and resource blocking

**Findings**:
- All permissions are appropriate and necessary for stated functionality
- No sensitive permissions requested (cookies, history, bookmarks, webRequest, downloads)
- Content scripts run on `<all_urls>` at `document_start` - required to intercept page loads for blocking
- No excessive or suspicious permission combinations

**Verdict**: Permission usage is justified and minimal for website blocking functionality.

---

### 3. Content Script Injection & DOM Manipulation
**Severity**: LOW
**Status**: CLEAN
**Files**: content_script.js

**Findings**:
```javascript
// content_script.js - Legitimate blocking behavior
function block_site(e) {
    window.stop();  // Stops page load
    // Replaces page content with block message
    document.getElementsByTagName("body")[0].innerHTML = blockTemplate;
}
```

**Analysis**:
- Content script communicates with background worker to check if current site should be blocked
- If blocked, stops page loading and displays block notification
- Uses randomized gradients/animations for block screen (purely cosmetic)
- No data collection from page DOM
- No keylogging, form interception, or credential harvesting
- No injection of ads, tracking pixels, or third-party scripts
- Polling interval uses randomization (5-7.5 seconds) to re-check block status

**Verdict**: DOM manipulation is exclusively for blocking UI display, not malicious purposes.

---

### 4. Background Script Analysis
**Severity**: N/A
**Status**: CLEAN
**Files**: background.js

**Findings**:
```javascript
// Storage management - all local
function saveObjToStorage(skipUpdate = false) {
    var data = { storage: JSON.stringify(STORAGE) };
    chrome.storage.local.set(data, function() {
        console.log("update ", JSON.parse(data.storage));
    });
    skipUpdate || initWebRequestBlocking();
}

// No external network calls detected
// No eval(), Function(), or dynamic code execution
// No extension enumeration or killing mechanisms
```

**Core Functionality**:
- Manages blocked site list in chrome.storage.local
- Implements time-based blocking rules (work hours, inactive hours)
- Creates declarativeNetRequest rules to block iframe loading from blocked sites
- Provides context menu integration for quick block/unblock
- Handles password protection for settings (using simple hash)

**Verdict**: Background script implements legitimate blocking logic without malicious patterns.

---

### 5. Dynamic Code Execution & Obfuscation
**Severity**: N/A
**Status**: CLEAN
**Files**: All JavaScript files

**Findings**:
- No eval(), Function(), atob(), fromCharCode() patterns detected
- No code obfuscation beyond standard minification (angular.js, jquery.js are standard libraries)
- AngularJS and jQuery are standard versions with no tampering detected
- All logic is human-readable and transparent

**Verdict**: No dynamic code execution or obfuscation present.

---

### 6. Storage & Data Handling
**Severity**: N/A
**Status**: CLEAN
**Files**: background.js, main-app.js

**Data Stored Locally**:
```javascript
STORAGE = {
    sites: [],              // Blocked site list
    redirect_url: "",       // Optional redirect URL
    subdomainOption: "1",   // Block subdomains
    enabled: "1",          // Extension on/off
    days_config: [],       // Time-based rules
    blockKeyList: [],      // URL keyword blocking
    pass: "",              // Hashed password (optional)
    rules: [],             // Allow/block URL rules
    advancedRules: []      // Resource type blocking rules
}
```

**Findings**:
- All data stored locally in chrome.storage.local
- Password stored as simple hash (not cryptographically secure but acceptable for local settings protection)
- No cloud sync or external storage
- Export/import functionality uses local file system only
- No user tracking, analytics, or telemetry

**Verdict**: Data handling is privacy-respecting and entirely local.

---

### 7. Advanced Features Analysis
**Severity**: N/A
**Status**: CLEAN
**Files**: background.js, rules.directive.js, advanced-rules.directive.js

**Rules System**:
- Keyword-based URL blocking (block/allow specific paths on a domain)
- Advanced resource type blocking (scripts, stylesheets, images, XHR, etc.)
- Uses declarativeNetRequest API with regex filters
- Time-based blocking schedules (inactive/active hours)
- White list mode (block all except listed sites)

**Findings**:
- Advanced blocking features are legitimate productivity tools
- No abuse of declarativeNetRequest for traffic interception
- No proxy infrastructure or residential proxy patterns
- Regex generation is safe and predictable

**Code Example**:
```javascript
// Advanced rule creation - legitimate blocking
function createAdvancedRulesForDNR(rules, startId) {
    return rules.filter(r => r.isChecked).map((rule, i) => {
        return {
            id: startId + i,
            condition: {
                regexFilter: convertAdvancedRuleToRegex(rule.urlPattern, rule.matchType),
                resourceTypes: rule.resourceTypes
            },
            action: { type: "block" }
        };
    });
}
```

**Verdict**: Advanced features serve stated functionality without malicious intent.

---

### 8. Third-Party Integration
**Severity**: N/A
**STATUS**: CLEAN
**Files**: options/index.html

**External References**:
- Contact form: `https://form.mightyforms.com/share/6cfdc322-34f2-4625-bd31-667642103878`
- Support link: `https://www.patreon.com/site_blocker_chrome`
- Info links: `https://site-blocker.info/` (documentation/contact)

**Findings**:
- External links are for user support and donations only
- No tracking scripts, analytics, or third-party SDKs embedded
- All functionality is self-contained
- Links open in new tabs, not injected into pages

**Verdict**: Minimal external references, all legitimate and transparent.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| innerHTML usage | content_script.js:34-35 | Legitimate DOM replacement for block screen display |
| chrome.tabs query | background.js:162-166 | Required for tab management in website blocker |
| document.execCommand('copy') | main-app.js:414 | Deprecated but harmless copy-to-clipboard for export feature |
| Polling interval | content_script.js:15-23 | Checks if site should be blocked (necessary for time-based rules) |
| Favicon fetch | options/index.html:165 | Google favicon service for UI display only |

---

## API Endpoints & External Connections

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store auto-update (standard) | None |
| `http://www.google.com/s2/favicons?domain=` | Favicon display in UI (passive GET request) | Minimal - discloses blocked domains to Google |
| `https://form.mightyforms.com/share/*` | User contact form link (opens in new tab) | None |
| `https://www.patreon.com/site_blocker_chrome` | Donation/support link (opens in new tab) | None |
| `https://site-blocker.info/*` | Documentation site links | None |

**Note**: The favicon endpoint is the only passive external request, used purely for UI enhancement. It does not send user data or tracking information beyond the domain names in the user's block list (which are only sent when the options page is viewed).

---

## Data Flow Summary

```
User Input (Options Page)
    ↓
chrome.storage.local (Local Storage)
    ↓
Background Worker (Processes Rules)
    ↓
chrome.declarativeNetRequest (Blocks Resources)
    ↓
Content Script (Displays Block Page)
```

**Key Observations**:
1. No data leaves the browser except passive favicon fetches for UI
2. All processing happens locally
3. No analytics, tracking, or telemetry
4. No remote configuration or kill switches
5. User data remains under user control (export/import available)

---

## Security Best Practices Assessment

**Positive Aspects**:
- ✅ No external network communication for core functionality
- ✅ Manifest V3 (modern, secure platform)
- ✅ Uses declarativeNetRequest instead of webRequest (more secure)
- ✅ No dynamic code execution
- ✅ Transparent, readable code
- ✅ Privacy-respecting (no telemetry)
- ✅ Password protection option for settings
- ✅ Export/import for data portability

**Minor Concerns** (Not Security Issues):
- ⚠️ Password hashing uses simple hash, not cryptographic (acceptable for local settings protection)
- ⚠️ Favicon fetching to Google discloses blocked domains (minor privacy consideration)
- ℹ️ Deprecated execCommand('copy') used (should migrate to Clipboard API)

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension serves its stated purpose of blocking distracting websites through legitimate browser APIs. It demonstrates:

1. **No Malicious Behavior**: No data exfiltration, tracking, ad injection, or credential harvesting
2. **Appropriate Permissions**: Only uses permissions necessary for website blocking functionality
3. **Local Operation**: All data processing and storage is local to the browser
4. **Transparent Code**: No obfuscation or hidden functionality
5. **Privacy Respecting**: No analytics, telemetry, or user tracking
6. **No Suspicious Patterns**: No extension killing, proxy infrastructure, or remote configuration

The extension exhibits clean security characteristics throughout. While it requests powerful permissions (`<all_urls>` content script injection), these are justified and properly utilized for the core blocking functionality. The extension does not abuse these permissions for malicious purposes.

**Recommendation**: This extension is safe for use. The invasive permissions are necessary for a website blocker to function, and the implementation demonstrates responsible use of those capabilities.

---

## Conclusion

Web Site blocker (aoabjfoanlljmgnohepbkimcekolejjn) is a legitimate productivity tool that operates as advertised. The comprehensive security analysis found no vulnerabilities, malicious code patterns, or privacy concerns. The extension uses appropriate Chrome APIs, maintains user data locally, and does not communicate with external servers beyond standard Chrome Web Store updates. The implementation is transparent and privacy-respecting.

**Final Verdict: CLEAN - No security concerns identified**
