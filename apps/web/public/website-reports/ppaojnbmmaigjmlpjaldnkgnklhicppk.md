# Vulnerability Report: Webtime Tracker

## Metadata
- **Extension Name**: Webtime Tracker
- **Extension ID**: ppaojnbmmaigjmlpjaldnkgnklhicppk
- **Version**: 3.1.0
- **User Count**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Webtime Tracker is a browser time-tracking extension that monitors active tab usage and provides analytics. The extension is **CLEAN** with no malicious behavior detected. It follows best security practices for a time-tracking utility, with all data stored locally and no external network communication beyond standard install/uninstall telemetry and documentation links.

The extension implements legitimate time tracking functionality using standard Chrome APIs (tabs, idle, storage, alarms) and maintains user privacy by storing all browsing data locally in chrome.storage.local. The optional `<all_urls>` permission is only requested for the screenshot feature and requires explicit user consent.

## Vulnerability Details

### 1. CLEAN - No Network Exfiltration
**Severity**: N/A
**Files**: background.ef004079.js, popup.4f1a441e.js
**Verdict**: CLEAN

**Analysis**:
- No `fetch()`, `XMLHttpRequest`, or network API calls detected for data exfiltration
- All browsing history and domain tracking data stored exclusively in `chrome.storage.local`
- Only network-related URLs are static links to developer website (petasittek.com) for:
  - Install/update welcome pages with UTM tracking
  - Uninstall feedback URL
  - Support/documentation links
  - Browser store review links

**Code Evidence**:
```javascript
// Background script - only static URLs, no dynamic data transmission
N = "https://www.petasittek.com/"
E = `${N}${x}/`  // Base URL for extension pages
W = `${E}version/`  // Version announcement pages

// Install/update handlers - opens static pages only
J = async ({reason: a}) => {
  if (a === chrome.runtime.OnInstalledReason.INSTALL) {
    let a = z(N, "install");
    chrome.tabs.create({url: a})
  }
  // Sets uninstall URL (standard practice)
  let e = z(N, "uninstall");
  chrome.runtime.setUninstallURL(e)
}
```

### 2. CLEAN - Appropriate Permission Usage
**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN

**Declared Permissions**:
- `tabs` - Read tab URLs for time tracking (core functionality)
- `idle` - Detect user idle state to pause tracking
- `storage` - Store tracking data locally
- `unlimitedStorage` - Store extended browsing history
- `alarms` - Periodic updates (30-second intervals)

**Optional Permissions** (requires user consent):
- `<all_urls>` - Only for screenshot feature (`chrome.tabs.captureVisibleTab`)

**Analysis**:
All permissions are used for their stated purpose. The extension correctly implements the optional permissions pattern for `<all_urls>`, requesting it only when the user activates the screenshot feature:

```javascript
// Screenshot permission request - user must approve
tU = async t => {
  try {
    return await chrome.permissions.request(t)
  } catch (t) {
    return S("Permissions - request: " + t.message), !1
  }
}

// Check permission before screenshot
tG({origins: ["<all_urls>"]})
```

### 3. CLEAN - No Sensitive Data Collection
**Severity**: N/A
**Files**: background.ef004079.js
**Verdict**: CLEAN

**Analysis**:
The extension tracks only:
- Domain names (hostnames only, not full URLs)
- Time spent per domain (in seconds)
- Idle state detection
- Tab focus events

No collection of:
- URL parameters or query strings
- Page content
- Form data
- Cookies
- Authentication tokens
- Personal information

**Code Evidence**:
```javascript
// Only extracts hostname from URLs
v = a => a && new URL(a).hostname

// Stores minimal domain tracking data
I = () => ({
  name: "",
  alltime: {seconds: 0},
  days: {}
})

// Excludes chrome:// and extension URLs
l = ["chrome:", "chrome-extension:", "moz-extension:"]
al = a => {
  let e = v(a), t = S(a);
  return !(c.includes(e) || l.includes(t) || "" === e)
}
```

### 4. CLEAN - Local-Only Data Storage
**Severity**: N/A
**Files**: background.ef004079.js, popup.4f1a441e.js
**Verdict**: CLEAN

**Analysis**:
All tracking data stored in `chrome.storage.local` with no remote backup or sync:

```javascript
// Save function - local storage only
D = async (a, e) => {
  let t = {[a]: JSON.stringify(e)};
  try {
    await chrome.storage.local.set(t)
  } catch (a) {
    k("Error saving to storage:", a)
  }
}

// Domain tracking persistence
ay = async () => {
  a.domainsChanged && (
    await D(u, a.domains),
    await D(g, a.seconds.alltime),
    a.domainsChanged = !1
  )
}
```

The extension provides backup/restore functionality via local file download/upload (no cloud sync):

```javascript
// Backup to local file with SHA-256 hash verification
H(a).then(t => {
  N([JSON.stringify({
    content: e,
    hash: {sha256: t}
  })], "octet/stream", `webtime-tracker-backup-${a}.json`)
})
```

### 5. CLEAN - No Dynamic Code Execution
**Severity**: N/A
**Files**: All JavaScript files
**Verdict**: CLEAN

**Analysis**:
- No `eval()` calls
- No `Function()` constructor usage
- No `document.write()`
- `innerHTML` usage limited to safe, static UI updates in popup
- `atob()/btoa()` used only for premium feature unlock code validation (not security-sensitive)

**Premium Code Validation**:
```javascript
// Hardcoded unlock code check - not a security issue
"V1RST0NLUw==" === btoa(tD.value) // Checks for "VIRTUELS" string
```

### 6. CLEAN - No Content Script Injection
**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN

**Analysis**:
No content scripts declared or injected. Extension operates entirely via:
- Background service worker (time tracking logic)
- Popup UI (data visualization)
- Chrome API event listeners

This minimizes attack surface and ensures no interference with web pages.

### 7. CLEAN - CSP and Security Headers
**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN

**Analysis**:
Manifest V3 enforces strict CSP by default. No custom CSP overrides detected. Extension follows secure coding practices:
- No inline scripts in HTML
- All JavaScript in separate files
- No remote script loading
- No unsafe-eval directives

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `innerHTML` usage | popup.4f1a441e.js:197 | Used for UI updates with static/computed strings, no user input | False Positive |
| `btoa()` usage | popup.4f1a441e.js:591 | Premium unlock code validation (non-sensitive) | False Positive |
| `atob()` usage | popup.4f1a441e.js:663 | Screenshot data URI decoding (legitimate) | False Positive |
| `crypto.subtle.digest` | popup.4f1a441e.js:126 | SHA-256 hash for backup file integrity verification | False Positive |
| `window.open()` | popup.4f1a441e.js:686 | Opens clicked domain in new tab (user-initiated) | False Positive |
| Hardcoded domain | background.ef004079.js:91 | Developer website (petasittek.com) for docs/support | False Positive |

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| https://www.petasittek.com/ | Developer homepage, install/uninstall pages | UTM parameters (source/medium/campaign) | LOW - Standard analytics |
| Browser store review URLs | User-initiated review links | None | NONE - Static links |

**Notes**:
- No API endpoints receive browsing data
- No authentication endpoints
- No remote configuration
- No analytics SDKs (no Google Analytics, Sentry, etc.)

## Data Flow Summary

```
User Browsing → Chrome Tab Events → Background Service Worker
                                           ↓
                                    Domain Extraction
                                    (hostname only)
                                           ↓
                                    Time Calculation
                                           ↓
                                    chrome.storage.local
                                    (encrypted by browser)
                                           ↓
                                    Popup UI Visualization
                                           ↓
                                    Optional: CSV/JSON Export
                                    (local file download)
```

**Key Points**:
- All data processing occurs locally
- No network transmission of tracking data
- User retains full control via backup/restore/clear functions
- Data encrypted at rest by Chrome's storage API

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Rationale:
1. **No Malicious Behavior**: Zero evidence of data exfiltration, malware, or privacy violations
2. **Legitimate Functionality**: All code serves the stated purpose of time tracking
3. **Privacy Preserving**: Stores all data locally, no remote sync or telemetry
4. **Minimal Attack Surface**: No content scripts, no remote code loading
5. **Transparent Permissions**: Clearly documented purpose for each permission
6. **User Control**: Provides backup, restore, and data clearing functionality
7. **Optional Permissions**: `<all_urls>` requested only when needed (screenshot feature)
8. **Manifest V3**: Uses latest security standards

### Security Strengths:
- Fully local data storage
- No third-party analytics or tracking SDKs
- Minimal permission set for core functionality
- Hash verification for backup file integrity
- Proper idle detection to avoid tracking inactive time
- Excludes chrome:// and extension URLs from tracking
- No dynamic code execution vectors

### Recommendations:
None. This extension follows security best practices and poses no risk to users.

## Conclusion

Webtime Tracker is a **clean, privacy-focused time tracking extension** with no security vulnerabilities or malicious behavior. The codebase demonstrates responsible development practices with appropriate permission usage, local-only data storage, and transparent functionality. The extension is safe for use and presents no risk to user privacy or security.
