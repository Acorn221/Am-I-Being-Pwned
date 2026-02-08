# Vulnerability Report: Off The Record History

## Metadata
- **Extension Name**: Off The Record History
- **Extension ID**: djbaolpiihkcmmfjnjdmomeeheldhhdp
- **User Count**: ~50,000
- **Version**: 0.4.1
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Off The Record History is a Chrome extension that tracks browsing history in incognito mode, maintaining records for up to 7 days. The extension only operates in incognito mode and stores all data locally using chrome.storage.local. The extension includes Google Analytics (GA4) for telemetry tracking with tracking ID G-2P4ENHZPXT.

**Overall Risk Assessment**: **LOW**

The extension operates as advertised with no clear malicious behavior. It tracks incognito browsing history locally, includes legitimate analytics, and does not exfiltrate browsing data to third parties beyond standard analytics events. However, the inclusion of analytics in an extension designed for privacy-conscious users (tracking incognito mode) represents a minor privacy concern.

## Vulnerability Details

### 1. Analytics Tracking in Privacy Extension
**Severity**: LOW
**Files**: `popup.js` (lines 1-200, 9900-9933)
**Verdict**: Privacy Concern

**Description**:
The extension includes Google Analytics 4 (GA4) with tracking ID `G-2P4ENHZPXT` and sends usage telemetry including:
- Click events with user IDs
- View events
- Extension settings (delete after setting)
- Error exceptions

**Code Evidence**:
```javascript
// popup.js lines 33-34
vtp_trackingId: "G-2P4ENHZPXT",
vtp_sessionDuration: 0,

// popup.js lines 9904-9911
function u(t, e, n) {
    if ("undefined" != typeof gtag) {
        const r = {
            event_category: t,
            event_uid: n.uid,
            event_uid_install: s(n.uid),
            ...c()
        };
        n.hasOwnProperty("settingsDeleteAfter") &&
            (r.event_settings_delete_after = n.settingsDeleteAfter),
        gtag("event", e + "_click", r)
    }
}

// popup.js line 9933
gtag("js", new Date), gtag("config", "G-2P4ENHZPXT");
```

**Analysis**:
- Extension generates a unique user ID (UID) on install and includes it in analytics events
- The UID is generated as: `Math.floor(9e8*Math.random())+1e8}-${Math.floor((new Date).getTime()/1e3)}`
- Analytics events include: popup views, tab clicks, settings changes, errors
- **No browsing history URLs or titles are sent to analytics** - only usage patterns
- Data sent to: `https://www.google-analytics.com/g/collect` and `https://analytics.google.com/g/collect`

**Privacy Impact**: While the extension markets itself as tracking incognito history (private browsing), it ironically includes third-party analytics. However, the analytics are limited to extension usage patterns and do not leak actual browsing URLs or page titles.

### 2. Cookie Access in Analytics Code
**Severity**: LOW
**Files**: `popup.js` (lines 4367-4400)
**Verdict**: Expected Functionality

**Description**:
The Google Analytics library included in popup.js has cookie reading/writing capabilities.

**Code Evidence**:
```javascript
// popup.js line 4370
Ma(a) && (a.document.cookie = t);

// popup.js line 4420
return Ma(window) ? window.document.cookie : ""
```

**Analysis**:
- Cookie access is part of the standard Google Analytics library
- Used for GA's own tracking purposes (session management, attribution)
- Not accessing browser cookies from tracked sites
- Only operates within extension popup context, not content script context

**Verdict**: Standard analytics library behavior, not a vulnerability.

### 3. Uninstall Survey Redirect
**Severity**: INFORMATIONAL
**Files**: `background.js` (line 201)
**Verdict**: Benign

**Description**:
Extension sets an uninstall URL to redirect users to a Google Form.

**Code Evidence**:
```javascript
chrome.runtime.setUninstallURL("https://forms.gle/SFe6KhBiumSuBH7T6")
```

**Analysis**: Standard practice for collecting uninstall feedback. Not a security concern.

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `XMLHttpRequest` | popup.js:8436 | Part of GA4 library for sending analytics beacons | False Positive |
| `document.cookie` | popup.js:4370, 4420 | GA4 cookie management, not accessing user cookies | False Positive |
| `.call()/.apply()` | popup.js (multiple) | Standard JavaScript function binding patterns | False Positive |
| `postMessage` | popup.js:4693 | Part of GA4 TCF (Transparency & Consent Framework) API implementation | False Positive |
| `eval` patterns | None found | - | N/A |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://www.google-analytics.com/g/collect` | GA4 analytics collection | Extension usage events, UID, settings | LOW |
| `https://analytics.google.com/g/collect` | GA4 analytics collection (alternate) | Extension usage events, UID, settings | LOW |
| `https://www.googletagmanager.com/a?id=G-2P4ENHZPXT&cv=1` | GTM container load | Container metadata | LOW |
| `https://forms.gle/SFe6KhBiumSuBH7T6` | Uninstall feedback form | User-submitted feedback (optional) | INFORMATIONAL |
| `https://www.merchant-center-analytics.goog/mc/collect` | GA4 merchant center endpoint (conditional) | Analytics data | LOW |

## Data Flow Summary

### Local Data Storage
The extension stores the following data in `chrome.storage.local`:
- **tabs**: Object mapping tab IDs to tab metadata (URL, title, favicon, timestamp, expiry, windowId)
- **history**: Array of visited URLs with metadata
- **recent**: Array of recently closed tabs
- **setting_delete_after**: Retention period (default 1 day, max 7 days, or -1 for session only)
- **uid**: Unique installation identifier
- **error**: Error logs (extension-generated, not user data)
- **install_log**: Installation/update events

### Data Expiration
```javascript
// background.js lines 27-35
function w(t) {
    const e = (new Date).getTime();
    let n = -1;
    for (let a = t.length - 1; a >= 0; a--)
        if (t[a] && t[a].expiry < e) {
            n = a;
            break
        }
    return t.slice(n + 1)
}
```
- History entries are automatically expired based on user settings
- Default: 1 day retention
- Maximum: 7 days retention
- Option: Delete on window close (-1 setting)

### External Data Transmission
1. **Analytics Only**: Extension sends usage telemetry to Google Analytics
   - Events: clicks, views, settings changes, errors
   - Included data: UID, event type, settings values
   - **NOT included**: Browsing URLs, page titles, tab content

2. **No Other Network Activity**: Extension does not:
   - Send browsing history to any servers
   - Make HTTP requests to third-party APIs
   - Use content scripts to exfiltrate page data
   - Communicate with remote command & control

### Permission Analysis
```json
"permissions": ["storage", "unlimitedStorage", "tabs"],
"incognito": "split"
```

- **storage/unlimitedStorage**: Required for storing incognito browsing history
- **tabs**: Required to access tab URL, title, favicon in incognito mode
- **incognito: split**: Extension runs in split mode (separate instances for normal/incognito)

**Assessment**: Permissions are appropriate for stated functionality.

## Security Observations

### Positive Security Practices
1. **Manifest V3**: Uses modern manifest version with better security model
2. **Local-First**: All browsing data stored locally, not transmitted to servers
3. **Incognito-Only Operation**: `chrome.extension.inIncognitoContext` checks ensure extension only operates in incognito windows
4. **Data Expiration**: Built-in data retention limits (max 7 days)
5. **No Content Scripts**: Extension does not inject scripts into web pages
6. **No Remote Code**: All code is bundled, no eval() or Function() constructors used for dynamic code execution
7. **Error Handling**: Proper error handling for chrome API calls

### Areas of Concern
1. **Analytics in Privacy Tool**: Including telemetry in a tool designed for privacy-conscious users (incognito tracking) is philosophically inconsistent, though technically benign
2. **Minified Analytics**: Large GA4 library (~10k lines) is difficult to audit thoroughly
3. **Favicon Leakage**: Favicons are stored, which could potentially leak information about visited sites through filesystem access (though this is local storage only)

## Comparison to Similar Extensions

**Intent**: Provide browsing history functionality in incognito mode (where Chrome normally doesn't save history)

**Similar Extensions**:
- Incognito History (stores history during incognito sessions)
- Private History (similar functionality)

**Key Difference**: This extension appears to be genuinely focused on user-side functionality rather than data harvesting. The analytics are for product improvement, not for selling browsing data.

## Overall Risk Assessment

**Risk Level**: **LOW**

**Justification**:
1. **No Malicious Behavior**: Extension does not exfiltrate browsing history, inject ads, modify pages, or perform unauthorized actions
2. **Transparent Functionality**: Extension operates as described - it tracks incognito browsing locally
3. **Limited Analytics**: While analytics are present, they track extension usage, not browsing behavior
4. **Appropriate Permissions**: Extension only requests permissions necessary for stated functionality
5. **No Remote Control**: No evidence of command & control, kill switches, or dynamic configuration
6. **No Obfuscation**: Code is minified but not deliberately obfuscated to hide malicious behavior

**User Concerns**:
- Users seeking complete privacy may object to the inclusion of Google Analytics
- Extension open-source on GitHub (https://github.com/dutiyesh/off-the-record-history) which increases transparency

**Recommendation**: Extension is safe for general use. Privacy-conscious users should be aware of analytics tracking, though it does not compromise browsing privacy. The extension serves its intended purpose without malicious side effects.
