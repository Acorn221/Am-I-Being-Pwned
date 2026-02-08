# Vulnerability Analysis Report: Simple Gmail Notes

## Extension Metadata
- **Extension Name**: Simple Gmail Notes
- **Extension ID**: jfjkcbkgjohminidbpendlodpfacgmlm
- **Version**: 2.9.21.9
- **User Count**: ~80,000 users
- **Analysis Date**: 2026-02-07
- **Codebase Size**: ~13,723 lines of JavaScript

## Executive Summary

Simple Gmail Notes is a Gmail productivity extension that allows users to add notes to emails and sync them via Google Drive. The extension also offers a premium "Simple Mobile CRM" feature with team collaboration capabilities. After comprehensive analysis of the codebase, the extension appears to be **legitimate** with no evidence of malicious behavior. However, there are **privacy and security concerns** related to the CRM feature that collects email metadata and communicates with third-party servers.

**Overall Risk Assessment: MEDIUM**

The extension uses appropriate Google OAuth flows, does not contain obfuscated malware patterns, and appears to function as advertised. The medium risk rating is due to:
1. Collection and transmission of email metadata to third-party CRM servers
2. Cross-origin postMessage communication with external domains
3. Broad content script permissions on mail.google.com
4. Optional data collection features that may not be fully transparent to users

## Vulnerability Details

### 1. Email Metadata Collection and Transmission
**Severity**: MEDIUM
**Files**: `content.js`, `background.js`, `settings.js`
**Lines**: Multiple locations

**Description**:
The extension's CRM feature collects email metadata and transmits it to `sgn.mobilecrm.io` and `portal.simplegmailnotes.com`. The extension reads email subjects, sender/recipient information, timestamps, and message IDs from Gmail.

**Code Evidence**:
```javascript
// settings.js:22-24
CRM_BASE_URL: "https://sgn.mobilecrm.io",
SGN_WEB_LOGIN_BASE_URL: "https://app.simplegmailnotes.com",
SUBSCRIBER_PORTAL_BASE_URL: "https://portal.simplegmailnotes.com/",
```

```javascript
// content.js:6865-6867
sendBackgroundMessage({action:"update_crm_user_info",
                      crm_user_email: crm_user_email,
                      crm_user_token: crm_user_token});
```

**Verdict**: **PRIVACY CONCERN** - The extension collects email metadata for its CRM feature. While this appears to be intentional functionality for the advertised CRM service, users may not be fully aware of the extent of data collection. The extension has optional flags like `is_collect_full_email` and `is_collect_full_email_img` (content.js:6855-6856) suggesting potential collection of full email content.

---

### 2. Cross-Origin postMessage Communication
**Severity**: MEDIUM
**Files**: `content.js`, `page.js`
**Lines**: content.js:6792-6977, page.js:854

**Description**:
The extension uses `postMessage` to communicate with external domains (`sgn.mobilecrm.io`) and accepts messages prefixed with "sgncrm:". While origin validation is performed, this creates an attack surface.

**Code Evidence**:
```javascript
// content.js:6792-6795
window.addEventListener('message', function(e) {
  if (typeof e.data !== 'string' || !e.data.startsWith("sgncrm"))
    return;
```

```javascript
// content.js:2683
win.postMessage(extraData, settings.CRM_BASE_URL);
```

**Verdict**: **ACCEPTABLE WITH CAUTION** - The extension validates message origins and uses string prefixes for message filtering. However, postMessage communication with external domains always carries risk. The implementation appears reasonable but should be monitored for changes.

---

### 3. Google API Token Management
**Severity**: LOW
**Files**: `background.js`
**Lines**: 625-647, 1098-1140

**Description**:
The extension handles Google OAuth refresh tokens and access tokens for Drive API access. Tokens are stored in chrome.storage.local.

**Code Evidence**:
```javascript
// background.js:625-634
var result = SGNC.getBrowser().identity.launchWebAuthFlow(
  {"url": "https://accounts.google.com/o/oauth2/auth?" +
    $.param({"client_id": clientId,
        "scope": scope,
        "redirect_uri": SGNC.getRedirectUri(),
        "response_type":"code",
        "access_type":"offline",
        "login_hint":sender.email,
        "prompt":"consent select_account"
    }),
```

**Verdict**: **CLEAN** - The extension uses legitimate Google OAuth flows via `chrome.identity.launchWebAuthFlow`. Token management follows standard patterns with appropriate error handling. The scope is limited to `https://www.googleapis.com/auth/drive.file` (settings.js:10), which only grants access to files created by the extension.

---

### 4. Network Requests to Third-Party Servers
**Severity**: MEDIUM
**Files**: `background.js`, `content.js`
**Lines**: Multiple locations

**Description**:
The extension makes network requests to several domains:
- `*.googleapis.com` (legitimate Google APIs)
- `sgn.mobilecrm.io` (CRM backend)
- `portal.simplegmailnotes.com` (subscriber portal)
- `bart.solutions` (marketing/support site)
- `static-gl*.simplegmailnotes.com` (static assets)

**Code Evidence**:
```javascript
// background.js:540
fetch(url, payload)
```

All Google API requests use standard REST endpoints:
- `https://www.googleapis.com/upload/drive/v2/files` (notes storage)
- `https://www.googleapis.com/oauth2/v3/token` (token refresh)
- `https://www.googleapis.com/drive/v2/about` (account info)

**Verdict**: **ACCEPTABLE** - Network requests to Google APIs are legitimate and expected. Requests to simplegmailnotes.com and mobilecrm.io domains are for the advertised CRM functionality. No evidence of data exfiltration to unexpected domains.

---

### 5. Content Script DOM Manipulation
**Severity**: LOW
**Files**: `content.js`, `page.js`, `common/gmail-sgn-dom.js`
**Lines**: Multiple locations

**Description**:
The extension performs extensive DOM manipulation on Gmail pages to inject note UI elements. Uses jQuery for DOM traversal and modification.

**Code Evidence**:
```javascript
// content.js:5144-5147
var innerHTML = errorNode.html();
var finalErrorMessage = innerHTML;
```

**Verdict**: **CLEAN** - DOM manipulation is limited to adding UI elements for notes functionality. No evidence of HTML injection attacks, XSS attempts, or data harvesting from other extensions' DOM elements. The `innerHTML` usage observed is for reading error messages, not injection.

---

### 6. Extension Update Behavior
**Severity**: LOW
**Files**: `background-event.js`
**Lines**: 36-89

**Description**:
The extension opens marketing tabs on install and update events, directing users to `bart.solutions`.

**Code Evidence**:
```javascript
// background-event.js:47
chrome.tabs.create({url: "https://bart.solutions/simple-gmail-notes-installed/"}, function (tab) {
  console.log("Welcome page launched");
});

// background-event.js:80
chrome.tabs.create({url: "https://bart.solutions/simple-gmail-notes-updated/"}, function (tab) {
  console.log("Welcome page launched");
});
```

**Verdict**: **ACCEPTABLE** - Opening welcome/update tabs is common extension behavior. Users can disable update tabs via the `disableUpgradeTab` preference (background-event.js:77).

---

## False Positives Table

| Pattern Detected | Context | Why It's Not Malicious |
|-----------------|---------|------------------------|
| `innerHTML` usage | content.js:5144 | Reading error messages from DOM, not injecting content |
| `postMessage` | content.js:6792, page.js:854 | Legitimate IPC with owned CRM domain, origin validated |
| `fetch()` calls | background.js:540 | Standard API calls to Google and owned domains |
| `atob/btoa` | common/shared-common.js, page.js, content.js | Base64 encoding for data serialization (standard practice) |
| Token storage | background.js:1132-1133 | OAuth tokens stored in chrome.storage.local (secure) |
| Email metadata access | content.js, page.js | Core functionality - adding notes to emails requires message IDs |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| `https://www.googleapis.com/upload/drive/v2/files` | Store notes | Note content, email message ID, metadata | Legitimate |
| `https://www.googleapis.com/oauth2/v3/token` | Token refresh | OAuth refresh token | Legitimate |
| `https://www.googleapis.com/drive/v2/about` | User info | Access token | Legitimate |
| `https://sgn.mobilecrm.io` | CRM features | Email metadata, user tokens | Privacy concern |
| `https://portal.simplegmailnotes.com/*` | Subscription | User email, subscription status | Acceptable |
| `https://bart.solutions/*` | Marketing | None (tab navigation only) | Acceptable |
| `https://accounts.google.com/*` | OAuth flow | Standard OAuth parameters | Legitimate |

## Data Flow Summary

1. **Note Creation Flow**:
   - User types note in Gmail → Content script captures content
   - Content script sends to background via chrome.runtime.sendMessage
   - Background uploads to Google Drive via Drive API
   - Note metadata stored in chrome.storage.local for caching

2. **CRM Feature Flow** (Optional, requires user opt-in):
   - User logs into CRM via iframe to `sgn.mobilecrm.io`
   - CRM sends auth token via postMessage
   - Email metadata (subject, sender, timestamp) sent to CRM backend
   - CRM responses update Gmail UI with team notes/comments

3. **Authentication Flow**:
   - User clicks login → chrome.identity.launchWebAuthFlow launched
   - Google OAuth consent screen shown
   - Authorization code exchanged for refresh token
   - Tokens stored in chrome.storage.local per email account

## Privacy Analysis

**Data Collected**:
- Email message IDs (required for note association)
- Email subjects (stored in note titles)
- Gmail account email addresses
- Note content (user-generated)
- CRM features: sender/recipient addresses, timestamps, full email content (if enabled)

**Data Storage**:
- Notes: Google Drive (user's own account)
- Tokens: chrome.storage.local (local only)
- Preferences: chrome.storage.local (local only)
- CRM data: Transmitted to `sgn.mobilecrm.io` (third-party server)

**Data Sharing**:
- Google Drive API: Note content shared with user's own Drive account
- CRM servers: Email metadata optionally shared with mobilecrm.io for team features
- No evidence of data sharing with advertising networks or analytics platforms

## Security Strengths

1. **Proper OAuth Implementation**: Uses chrome.identity API correctly with appropriate scopes
2. **No Dynamic Code Execution**: No eval(), Function(), or remote script loading
3. **Limited Permissions**: Only requests necessary permissions (storage, identity, googleapis.com)
4. **CSP Present**: Manifest v3 with service worker architecture (no persistent background)
5. **Open Source**: GPL v3 licensed, source available on GitHub (walty8)
6. **No Obfuscation**: Code is readable with standard beautification

## Recommendations

1. **For Users**:
   - Review CRM feature settings if privacy is a concern
   - Understand that enabling CRM features shares email metadata with third-party servers
   - Extension is safe for basic note-taking functionality without CRM

2. **For Developers**:
   - Add clearer privacy disclosures for CRM data collection
   - Implement Content Security Policy in manifest
   - Consider end-to-end encryption for CRM features
   - Add audit logging for data transmitted to CRM servers

3. **For Security Researchers**:
   - Monitor changes to CRM backend communication patterns
   - Verify TLS configuration on mobilecrm.io domain
   - Review any future additions of analytics SDKs

## Overall Risk Assessment

**MEDIUM**

**Rationale**:
- **No Critical/High Vulnerabilities Found**: No malware, no credential theft, no ad injection
- **Legitimate Business Model**: Premium subscription for CRM features, not ad-supported
- **Privacy Trade-offs**: CRM features require sharing email metadata, but this is opt-in
- **Appropriate Permissions**: Extension only requests permissions necessary for functionality
- **Standard Security Practices**: OAuth flows, API usage, and token management follow best practices

The extension is **safe for general use** with the caveat that users enabling CRM features should understand email metadata is shared with third-party servers. The medium risk rating reflects privacy considerations rather than security vulnerabilities.

## Additional Notes

- Extension has been actively maintained since 2017 (GPLv3 license, copyright Walty Yeung)
- Large codebase (~14k LOC) with multiple third-party libraries (jQuery, TinyMCE, Moment.js)
- Manifest v3 compliant with service worker architecture
- No suspicious patterns matching known malware families
- GitHub repository: https://github.com/walty8 (per license headers)

---

**Analyst Note**: This extension represents a legitimate productivity tool with transparent functionality. The "CRM" features are clearly a value-add service requiring backend infrastructure, which explains the third-party communication. No evidence of malicious intent, deceptive practices, or unauthorized data collection was found.
