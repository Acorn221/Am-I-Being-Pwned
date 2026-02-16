# Vulnerability Report: Reader Mode

## Metadata
- **Extension ID**: llimhhconnjiflfimocjggfjdlmlhblm
- **Extension Name**: Reader Mode
- **Version**: 2.0.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Reader Mode is a legitimate browser extension that provides distraction-free reading with accessibility features, bookmarking, highlighting, and research tools. The extension communicates with its backend service at readermode.io for user authentication and data synchronization. After analysis of the deobfuscated code, the extension appears to function as advertised with minimal security concerns. The primary finding is a low-severity use of localStorage extraction for authentication tokens, which is limited to the extension's own domain (readermode.io) and represents standard OAuth/authentication flow implementation.

## Vulnerability Details

### 1. LOW: LocalStorage Access for Authentication
**Severity**: LOW
**Files**: bg.js (lines 30-52)
**CWE**: CWE-922 (Insecure Storage of Sensitive Information)
**Description**: The background script uses `chrome.scripting.executeScript` to extract localStorage data from web pages to retrieve authentication tokens (`readermode_auth_token`) and user data (`readermode_user`). This pattern executes when users navigate to the extension's own authentication pages.

**Evidence**:
```javascript
chrome.tabs.query({ currentWindow: true, active: true }, function(tabs) {
  chrome.scripting.executeScript({ target: { tabId: tabs[0].id }, function(){
    var res = JSON.stringify(localStorage);
    res = JSON.parse(res);

    if (res.readermode_auth_token) {
      chrome.storage.local.set({"auth_token": res.readermode_auth_token});
    }
    if (res.readermode_user) {
      chrome.storage.local.set({"user": user});
    }
  }});
});
```

This code is triggered specifically when the user visits `readermode.io/token` or `readermode.io/login` pages (lines 121-126 in bg.js).

**Verdict**: This is a legitimate authentication flow. The extension only reads localStorage from its own domain (readermode.io) during the OAuth callback process. This is standard practice for browser extensions integrating with web-based authentication systems. Not a security vulnerability in practice, as it's limited to the extension's own service domain and only activates during the authentication flow.

## False Positives Analysis

The static analyzer flagged this extension as "obfuscated", but upon manual review, the code is standard webpack-bundled JavaScript with jQuery and other common libraries. The code uses normal function names, readable variable names, and includes extensive commented code. This is not true obfuscation.

The CSP configuration `sandbox allow-scripts; 'unsafe-inline' 'self'` only applies to sandboxed resources and is a low-risk configuration for the extension's use case (rendering reader mode content in iframes).

The extension uses `chrome.scripting.executeScript` and `chrome.tabs.executeScript` (deprecated MV2 API still present in code), but these are used legitimately for:
- Extracting authentication tokens from the extension's own domain
- Loading reader mode functionality into web pages at user request
- No evidence of unauthorized code injection or data theft

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://readermode.io/token | OAuth token exchange | OAuth credentials (client_id, client_secret, refresh_token) | Low - Standard OAuth flow |
| https://readermode.io/extension/save_article | Save bookmarked articles | Article metadata (title, URL, highlights, reading time) | Low - Disclosed feature |
| https://readermode.io/extension/remove_article | Delete saved articles | Article identifier | Low - Disclosed feature |
| https://readermode.io/dashboard | User dashboard | None (navigation only) | None |
| https://readermode.io/welcome | Welcome page on install | None (navigation only) | None |

All endpoints are on the extension's own domain (readermode.io). The extension uses Bearer token authentication for API calls (line 188 in api.js).

Data sent to the server includes:
- Article metadata (title, author, URL, description, reading time)
- User highlights and annotations
- Folder/organization data for saved articles

This data collection is disclosed in the extension's description ("bookmarking, highlighting, and research tools") and is core to the extension's functionality.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate productivity extension that functions as advertised. The extension provides reader mode functionality with cloud sync features via the readermode.io service. While it has broad permissions (<all_urls>, scripting, tabs), these are necessary for its core functionality of rendering any web page in reader mode.

The localStorage extraction pattern initially appeared suspicious but is limited to:
1. Only the extension's own domain (readermode.io)
2. Only during authentication flow (token/login pages)
3. Standard OAuth/SSO implementation pattern for browser extensions

No evidence of:
- Unauthorized data exfiltration
- Hidden network requests to third parties
- Credential theft beyond the extension's own authentication
- Malicious code injection
- Privacy violations beyond disclosed functionality

The single low-severity finding relates to the authentication implementation pattern, which follows industry standard practices for browser extension authentication flows. Users should be aware that article data, highlights, and bookmarks are synced to readermode.io servers, but this is clearly part of the extension's disclosed functionality.
