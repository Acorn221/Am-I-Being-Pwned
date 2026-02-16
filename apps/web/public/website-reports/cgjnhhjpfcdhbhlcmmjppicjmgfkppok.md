# Vulnerability Report: DownAlbum

## Metadata
- **Extension ID**: cgjnhhjpfcdhbhlcmmjppicjmgfkppok
- **Extension Name**: DownAlbum
- **Version**: 0.20.7.1
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

DownAlbum is a social media album and video download tool that operates on Facebook, Instagram, Pinterest, Twitter, Ask.fm, and Weibo. The extension provides legitimate functionality for downloading photos and videos from these platforms. However, it accesses sensitive authentication tokens including CSRF tokens and session cookies from user browsers to authenticate API requests to social media platforms. While this behavior is necessary for the extension's core functionality, it raises privacy concerns as the extension has access to credentials that could be used for unauthorized actions. The extension uses Google Analytics for telemetry and contains eval() usage for JSON parsing, which are minor security concerns.

The extension does not appear to exfiltrate user credentials or engage in malicious behavior beyond its stated purpose. All network requests are made to legitimate social media platforms and the extension's own infrastructure. The cookie and token access is used locally within content scripts to authenticate downloads, not transmitted to third parties.

## Vulnerability Details

### 1. MEDIUM: Cookie and CSRF Token Access
**Severity**: MEDIUM
**Files**: fetcher.js (lines 1798, 2047), saveHelper.js
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension reads CSRF tokens and session cookies directly from `document.cookie` to authenticate API requests to Instagram, Twitter, and Facebook. While this is necessary for the download functionality, it means the extension has access to sensitive authentication credentials.

**Evidence**:
```javascript
// fetcher.js line 1798 - Instagram CSRF token access
var token = g.token || document.cookie.match(/csrftoken=(\S+);/)

// fetcher.js line 2047 - Twitter CSRF token access
g.csrf = document.cookie.split(';').filter(s => s.indexOf('ct0') > -1)[0].split('=')[1];
```

**Verdict**: This is expected behavior for a download extension that needs to authenticate API requests. The tokens appear to be used only for making authenticated fetch() calls to download content, not exfiltrated. However, the extension technically has access to session credentials that could be misused. This warrants a MEDIUM rating due to the sensitivity of the data accessed, even though no malicious use is observed.

### 2. MEDIUM: Use of eval() for JSON Parsing
**Severity**: MEDIUM
**Files**: fetcher.js (lines 147, 2074)
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
**Description**: The extension uses `eval()` as a fallback for JSON parsing and to execute embedded JavaScript configuration from Weibo pages.

**Evidence**:
```javascript
// fetcher.js line 147 - Fallback JSON parsing with eval
try {
  res = JSON.parse(candidate);
  return res;
} catch (e) {}
try {
  res = eval("(" + candidate + ")");
  return res;
} catch (e) {}

// fetcher.js line 2074 - Weibo config parsing
eval(id);  // id contains text matching /\$CONFIG\['oid'\]/
```

**Verdict**: The first use is a fallback for parsing malformed JSON from social media responses. The second use extracts configuration from Weibo page scripts. While eval() is generally dangerous, the data being evaluated comes from social media platforms the user is already visiting, not from arbitrary user input or remote sources. This is a code quality issue rather than a critical vulnerability, but should be refactored to use safer parsing methods.

### 3. LOW: Broad Permissions Scope
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>`, `webRequest`, and `webRequestBlocking` permissions. While these are used for legitimate purposes (modifying Instagram API request headers and intercepting download requests), they grant the extension significant capabilities.

**Evidence**:
```json
"permissions": [
  "<all_urls>",
  "storage",
  "tabs",
  "unlimitedStorage",
  "webRequest",
  "webRequestBlocking"
]
```

**Verdict**: The permissions are appropriate for the extension's functionality. The `webRequest` permissions are used to modify User-Agent headers for Instagram API calls (background.js line 280-295) to allow downloading stories. Content scripts are properly scoped to only Facebook and Instagram domains. This is a low-severity issue as the permissions match the extension's legitimate needs.

## False Positives Analysis

1. **Google Analytics Integration**: The extension includes Google Analytics (UA-38726447-3) for usage tracking. This is disclosed in the extension description and is standard telemetry, not malicious tracking.

2. **Network Requests to Social Media APIs**: All fetch() calls and XMLHttpRequests go to legitimate social media platform APIs (Instagram, Facebook, Twitter, Weibo, etc.) to retrieve photo/video data. This is the core functionality of the extension.

3. **User-Agent Spoofing**: The extension modifies User-Agent headers to appear as an iPhone app when requesting Instagram story data (background.js line 288). This is necessary to access mobile-only API endpoints and is a common technique for download tools.

4. **localStorage Usage**: The extension stores user preferences (layout settings, album data) in localStorage and chrome.storage. This is benign local data storage.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| i.instagram.com | Instagram story/user API | User ID, auth headers | Low - legitimate API access |
| www.instagram.com | Instagram GraphQL API | Query parameters, cookies | Low - legitimate API access |
| photo.weibo.com | Weibo photo album API | User ID, album ID | Low - legitimate API access |
| api.twitter.com | Twitter media timeline | User ID, CSRF token | Low - legitimate API access |
| www.facebook.com | Facebook video/photo API | CSRF token, user ID | Low - legitimate API access |
| www.google-analytics.com | Usage telemetry | Page views, events | Low - standard analytics |
| connect.facebook.net | Facebook SDK | Social widgets | Low - standard SDK |
| rawgit.com | CDN (deprecated) | None | Low - static resources |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: DownAlbum is a legitimate social media download utility that performs its stated function without malicious intent. However, it accesses sensitive authentication credentials (CSRF tokens and session cookies) from multiple social media platforms, which raises privacy concerns. While these credentials are used appropriately for authenticating download requests and not exfiltrated, the extension has technical access to data that could enable account hijacking if the code were modified maliciously or the extension were compromised.

The eval() usage and broad permissions are additional concerns, though less severe. The extension does not engage in hidden data collection, credential theft, or unauthorized API access beyond what's necessary for its download functionality.

Users should be aware that this extension has access to their social media session credentials when using it. The extension appears trustworthy based on code review, but the access to sensitive tokens inherently carries risk. A future version should consider using more secure authentication methods if available from the platforms.
