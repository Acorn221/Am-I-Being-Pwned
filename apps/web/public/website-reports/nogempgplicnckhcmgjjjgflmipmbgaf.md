# Vulnerability Report: Influencer Analytics by Wednesday

## Metadata
- **Extension ID**: nogempgplicnckhcmgjjjgflmipmbgaf
- **Extension Name**: Influencer Analytics by Wednesday
- **Version**: 3.0.0.4
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Influencer Analytics by Wednesday" is a legitimate influencer marketing analytics tool that provides profile insights for creators on Instagram, Twitter, YouTube, Pinterest, TikTok, and Twitch. The extension injects a UI panel that loads content from `plugin.wednesday.app`, passing along the current page URL and user's Chrome profile email/ID obtained via the `chrome.identity.getProfileUserInfo()` API.

The extension demonstrates clean development practices with proper webpack bundling, Sentry error monitoring, and no evidence of obfuscation or malicious behavior. The static analyzer found no suspicious data flows, and manual code review confirms the extension operates transparently within its stated purpose. The only minor concern is the broad `*://*/*` host permission, though this is appropriately scoped to the extension's multi-platform analytics functionality.

## Vulnerability Details

### 1. LOW: Broad Host Permissions with Limited Actual Usage

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-272 (Least Privilege Violation)
**Description**: The extension declares `"host_permissions": ["*://*/"]` in the manifest, granting access to all websites. However, the actual content script injection is limited to specific social media platforms (Instagram, Twitter, YouTube, Pinterest, TikTok, Twitch) via the `matches` property in `content_scripts`.

**Evidence**:
```json
"content_scripts": [
  {
    "js": ["src/content.js"],
    "matches": [
      "https://www.instagram.com/*",
      "https://twitter.com/*",
      "https://www.youtube.com/*",
      "https://www.pinterest.com/*",
      "https://www.tiktok.com/*",
      "https://www.twitch.tv/*"
    ]
  }
]
```

**Verdict**: While the broad host permission is not ideal from a least-privilege perspective, it does not pose a significant security risk because:
1. Content scripts only run on whitelisted social media domains
2. The extension does not hook or intercept network traffic beyond its stated purpose
3. MV3's activeTab permission provides additional protections
4. No evidence of the permission being abused for unintended data collection

## False Positives Analysis

1. **Sentry Error Tracking**: The extension includes Sentry monitoring with DSN `https://bc498a7177f74c489aacf6cc78a634a1@o6937.ingest.us.sentry.io/1242252`. This is standard error tracking for production applications and does not collect user data beyond crash reports.

2. **Webpack Bundle**: The majority of background.js (6,200 lines) consists of bundled Sentry SDK code. This is not obfuscation but standard dependency packaging.

3. **chrome.identity.getProfileUserInfo()**: The extension collects the user's Chrome profile email and ID. This is disclosed functionality for an influencer marketing tool that requires user identification to provide analytics services. The data is sent only to the first-party domain `plugin.wednesday.app`.

4. **iframe.js URL Decoding**: The iframe wrapper uses `decodeURIComponent(location.search.replace('?url=', ''))` to extract the plugin URL. This is a legitimate technique for nested iframes and not an attempt to obfuscate URLs.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| plugin.wednesday.app | Main analytics service | Page URL, user email, user ID, extension ID | Low - disclosed first-party service |
| o6937.ingest.us.sentry.io | Error monitoring | Stack traces, error context | Low - standard error tracking |

## Data Flow Analysis

1. **User triggers extension** (clicks icon or quick-access button on social media page)
2. **Background script obtains user info** via `chrome.identity.getProfileUserInfo()` → `{email, id}`
3. **Background script injects iframe** into page with URL: `https://plugin.wednesday.app?url={pageURL}&user_email={email}&user_id={id}&extension_id={extID}`
4. **iframe.html wrapper loads** the plugin URL via nested iframe
5. **Plugin service renders analytics** for the influencer profile on the current page

No unexpected network requests or data exfiltration beyond this documented flow.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension is a legitimate business tool with transparent functionality. The use of `chrome.identity` permissions to collect user email/ID is appropriate for a SaaS analytics product that requires user authentication. The data is sent only to the first-party Wednesday platform (`plugin.wednesday.app`), which is consistent with the extension's disclosed purpose of providing influencer marketing analytics.

The code quality is professional, with proper error handling via Sentry, no use of dangerous APIs (eval, Function constructor), and no evidence of obfuscation or malicious intent. The only minor issue is the overly broad host permission, but this does not result in actual over-collection of data.

**Recommendation**: CLEAN with minor improvement suggestion to reduce host_permissions scope to specific social media domains rather than `*://*/`.
