# Vulnerability Report: Leetcode helper by labuladong

## Metadata
- **Extension ID**: elafhogmnaapleckojedgipgmidneccg
- **Extension Name**: Leetcode helper by labuladong
- **Version**: 6.0.4
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a LeetCode study companion that displays algorithmic solutions and explanations from labuladong.online directly on LeetCode problem pages. The extension injects content scripts on leetcode.com and leetcode.cn to enhance the user experience with solution previews, study plans, and learning materials.

Analysis reveals minimal security concerns. The extension fetches metadata and user authentication tokens from labuladong.online, but this behavior is consistent with its stated purpose as a study helper. The static analyzer flagged six exfiltration flows where storage data and DOM content are sent to labuladong.online, but upon manual review, these flows represent legitimate feature functionality (fetching solutions based on problem slugs, user preferences, and authentication status). The extension uses standard permissions (storage, unlimitedStorage) and follows modern MV3 security practices.

## Vulnerability Details

### 1. LOW: Remote Configuration and User Token Transmission
**Severity**: LOW
**Files**: static/background/index.js, leetcode.14fe0dea.js, leetcode_cn.612a0eb3.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension fetches remote metadata from labuladong.online and retrieves user authentication tokens via the site's API. The background service worker periodically updates metadata from `https://labuladong.online/plugin-v6/meta_v2.json` and fetches authentication cookies from `https://labuladong.online/api/v1/user/cookie-val/`.

**Evidence**:
```javascript
// Background script - metadata fetch
let t = await fetch("https://labuladong.online/plugin-v6/meta_v2.json");
let o = await t.json();
await chrome.storage.local.set({
  meta_v2: o,
  lastMetaUpdateTime: n
});

// Background script - token retrieval
let e = await fetch("https://labuladong.online/api/v1/user/cookie-val/", {
  method: "GET",
  credentials: "include",
  headers: {
    "Content-Type": "application/json"
  }
});
```

**Verdict**: This behavior is expected for a companion extension that needs to authenticate users with the associated learning platform. The token is only sent to labuladong.online (the extension author's domain), and the metadata controls which problems have available solutions. The extension uses HTTPS for all communications. This is standard practice for extensions that integrate with external services.

## False Positives Analysis

**Static Analyzer Exfiltration Flows**: The ext-analyzer tool flagged 6 HIGH-severity exfiltration flows where `chrome.storage.local.get`, `chrome.storage.sync.get`, and `document.querySelectorAll` data flows to `fetch(labuladong.online)`. However, upon manual inspection:

1. **Storage access**: The extension reads user preferences (language, theme, display settings) and the cached metadata to determine which solutions are available for the current problem.

2. **DOM queries**: The extension extracts the problem title/slug from the LeetCode page DOM to look up the corresponding solution URL.

3. **Network requests**: Data is sent to labuladong.online only to construct iframe URLs for displaying solutions, and to retrieve authentication tokens for premium content access.

These flows represent legitimate functionality for a study helper extension - it needs to know what problem the user is viewing and their preferences to display the correct solution. The extension does not exfiltrate browsing history, sensitive form data, or credentials from other sites.

**externally_connectable Warning**: The manifest declares `"externally_connectable": {"matches": ["*://labuladong.online/*"]}`, allowing the labuladong.online website to send messages to the extension. This is intentional and necessary for coordinating authentication state between the website and extension. The extension only accepts specific commands (`get_site_token`, `check_meta`) and does not expose dangerous functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| labuladong.online/plugin-v6/meta_v2.json | Fetch metadata about available solutions | None | Low - Public metadata |
| labuladong.online/api/v1/user/cookie-val/ | Retrieve user auth token | Browser cookies (credentials: include) | Low - Expected authentication flow |
| labuladong.online/.../algo/leetcode/{slug}/ | Display solution iframe | Problem slug, theme preference, auth token | Low - Core functionality |
| leetcode.com/graphql/ | Fetch study plan details | Study plan slug | Low - Public LeetCode API |
| leetcode.cn/graphql/ | Fetch study plan details (Chinese) | Study plan slug | Low - Public LeetCode API |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension performs its stated function (providing study solutions for LeetCode problems) without engaging in concerning security or privacy practices. While it does communicate with a third-party domain (labuladong.online), this is transparent in the extension's description and necessary for its core functionality. The extension:

- Uses minimal permissions (storage only, no broad host permissions)
- Does not access sensitive user data beyond the current LeetCode problem page
- Follows MV3 security best practices (no eval, CSP-compliant, service worker background)
- Implements proper sandboxing for iframes displaying external content
- Only communicates with its own backend service and the public LeetCode GraphQL API

The remote configuration pattern (fetching metadata and tokens) is a minor concern but falls within acceptable bounds for a legitimate study/education extension. Users should be aware that their LeetCode activity (which problems they view) is shared with labuladong.online to fetch corresponding solutions, but this is inherent to the extension's value proposition.

**Recommendation**: Safe for use by individuals seeking LeetCode study assistance. Users should understand that their problem-solving activity is visible to the labuladong.online service.
