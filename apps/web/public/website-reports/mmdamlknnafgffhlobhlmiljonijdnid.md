# Vulnerability Assessment Report

## Extension Metadata
- **Name**: Titans Pro - Amazon KDP Keyword Research Tool
- **Extension ID**: mmdamlknnafgffhlobhlmiljonijdnid
- **User Count**: ~40,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Titans Pro is a legitimate keyword research tool for Amazon KDP authors and sellers. The extension provides keyword suggestion features across multiple e-commerce and search platforms (Amazon, Google, Etsy, eBay, Fiverr, Pinterest, TikTok, Walmart, YouTube, Bing, Audible).

After comprehensive analysis of the extension's manifest, background service worker, and 12 content scripts (totaling over 500,000 lines of code), **no malicious behavior or critical vulnerabilities were identified**. The extension operates as advertised, communicating only with its legitimate backend API at selfpublishingtitans.com for authentication and keyword data services.

## Vulnerability Details

### 1. Cookie Access in Content Scripts
**Severity**: LOW
**Files**: content-scripts/google.js (lines 42974-42991)
**Code**:
```javascript
sD = gn.hasStandardBrowserEnv ? {
  write(e, t, r, n, i, s) {
    const l = [e + "=" + encodeURIComponent(t)];
    xe.isNumber(r) && l.push("expires=" + new Date(r).toGMTString()),
    // ... domain, path, secure flags
    document.cookie = l.join("; ")
  },
  read(e) {
    const t = document.cookie.match(new RegExp("(^|;\\s*)(" + e + ")=([^;]*)"));
    return t ? decodeURIComponent(t[3]) : null
  },
  remove(e) {
    this.write(e, "", Date.now() - 864e5)
  }
}
```

**Verdict**: FALSE POSITIVE - Standard Axios HTTP client cookie utilities
**Explanation**: This is part of the bundled Axios library's XSRF protection mechanism. The cookie access is conditionally used only in browser environments and is a standard feature of the Axios HTTP client (used for CSRF token handling). No evidence of cookie harvesting or unauthorized access to sensitive cookies.

### 2. Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**Permissions**: `host_permissions: ["*://*/*"]`, `optional_host_permissions: ["*://*/*"]`

**Verdict**: JUSTIFIED - Required for multi-platform functionality
**Explanation**: The extension legitimately needs broad host permissions to operate across 12+ different platforms (Amazon, Google, Etsy, eBay, Fiverr, Pinterest, TikTok, Walmart, YouTube, Bing, Audible). Content scripts are explicitly scoped to specific domains in the manifest, and the extension uses the webext-permission-toggle library to request permissions on-demand per domain. This is appropriate for a cross-platform keyword research tool.

### 3. Background API Proxy Pattern
**Severity**: LOW
**Files**: background.js (lines 5855-5882)
**Code**:
```javascript
async function Ka({payload: e}) {
  const {method: t, url: r, headers: n, body: s} = e;
  try {
    const i = {
      method: t,
      headers: n,
      ...s ? {body: JSON.stringify(s)} : {}
    },
    o = await Ha(r, i, 12e4);  // 120s timeout
    if (!o.ok) throw new Error(`HTTP error! status: ${o.status}`);
    return await o.json()
  } catch (i) {
    throw console.error("API Request failed:", i), i
  }
}
```

**Verdict**: ACCEPTABLE - Standard service worker pattern
**Explanation**: Content scripts proxy API requests through the background service worker via the `handleApiRequests` message handler. This is a standard MV3 pattern since content scripts have CORS limitations. All observed requests go to legitimate endpoints at `selfpublishingtitans.com` and `go.selfpublishingtitans.com`. No evidence of unauthorized data exfiltration.

### 4. Session Token Storage
**Severity**: LOW
**Files**: background.js (lines 3961-3975)
**Code**:
```javascript
async function Co() {
  try {
    const e = await ro();  // ro = async () => (await z.get(`${tr}/api/auth/session`)).data
    if (e) return console.log("Logged in as", e),
      Br.setValue({
        id: e.id,
        username: e.username,
        email: e.email,
        avatar: e.picture,
        token: e.token
      }), e;
    Vr()  // Clear session
  } catch (e) {
    console.error(e), Vr()
  }
}
```

**Verdict**: ACCEPTABLE - Standard authentication pattern
**Explanation**: The extension stores user authentication tokens in chrome.storage (via the wxt storage API). Tokens are validated against `selfpublishingtitans.com/api/auth/session` and `selfpublishingtitans.com/api/v1/auth/verify`. This is standard practice for SaaS extensions requiring user authentication. No hardcoded credentials or insecure storage detected.

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` usage | Multiple React components | Standard React DOM manipulation via dangerouslySetInnerHTML for SVG rendering |
| Axios Authorization headers | content-scripts/search.js | Legitimate Bearer token authentication for API requests |
| `document.cookie` access | Axios library bundle | XSRF token handling, not used for cookie harvesting |
| Broad permissions | manifest.json | Required for 12-platform keyword research functionality |
| `chrome.downloads` API | background.js (5904-5910) | CSV export feature - legitimate user-initiated downloads |

## API Endpoints Analysis

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `selfpublishingtitans.com/api/auth/session` | GET | Session validation | Bearer token (Authorization header) |
| `selfpublishingtitans.com/api/v1/auth/verify` | GET | Token verification | Bearer token (Authorization header) |
| `selfpublishingtitans.com/extension/welcome?tab=month` | GET | New install welcome page | None (tab opened on install) |
| `go.selfpublishingtitans.com/api/v1/chrome/free-suggestions` | GET | Keyword suggestions (free tier) | Search query, auth token |

**Note**: All API communications use HTTPS. No third-party analytics SDKs, advertising networks, or data brokers detected.

## Data Flow Summary

1. **User Authentication**: Users log in via the popup UI → credentials sent to selfpublishingtitans.com → token stored in chrome.storage
2. **Keyword Research**: User searches on Amazon/Google/etc. → content script detects input → sends query + auth token to backend API via background proxy → displays keyword suggestions in overlay UI
3. **CSV Export**: User clicks export → data formatted client-side → chrome.downloads API initiates download
4. **No Third-Party Sharing**: All data flows exclusively between the extension and selfpublishingtitans.com. No external trackers, analytics, or data brokers.

## Security Strengths

1. **Manifest V3 Compliance**: Modern security model with service worker background
2. **No Remote Code Execution**: No `eval()`, `Function()`, or dynamic script loading
3. **CSP Compliant**: No content_security_policy weakening in manifest
4. **Scoped Content Scripts**: Despite broad permissions, content scripts explicitly limited to target domains
5. **No Extension Enumeration**: Does not query chrome.management or attempt to detect other extensions
6. **No Ad/Coupon Injection**: No DOM manipulation for advertising purposes
7. **Transparent Functionality**: All features clearly documented and match stated purpose

## Privacy Considerations

- **Search Query Collection**: The extension sends user search queries to the backend API for keyword analysis. This is inherent to the stated functionality.
- **User Consent**: Functionality requires user account creation and login, providing implicit consent for data processing.
- **Data Minimization**: Only search queries and authentication tokens are transmitted; no browsing history, cookies, or unrelated data harvesting observed.

## Overall Risk Assessment: **CLEAN**

**Justification**:

Titans Pro is a **legitimate commercial keyword research tool** with no malicious behavior or exploitable vulnerabilities. While the extension requires broad permissions and collects search queries, this is **essential for its intended purpose** as a multi-platform keyword research assistant.

The extension:
- ✅ Operates transparently with clear functionality
- ✅ Uses authentication (users must create accounts)
- ✅ Communicates only with its own legitimate backend infrastructure
- ✅ Contains no ad injection, tracking scripts, or data broker SDKs
- ✅ Implements standard security practices (HTTPS, MV3, no eval)
- ✅ Provides value proposition (keyword research for Amazon KDP authors/sellers)

**Recommendation**: CLEAN - Approve for use. The extension is invasive by necessity (multi-platform keyword research) but serves its stated purpose without malicious behavior or key vulnerabilities. Users should be aware that search queries are sent to the vendor's backend as part of the service.
