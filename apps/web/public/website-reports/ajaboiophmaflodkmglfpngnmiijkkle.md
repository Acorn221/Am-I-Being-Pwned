# ZetaMarker - PDF & Web Highlighter Security Analysis

## Metadata
- **Extension ID**: ajaboiophmaflodkmglfpngnmiijkkle
- **Extension Name**: ZetaMarker - PDF & Web Highlighter
- **User Count**: ~20,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

ZetaMarker is a web and PDF highlighting tool with cloud synchronization capabilities. The extension demonstrates **clean security practices** with legitimate functionality and no evidence of malicious behavior. All network communications are limited to the extension's documented API endpoints for sync functionality. The extension uses standard permissions appropriately for its stated purpose and does not engage in data exfiltration, ad injection, or other malicious activities.

**Overall Risk Level: CLEAN**

## Vulnerability Details

### 1. Google OAuth Token Handling
**Severity**: LOW
**Files**: `w.js` (lines 445-469)
**Code**:
```javascript
async function r(y, z) {
  const A = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  A['searchParams']['set']('client_id', '1035564230748-65hg3o499bf89rp6rbghtvdtug1fbvgh.apps.googleusercontent.com'),
  // ... OAuth flow
  const D = C['get']('id_token')['split']('.')[1],
  const E = D['replace']('-', '+')['replace']('_', '/'),
  const { email: F, name: G } = JSON['parse'](atob(E));
  s(F, G, y, z, 'Google');
}
```
**Description**: The extension uses `atob()` to decode JWT tokens from Google OAuth. While the token replacement logic has a minor bug (should use `replaceAll` or regex with `g` flag instead of single `replace`), this is a benign implementation detail that doesn't pose security risks.
**Verdict**: **FALSE POSITIVE** - Standard OAuth implementation pattern. The bug doesn't create vulnerabilities, just potential decoding issues in edge cases.

### 2. External Extension Communication
**Severity**: LOW
**Files**: `manifest.json` (line 1), `w.js` (lines 4-18), `c-r.js` (line 843)
**Code**:
```javascript
// manifest.json
"externally_connectable":{"ids":["efmpofoemibeochefpdgajaaoliaehji"]}

// w.js
chrome['runtime']['onMessageExternal']['addListener']((y, z, A) => {
  if (z['id'] !== 'efmpofoemibeochefpdgajaaoliaehji') return;
  switch (y['m']) {
    case 'i-u':
      chrome['storage']['local']['get'](null, B => {
        const C = [];
        for (const D in B) {
          D !== 'auth' && D !== 'cursorColor' && D !== 'smodal' && D !== 'toolbar' && D !== 'theme' && D !== 'ff' && C['push'](D);
        }
        A({ 'pus': C });
      });
      return;
  }
});
```
**Description**: The extension allows external communication from extension ID `efmpofoemibeochefpdgajaaoliaehji` (appears to be a "ZetaMarker Notifier" companion extension). The exposed functionality only returns a list of page URLs stored locally (excluding sensitive data like auth tokens). This is used for notification purposes.
**Verdict**: **CLEAN** - Properly restricted to a single whitelisted extension ID with minimal data exposure. No sensitive data (auth tokens, passwords) is shared externally.

### 3. File Protocol Access
**Severity**: LOW
**Files**: `manifest.json` (line 1)
**Code**:
```json
"host_permissions":["file:///*"]
```
**Description**: Extension requests `file:///*` permission to enable PDF highlighting on local files.
**Verdict**: **CLEAN** - Required for legitimate PDF viewer functionality. The extension includes a built-in PDF viewer (`viewer/` directory) that needs to access local PDF files.

### 4. Identity Permission for OAuth
**Severity**: LOW
**Files**: `manifest.json`, `w.js` (lines 445-469)
**Code**:
```json
"permissions":["storage","activeTab","scripting","identity"]
```
**Description**: The `identity` permission is used for Google OAuth login flow via `chrome.identity.launchWebAuthFlow()`.
**Verdict**: **CLEAN** - Standard use of identity permission for authentication. No abuse detected.

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `atob()` / `btoa()` | `w.js:424, 459` | Legitimate base64 encoding for PDF data transfer and JWT token decoding in OAuth flow |
| `innerHTML` | Multiple locations | Used for creating UI elements with static, extension-controlled content. No user input injection risks |
| `fetch()` | `w.js:402, 518, 531` | All fetch calls target legitimate ZetaMarker API endpoints only |
| jQuery library | `jq.js` | Standard jQuery v3.6.0 library for DOM manipulation |
| PDF.js library | `viewer/build/*` | Standard Mozilla PDF.js library for PDF rendering |
| External messaging | `w.js:4-18` | Properly restricted to whitelisted companion extension with minimal data exposure |

## API Endpoints

| Endpoint | Purpose | Authentication |
|----------|---------|----------------|
| `https://zetamarker-api.herokuapp.com/auth/login` | User login | Email/password |
| `https://zetamarker-api.herokuapp.com/auth/google-auth` | Google OAuth login | Google ID token |
| `https://zetamarker-api.herokuapp.com/auth/pages` | Fetch user's saved pages | Bearer token |
| `https://zetamarker-api.herokuapp.com/annotation/sync` | Sync highlights to cloud | Bearer token |
| `https://zetamarker-api.herokuapp.com/annotation/page-highlights-new` | Create new page highlights | Bearer token |
| `https://zetamarker-api.herokuapp.com/annotation/page-highlights/{id}` | Fetch highlights by page ID | Bearer token |
| `https://zetamarker-api.herokuapp.com/annotation/update-url` | Update page URL | Bearer token |
| `https://zetamarker-api.herokuapp.com/bug-report` | Submit bug reports | Bearer token |
| `https://www.zetamarker.com/*` | Marketing/documentation pages | None |
| `https://app.zetamarker.com/*` | Web app pages (signup, feedback, etc.) | Token via URL param |
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth flow | OAuth client ID |

## Data Flow Summary

### User Data Collected
- **Authentication**: Email, password (for ZetaMarker accounts), or Google email/name (for Google login)
- **Highlights**: Text selections, colors, comments, page URLs, page titles
- **Settings**: Theme preference, toolbar style, cursor color

### Data Storage
- **Local Storage (chrome.storage.local)**: All highlight data, authentication token, user preferences
- **Cloud Storage**: Highlights synced to ZetaMarker API (optional, user-initiated)

### Data Transmission
- **Authentication tokens**: Stored locally and sent as Bearer token in API requests
- **Highlight data**: Sent to ZetaMarker API only when user triggers sync
- **Bug reports**: User-submitted feedback sent to API endpoint
- **No third-party analytics**: No evidence of Google Analytics, tracking pixels, or third-party data sharing

### Privacy Assessment
The extension properly implements its stated functionality:
1. Highlights are stored locally by default
2. Cloud sync is optional and user-controlled
3. Authentication uses standard OAuth patterns
4. No data is sent to unexpected third parties
5. File:// access is required and limited to PDF viewing

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification
ZetaMarker is a legitimate highlighting and annotation tool that:
- ✅ Uses permissions appropriately for its stated purpose
- ✅ Implements secure authentication (OAuth + token-based)
- ✅ Stores data locally with optional cloud sync
- ✅ Makes network requests only to documented API endpoints
- ✅ Does not inject ads, tracking scripts, or malicious content
- ✅ Does not harvest cookies, passwords, or sensitive page data
- ✅ Does not implement keyloggers, clipboard hijacking, or data exfiltration
- ✅ Properly validates external extension communication
- ✅ Uses standard libraries (jQuery, PDF.js) without modification

### Invasiveness Assessment
While the extension requests powerful permissions (`scripting`, `activeTab`, `file:///*`), these are **necessary and properly used** for the highlighting functionality:
- Content scripts inject highlighting UI and capture text selections
- File access enables local PDF highlighting
- No evidence of abuse or scope creep beyond stated functionality

### Recommendation
**CLEAN** - Extension demonstrates good security practices and legitimate functionality. Safe for users who want web/PDF highlighting with cloud sync.
