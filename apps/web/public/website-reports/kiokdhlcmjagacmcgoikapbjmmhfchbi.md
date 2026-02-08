# Vulnerability Report: Web Clipper (Nimbus)

## Metadata
- **Extension Name**: Web Clipper (Nimbus)
- **Extension ID**: kiokdhlcmjagacmcgoikapbjmmhfchbi
- **Version**: 4.9.9.1
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Web Clipper (Nimbus) is a legitimate productivity extension by Nimbus Web (everhelper.me) that allows users to clip web content, articles, images, and emails to their Nimbus Note account. The extension demonstrates **CLEAN** security posture with standard web clipper functionality and appropriate API usage. No malicious behavior, data exfiltration, or suspicious patterns were detected.

The extension uses cookies permission for authenticated sync with the Nimbus backend, requires host permissions for content clipping functionality across all websites, and implements reasonable security practices including CSP with wasm-unsafe-eval (for legitimate WASM usage).

**Overall Risk Level**: **CLEAN**

## Vulnerability Analysis

### 1. Permissions Review - CLEAN ✓

**Requested Permissions**:
- `activeTab` - For accessing active tab content
- `tabs` - For tab management and clipping operations
- `contextMenus` - For right-click menu integration
- `cookies` - For authentication session management
- `storage` - For settings persistence
- `host_permissions: *://*/*` - Required for universal content clipping

**Verdict**: All permissions are justified for a web clipper. The cookies permission is legitimately used to retrieve the `eversessionid` cookie for authenticating with the Nimbus sync API (sync.everhelper.me). No evidence of cookie harvesting from other domains.

**Evidence**:
```javascript
// server.js:151-160 - Legitimate cookie usage for authentication
chrome.cookies.getAll({domain: self.domainCookies, name: "eversessionid"}, function(cooks){
    if (cooks.length>0) {
        if ( !_bd.headers ) _bd.headers = {};
        _bd.headers['EverHelper-Session-ID'] = cooks[0].value;
        _request(url, _bd);
    }
    else {
        callback( true, -6 );
    }
})
```

### 2. Content Security Policy - CLEAN ✓

**CSP**: `script-src 'self' 'wasm-unsafe-eval'`

**Verdict**: Appropriately restrictive CSP. The `wasm-unsafe-eval` directive is present in manifest but no WASM files were found in deobfuscated directory (manifest references `main.wasm` which may be for future functionality). No inline scripts or unsafe-eval detected.

### 3. Network Activity Analysis - CLEAN ✓

**Primary API Endpoints**:
- Production: `https://sync.everhelper.me` (sync API)
- Auth: `https://nimbusweb.me/auth/api/` (authentication)
- Test domains: `sync.nimbustestapi.co`, `sync.develop.nimbustest.com` (development environments)

**Verdict**: All network requests go to legitimate Nimbus/EverHelper domains. The extension uses `fetch()` API with proper error handling and authentication headers. No third-party analytics, tracking SDKs, or suspicious endpoints detected.

**Evidence**:
```javascript
// server.js:8-16 - Domain configuration by mode
if (gMode == "production") {
    this.apiUrl = 'https://sync.everhelper.me';
    this.domainCookies = 'nimbusweb.me';
}
this.authenticationUrl = 'https://nimbusweb.me/auth/api/';
```

### 4. Background Script Analysis - CLEAN ✓

**Background Service Worker**: `js/background.js`

**Functionality**:
- Tab state management and popup updates
- Context menu integration
- Message routing between content scripts and background
- Settings synchronization via `chrome.storage.local`
- Welcome page on first install (nimbusweb.me/welcome-to-clipper-chrome.php)

**Verdict**: Standard extension lifecycle management. No dynamic code execution, no eval(), no remote script loading. Clean message passing architecture.

### 5. Content Scripts Analysis - CLEAN ✓

**Content Scripts Loaded**: 50+ files including:
- Core functionality: nimbus.js, pageHelper.js, imageHelper.js
- HTML parsers: Readability.js, mercury.web.js, article parsers
- Site-specific modules: gmail.js, facebook.js, youtube.js, linkedin.js, amazon.js

**Functionality**:
- DOM parsing for article extraction (using Mozilla Readability and Mercury parsers)
- Image clipping and screenshot capture
- Fragment/region selection UI
- Site-specific content extraction for Gmail, YouTube, etc.

**Verdict**: Legitimate content clipping functionality. No keyloggers, no credential harvesting, no ad injection, no DOM manipulation for malicious purposes.

**Evidence**:
```javascript
// content_scripts/inject.js:2-8 - Minimal postMessage for accessing page globals
window.addEventListener("message", (event) => {
    const data = event.data;
    if (data.name == "get-nimbus-receive-globals") {
        window.postMessage({ name: "nimbus-receive-globals", globals: window.GLOBALS }, "*");
    }
}, false);
```

### 6. Data Collection Analysis - CLEAN ✓

**Data Stored**:
- User settings in `chrome.storage.local` (preferences, default actions)
- Authentication state (sessionId from backend)
- Clipped content (sent to sync.everhelper.me for cloud sync)

**Data Transmitted**:
- User credentials to authentication API (standard OAuth-like flow)
- Clipped articles/images/bookmarks to sync API
- User info requests (workspaces, folders, tags)

**Verdict**: No excessive data collection. All transmitted data is required for core functionality (web clipping and sync). User must authenticate to use the service. No PII harvesting from unrelated sites.

### 7. Obfuscation Analysis - CLEAN ✓

**Code Quality**: Well-structured, readable code with Russian comments. Uses standard libraries (jQuery 3.3.1, jQuery UI, async.js). No minification beyond external libraries, no string obfuscation, no anti-debugging measures.

**Verdict**: Transparent codebase suitable for security review.

### 8. Third-Party SDK Analysis - CLEAN ✓

**External Libraries**:
- jquery-3.3.1.min.js (125KB)
- jquery-ui.min.js (81KB)
- async.js (34KB)
- jquery.hotkeys.js (4.9KB)

**Verdict**: No tracking SDKs detected. No Sensor Tower, Pathmatics, Amplitude, Mixpanel, or market intelligence frameworks found.

### 9. Extension Interaction Analysis - CLEAN ✓

**Extension Enumeration**: No evidence of enumerating installed extensions or attempting to disable competitors.

**XHR/Fetch Hooking**: No hooks or interception of other extensions' network requests.

### 10. Remote Code Execution Risk - CLEAN ✓

**Dynamic Code Patterns**: No `eval()`, `Function()`, `new Function()`, or `innerHTML` with unsanitized user input detected across the codebase.

**Script Injection**: No `chrome.scripting.executeScript` or dynamic script loading from remote sources.

**Verdict**: No RCE vectors identified.

## False Positive Analysis

| Pattern | Location | Reason for Exclusion |
|---------|----------|---------------------|
| `postMessage` in inject.js | js/content_scripts/inject.js:7 | Legitimate page context communication for accessing `window.GLOBALS` - minimal exposure |
| `everhelper.js` postMessage bridge | js/content_scripts/everhelper.js:6-28 | Web-to-extension communication bridge for everhelper.me domain - scoped to specific domain |
| Cookie access | js/server.js:151 | Authentication session cookie retrieval - restricted to Nimbus domains only |
| Host permissions `*://*/*` | manifest.json:17 | Required for universal web clipping functionality |

## API Endpoints Summary

| Endpoint | Purpose | Method | Authentication |
|----------|---------|--------|----------------|
| `https://sync.everhelper.me` | Sync API (clippings, folders, workspaces) | POST | EverHelper-Session-ID header |
| `https://nimbusweb.me/auth/api/auth` | User login | POST | Credentials in body |
| `https://nimbusweb.me/auth/api/register` | User registration | POST | Email/password in body |
| `https://nimbusweb.me/auth/api/challenge` | 2FA/CAPTCHA challenge | POST | OTP/CAPTCHA code |
| `{apiUrl}/files:preupload` | File attachment upload | POST | Session ID header |
| `{apiUrl}/clippings:save` | Save clipped content | POST | Session ID header |
| `{apiUrl}/notes:getFolders` | Fetch user folders | POST | Session ID header |
| `{apiUrl}/notes:getTags` | Fetch user tags | POST | Session ID header |
| `{apiUrl}/orgs:getAll` | Get organizations | POST | Session ID header |

## Data Flow Summary

1. **User Authentication**:
   - User enters credentials in `auth_popup.html`
   - Credentials sent to `https://nimbusweb.me/auth/api/auth` via `server.login()`
   - Backend returns `sessionId`, stored in `chrome.storage.local` as `auth` object
   - Session cookie `eversessionid` stored in browser cookies for `nimbusweb.me` domain

2. **Content Clipping**:
   - User triggers clip action (fragment, full page, article, image)
   - Content script parses DOM using appropriate parser (Readability, Mercury, etc.)
   - Parsed HTML/images converted to data URLs or uploaded via `preUploadFile()`
   - Clipping data sent to `{apiUrl}/clippings:save` with authentication header
   - Backend syncs to user's Nimbus Note account

3. **Settings Storage**:
   - User preferences stored in `chrome.storage.local` (no sensitive data)
   - Settings synced between popup, options, and content scripts via message passing

## Security Strengths

1. **Authentication**: Secure credential flow with 2FA support (OTP, CAPTCHA)
2. **CSP**: Restrictive content security policy preventing inline scripts
3. **No Tracking**: Zero third-party analytics or market intelligence SDKs
4. **Code Transparency**: Readable, well-documented code with clear intent
5. **Scoped Permissions**: Cookie access limited to Nimbus domains only
6. **Standard Libraries**: Uses well-known, unmodified jQuery and async libraries

## Potential Privacy Concerns (Non-Malicious)

1. **Broad Host Permissions**: Required for clipping any website, but inherent to web clipper functionality
2. **Content Upload**: All clipped content sent to Nimbus cloud - users should trust Nimbus privacy policy
3. **Welcome Page**: Opens marketing page on first install (common practice, not malicious)

## Recommendations

None. Extension follows Chrome best practices for web clippers.

## Conclusion

Web Clipper (Nimbus) is a **CLEAN** extension with legitimate productivity functionality. It demonstrates proper security hygiene, transparent data handling, and appropriate permission usage for its stated purpose. No evidence of malicious behavior, data theft, or hidden functionality.

The extension is safe for general use, assuming users trust Nimbus Web Inc. with their clipped content (standard cloud service trust model).

---

**Risk Level**: **CLEAN**
**Analyst Verdict**: No security concerns identified. Approved for use.
