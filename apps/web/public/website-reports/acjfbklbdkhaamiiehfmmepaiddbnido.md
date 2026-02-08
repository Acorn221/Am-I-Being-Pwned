# Security Analysis Report: Mathpix Snip

## Metadata
- **Extension Name**: Mathpix Snip
- **Extension ID**: acjfbklbdkhaamiiehfmmepaiddbnido
- **Version**: 1.0.6
- **User Count**: ~60,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

Mathpix Snip is a PDF conversion extension that provides legitimate functionality for converting PDFs to LaTeX, DOCX, and Markdown formats. The extension demonstrates **reasonable security practices** with a clean React-based architecture. The primary concerns are the broad `<all_urls>` host permission and the cookies permission combined with first-party authentication cookie storage. The codebase consists primarily of PDF.js library code with minimal custom business logic.

**Overall Risk Level: LOW**

The extension shows no evidence of malicious behavior, obfuscation, or suspicious third-party integrations. All network communications are directed to legitimate Mathpix API endpoints.

## Vulnerability Details

### 1. Broad Host Permissions
**Severity**: MEDIUM
**Files**: `manifest.json`
**Code**:
```json
"host_permissions": ["<all_urls>"]
```

**Analysis**: The extension requests access to all URLs, which is overly broad for an extension focused on PDF processing. This permission enables the background script to fetch PDF content from any URL to determine if the current page contains a PDF.

**Verdict**: **FUNCTIONAL REQUIREMENT** - The extension uses this permission to fetch URLs and check if they are PDFs by inspecting the response content-type. This is a legitimate use case for the extension's core functionality (detecting PDFs in the active tab).

**Code Context** (`background/background.js` lines 12-31):
```javascript
fetch(tab.url)
  .then(response => {
    if (response.ok) {
      return response.blob();
    }
    throw new Error('Failed to read file contents.');
  })
  .then(blob => {
    if (blob.type === 'application/pdf') {
      console.log('This url is a PDF file.');
      chrome?.action?.setIcon({ path: "../logoActive.png" });
    } else {
      console.log('This url is not a PDF file.');
      chrome?.action?.setIcon({ path: "../logoIn.png" });
    }
  })
```

### 2. Cookie Access and First-Party Storage
**Severity**: LOW
**Files**: `manifest.json`, `static/js/main.730aefe9.js`
**Code**:
```json
"permissions": ["tabs", "cookies"]
```

**Analysis**: The extension uses the cookies permission to store authentication tokens in first-party cookies for the domain `snip.mathpix.com`.

**Verdict**: **ACCEPTABLE** - Cookie storage is used exclusively for maintaining user session state with the Mathpix service. No evidence of third-party cookie harvesting or cross-site tracking.

**Code Context** (`static/js/main.730aefe9.js` lines 60502-60514):
```javascript
chrome.cookies.set({
  name: "token",
  url: "http://snip.mathpix.com",
  value: "".concat(e)
}),
chrome.cookies.set({
  name: "email",
  url: "http://snip.mathpix.com",
  value: "".concat(t)
}),
chrome.cookies.set({
  name: "mfa_method",
  url: "http://snip.mathpix.com",
  value: "".concat(r)
})
```

### 3. PDF.js Dynamic Code Generation
**Severity**: LOW
**Files**: `static/js/main.730aefe9.js`
**Code**:
```javascript
// Line 2517
return new Function(""), !0

// Line 3808
return worker = eval("require")(_this14.workerSrc), _context4.abrupt("return", worker.WorkerMessageHandler);

// Line 5350
return this.compiledGlyphs[t] = new Function("c", "size", i.join(""))
```

**Analysis**: The main.js bundle contains PDF.js library code that uses `new Function()` and `eval()` for dynamic code generation. These patterns are part of the PDF.js rendering engine.

**Verdict**: **FALSE POSITIVE** - This is standard PDF.js library code used for font glyph compilation and worker initialization. The extension's CSP (`script-src 'self'; object-src 'self'`) prevents arbitrary code execution from external sources.

### 4. React innerHTML Usage
**Severity**: LOW
**Files**: `static/js/main.730aefe9.js`
**Code**:
```javascript
// Line 53214
if ("http://www.w3.org/2000/svg" !== e.namespaceURI || "innerHTML" in e) e.innerHTML = t;
// Line 53216
(ce = ce || document.createElement("div")).innerHTML = "<svg>" + t.valueOf().toString() + "</svg>"
```

**Analysis**: Standard React SVG rendering patterns using innerHTML for SVG namespace handling.

**Verdict**: **FALSE POSITIVE** - React SVG rendering for icon/graphic elements. No user-controlled input flows to these innerHTML assignments.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function()` | main.730aefe9.js:2517, 5350, 14145 | PDF.js glyph compiler and feature detection |
| `eval("require")` | main.730aefe9.js:3808 | PDF.js worker loader in Node.js environment detection |
| `innerHTML` | main.730aefe9.js:53214, 53216 | React SVG namespace rendering |
| `postMessage` | main.730aefe9.js (multiple) | PDF.js web worker communication channel |
| `XMLHttpRequest` | main.730aefe9.js:741, 4648 | PDF.js fetch polyfill and Axios HTTP library |
| `fetch` usage | background/background.js:12-31 | PDF content-type detection for icon updates |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent | Auth |
|----------|--------|---------|-----------|------|
| `https://snip-api.mathpix.com/v1/user/login` | POST | User authentication | `{email, password}` | None |
| `https://snip-api.mathpix.com/v1/user/logout` | POST | User logout | `{}` | Bearer token |
| `https://snip-api.mathpix.com/v1/user` | GET | Fetch user profile | None | Bearer token |
| `https://snip-api.mathpix.com/v1/user/resend_mfa_code` | POST | Resend MFA code | None | Bearer token |
| `https://snip-api.mathpix.com/v1/pdfs` | GET | List user PDFs | Query params (pagination) | Bearer token |
| `https://snip-api.mathpix.com/v1/pdfs` | POST | Upload PDF for conversion | FormData (PDF file + metadata) | Bearer token |
| `https://accounts.mathpix.com/upgrade` | N/A | External link (account upgrade) | None | None |
| `https://accounts.mathpix.com/forgot-password` | N/A | External link (password reset) | None | None |
| `https://accounts.mathpix.com/signup` | N/A | External link (registration) | None | None |

## Data Flow Summary

### Authentication Flow
1. User enters email/password in popup UI
2. Credentials sent to `snip-api.mathpix.com/v1/user/login` via POST
3. On success, JWT token received and stored in chrome.cookies (`snip.mathpix.com` domain)
4. 2FA flow supported (authenticator app, email, backup codes)
5. Token used for subsequent API requests via `Authorization: Bearer` header

### PDF Processing Flow
1. Background script monitors active tab URL changes (`chrome.tabs.onActivated`, `chrome.tabs.onUpdated`)
2. When URL changes, background script fetches the URL to check Content-Type
3. If `application/pdf` detected, extension icon changes to "active" state
4. User clicks extension popup, which checks for PDF availability
5. User can upload PDF to Mathpix API for conversion
6. PDF sent to `snip-api.mathpix.com/v1/pdfs` as multipart FormData
7. Conversion results retrieved from API

### Data Storage
- **chrome.cookies**: Stores `token`, `email`, `mfa_method` for domain `snip.mathpix.com`
- **localStorage**: Stores `remainingTime` for MFA timeout countdown
- No evidence of IndexedDB, chrome.storage.local, or other persistent storage mechanisms

### Network Communication
- **First-party only**: All API calls to `*.mathpix.com` domains
- **No third-party SDKs**: No analytics, error tracking, or ad networks detected
- **No remote config**: No dynamic code loading from external sources

## Security Strengths

1. **Manifest V3**: Uses service workers instead of background pages
2. **Strict CSP**: `script-src 'self'; object-src 'self'` prevents inline scripts and external code execution
3. **HTTPS-only API**: All API endpoints use HTTPS
4. **Bearer token auth**: Modern token-based authentication instead of session cookies
5. **MFA support**: Optional two-factor authentication (TOTP, email, backup codes)
6. **No content scripts**: Extension does not inject JavaScript into web pages
7. **Verified code signature**: Chrome Web Store verified_contents.json present and valid
8. **No obfuscation**: React bundle is minified but not maliciously obfuscated

## Potential Privacy Concerns

1. **URL fetching**: Background script fetches arbitrary URLs to detect PDFs. This could theoretically leak browsing history to network observers if users visit HTTP (non-HTTPS) URLs, though most PDF hosting is HTTPS.
2. **Tab monitoring**: Extension monitors all tab changes to detect PDF navigation. This is required for core functionality but means the extension is aware of all URL changes.

## Recommendations

1. **Scope host_permissions**: Consider requesting only `<all_urls>` for specific URL patterns (e.g., `*.pdf`, `*//*.pdf`) if Chrome API supports pattern-based PDF detection, or use declarativeNetRequest to detect PDF content-types without full fetch permission.
2. **Use chrome.storage instead of cookies**: Migrate from chrome.cookies to chrome.storage.local for token storage to reduce cookie permission scope.
3. **Add SRI for PDF.js**: If PDF.js is loaded from external CDN (not detected in this analysis), add Subresource Integrity hashes.

## Overall Risk Assessment

**Risk Level: LOW**

**Justification**:
- No malicious code patterns detected
- No suspicious third-party integrations
- No data exfiltration beyond legitimate API usage
- No obfuscation or anti-analysis techniques
- Permissions are justified by functionality (though could be more restricted)
- Code quality is professional (React + TypeScript toolchain)
- Published by legitimate company (Mathpix, Inc.)

**Verdict: CLEAN**

The extension provides legitimate PDF conversion functionality with appropriate security controls. The broad permissions are concerning from a least-privilege perspective but are functionally justified and not abused for malicious purposes.
