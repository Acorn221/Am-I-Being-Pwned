# Vulnerability Analysis Report: Online Image Editor (img2go.com)

## Extension Metadata
- **Extension Name**: Online Image Editor (img2go.com)
- **Extension ID**: kpecfgjcmboghimfnkpcfijmoknhipdi
- **User Count**: ~50,000 users
- **Version**: 7.5.1
- **Manifest Version**: 3
- **Author**: https://img2go.com

## Executive Summary

The Online Image Editor extension is a **CLEAN** extension that provides legitimate image conversion and editing functionality by redirecting users to the img2go.com web service. The extension operates as a browser integration tool that facilitates file uploads to img2go's cloud-based conversion service. While it has broad permissions and injects content on multiple websites (Google, Gmail, Bing, and all other sites for PDF processing), all functionality serves the extension's stated purpose without evidence of malicious behavior.

The extension's architecture involves:
1. Content scripts that inject UI elements on Google/Gmail/Bing for quick access to conversion tools
2. A background service worker that handles file upload, conversion job management, and API communication
3. Communication with legitimate img2go.com and satcore.img2go.com API endpoints
4. Context menu integration for image/link/page conversion

## Overall Risk Assessment: **CLEAN**

## Vulnerability Analysis

### 1. Broad Host Permissions - MEDIUM Severity (Intended Functionality)

**Finding**: The extension requests host permissions for `http://*/*`, `https://*/*`, and `file://*/*`.

**Evidence**:
```json
"host_permissions": ["http://*/*", "https://*/*", "file://*/*"]
```

**Analysis**: These permissions allow the extension to access all websites and local files. However, this is justified by the extension's functionality:
- PDF content script runs on all sites to detect and process PDF files
- Context menu functionality for converting images/links/pages from any website
- User-initiated file uploads for conversion

**Verdict**: CLEAN - The broad permissions serve the extension's legitimate PDF processing and image conversion features. No evidence of unauthorized data collection.

---

### 2. XMLHttpRequest Hooking in Gmail - LOW Severity (Gmail Integration Feature)

**Finding**: The extension patches `XMLHttpRequest.prototype.open` and `XMLHttpRequest.prototype.send` on Gmail pages.

**Evidence** (gmail_injected.js):
```javascript
o.tools.patch(e.XMLHttpRequest.prototype.open, (t => {
  e.XMLHttpRequest.prototype.open = function(e, n, r, i, a) {
    // Custom handling
  }
}))
o.tools.patch(e.XMLHttpRequest.prototype.send, (n => {
  e.XMLHttpRequest.prototype.send = function(e) {
    // Custom handling
  }
}))
```

**Analysis**: This hooking is part of gmail.js library integration (evidenced by `_gmailjs` references) to detect compose windows and integrate file compression features. The patching monitors Gmail's internal API calls to provide attachment conversion functionality. This is a known pattern for Gmail extensions that enhance email composition.

**Verdict**: CLEAN - Standard Gmail integration pattern for providing email enhancement features. No evidence of data interception or exfiltration.

---

### 3. Content Script Injection Across All Sites - MEDIUM Severity (PDF Processing)

**Finding**: Content scripts are injected on all HTTP/HTTPS/file URLs (excluding Google, Gmail, Bing).

**Evidence** (manifest.json):
```json
{
  "matches": ["http://*/*", "https://*/*", "file://*/*"],
  "exclude_matches": ["https://www.google.com/*", "https://mail.google.com/*","https://www.bing.com/*"],
  "js": ["translate_content.js", "pdf_content.js", "pdf_injected.js"],
  "run_at": "document_idle"
}
```

**Analysis**: The content scripts are primarily for PDF detection and conversion functionality. The scripts:
- Detect PDF files being viewed
- Inject UI for PDF conversion/editing
- Upload selected PDFs to img2go.com for processing
- Do not scrape page content or intercept user data

**Verdict**: CLEAN - The injection serves legitimate PDF processing functionality with user-initiated actions.

---

### 4. API Communication with img2go.com Services - LOW Severity (Core Functionality)

**Finding**: The extension communicates with multiple img2go.com and satcore.img2go.com endpoints.

**Evidence** (background.js):
```javascript
baseApiUrl: "https://dragon.img2go.com/api"
satcoreUrl: "https://satcore.img2go.com/v2"
getBrowserExtensionIdUrl: "https://dragon.img2go.com/api/user/browserextensiontoken"
loginExtensionUrl: "https://satcore.img2go.com/v2/tokens/browserextension"
```

**API Endpoints Identified**:
- `https://dragon.img2go.com/api/jobs` - Job creation and management
- `https://dragon.img2go.com/api/jobs/{id}/input` - File upload
- `https://dragon.img2go.com/api/jobs/{id}/conversions` - Conversion configuration
- `https://satcore.img2go.com/v2/tokens/browserextension` - Authentication
- `https://satcore.img2go.com/v2/users/0/browserextension` - Rate limiting

**Data Transmitted**:
- Browser extension token (authentication)
- File content (base64 encoded) for conversion
- Conversion parameters (format, quality, dimensions)
- Job status polling

**Analysis**: All API communication is with official img2go.com domains operated by the extension publisher. The data transmission is necessary for the cloud-based conversion service. Files are uploaded only when users explicitly request conversion.

**Verdict**: CLEAN - Standard cloud service communication pattern. No unauthorized data exfiltration.

---

### 5. Chrome Storage Usage - LOW Severity (Configuration Storage)

**Finding**: The extension uses both `chrome.storage.sync` and `chrome.storage.local` for data persistence.

**Evidence**:
```javascript
chrome.storage.sync.set({
  browser_extension_id: t.browser_extension_id,
  token: t.token
})

chrome.storage.local.set(r) // Task data
```

**Data Stored**:
- Browser extension authentication tokens
- Job/task status data
- User preferences
- No sensitive user data or browsing history

**Verdict**: CLEAN - Standard configuration and state management.

---

### 6. Dynamic Code Patterns - FALSE POSITIVE

**Finding**: Use of `Function()` constructor and `setTimeout`.

**Evidence**:
```javascript
Function("r", "regeneratorRuntime = r")(t)
setTimeout(() => { ... })
```

**Analysis**: These are part of:
- Regenerator runtime polyfill (standard transpiled async/await code)
- jQuery library code
- Legitimate timing for polling job status and UI updates
- No eval() or dynamic code execution from remote sources

**Verdict**: FALSE POSITIVE - Standard library code and async polling mechanisms.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `Function("r", "regeneratorRuntime = r")` | Multiple files | Regenerator runtime polyfill for async/await support |
| `setTimeout` usage | Throughout | Legitimate polling for job status, UI delays, and async operations |
| `XMLHttpRequest` hooking | gmail_injected.js | gmail.js library integration for Gmail API monitoring |
| jQuery library code | gmail_injected_lib.js, popup_tools.js | Standard jQuery AJAX and DOM manipulation |
| Axios library | background.js | Standard HTTP client library |

## API Endpoints and Data Flow

### Outbound API Calls

| Endpoint | Purpose | Data Sent | Authentication |
|----------|---------|-----------|----------------|
| `https://dragon.img2go.com/api/user/browserextensiontoken` | Get extension token | None | None |
| `https://dragon.img2go.com/api/jobs` | Create conversion job | Operation type, options | Browser extension token |
| `https://dragon.img2go.com/api/jobs/{id}/input` | Upload file | Base64 encoded file | Token + job ID |
| `https://dragon.img2go.com/api/jobs/{id}` | Poll job status | None | Token + job ID |
| `https://dragon.img2go.com/api/jobs/{id}/conversions` | Add conversion | Target format, options | Token + job ID |
| `https://satcore.img2go.com/v2/tokens/browserextension` | Login | Browser extension ID | Extension token |
| `https://satcore.img2go.com/v2/users/0/browserextension` | Rate limiting check | None | Token |

### Data Flow Summary

1. **User Action**: User right-clicks image/link/page or uses PDF conversion feature
2. **File Upload**: Selected file is base64 encoded and uploaded to img2go.com API
3. **Job Processing**: Backend processes the conversion job
4. **Status Polling**: Extension polls job status every 500-1000ms
5. **Result Delivery**: Download URL is provided when job completes
6. **User Download**: User is directed to img2go.com to download converted file

**Privacy Note**: Files are processed on img2go.com servers. Users should be aware that uploaded files are transmitted to third-party servers for processing.

## Security Strengths

1. **Manifest V3 Compliance**: Uses modern service worker architecture
2. **Limited Scope**: Only collects data explicitly provided by users for conversion
3. **No Background Tracking**: No analytics, tracking pixels, or user behavior monitoring
4. **Proper CSP**: No unsafe-eval or unsafe-inline in default CSP
5. **Legitimate Domain Communication**: All API calls go to official img2go.com domains
6. **User-Initiated Actions**: All file uploads require explicit user action

## Recommendations

1. **Transparency**: Consider adding privacy policy disclosure about cloud file processing
2. **Permission Optimization**: Could potentially use activeTab instead of broad host permissions for context menu actions
3. **File Access Warning**: Ensure users are clearly informed that local file access is for PDF processing only

## Conclusion

The Online Image Editor extension is a **CLEAN** extension that provides legitimate file conversion functionality through integration with img2go.com's cloud service. While it has broad permissions and injects content on multiple websites, all functionality serves the extension's stated purpose without evidence of malicious behavior, data harvesting, or privacy violations. The extension operates transparently as a browser integration for a legitimate web service.

The invasive permissions (all hosts, file access) are justified by the extension's PDF processing and image conversion features, which require the ability to detect and process files from any source. No security vulnerabilities or malicious patterns were identified.

---

**Risk Level**: CLEAN
**Report Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
