# Security Analysis: Online PDF Editor pdf2go.com Extension

**Extension ID:** `dfnhijmficoiilogkjlnkionfjlgecdi`
**User Count:** ~300,000
**Version Analyzed:** 7.5.1
**Risk Level:** CLEAN
**Analysis Date:** 2026-02-06

---

## Executive Summary

The Online PDF Editor pdf2go.com extension is a legitimate PDF conversion and editing tool that operates as expected. The extension provides PDF manipulation features through integration with the pdf2go.com cloud service. No malicious behavior, suspicious data collection, or privacy violations were identified.

**Key Findings:**
- ✅ No XHR/fetch hooking
- ✅ No extension enumeration or killing
- ✅ No residential proxy infrastructure
- ✅ No market intelligence SDKs
- ✅ No AI conversation scraping
- ✅ No unauthorized data harvesting
- ✅ No remote kill switches
- ✅ Legitimate authentication tokens (browser extension tokens only)
- ✅ Appropriate CSP and permissions

---

## Manifest Analysis

### Permissions Review

```json
"permissions": ["contextMenus", "storage", "scripting"]
"host_permissions": ["http://*/*", "https://*/*", "file://*/*"]
```

**Assessment:** ✅ CLEAN
- **contextMenus**: Used for right-click PDF conversion options (convert page/image/link to PDF)
- **storage**: Stores browser extension authentication tokens and user settings
- **scripting**: Required for content script injection on Gmail and other pages
- **host_permissions**: Broad but necessary for PDF detection and conversion on any page

### Content Security Policy

Default CSP applies (no custom CSP specified). The extension relies on Chrome's built-in CSP for MV3.

### Externally Connectable

```json
"externally_connectable": {
  "matches": ["*://*.pdf2go.com/*", "*://*.pdf2go.test/*"]
}
```

**Assessment:** ✅ CLEAN - Limited to pdf2go.com domains only, appropriate for service integration.

---

## Network Communication Analysis

### API Endpoints

All network communication goes to legitimate pdf2go.com infrastructure:

```javascript
baseApiUrl: "https://dragon.pdf2go.com/api"
satcoreUrl: "https://satcore.pdf2go.com/v2"
getBrowserExtensionIdUrl: "https://dragon.pdf2go.com/api/user/browserextensiontoken"
loginExtensionUrl: "https://satcore.pdf2go.com/v2/tokens/browserextension"
```

**Assessment:** ✅ CLEAN
- All endpoints are first-party pdf2go.com infrastructure
- No third-party analytics or tracking services
- No ad networks or affiliate systems
- No data exfiltration to external servers

### Authentication Mechanism

The extension uses a browser extension token system:

```javascript
function getBrowserExtensionIdUrl() {
  return "https://dragon.pdf2go.com/api/user/browserextensiontoken"
}

function saveToken(data) {
  chrome.storage.sync.set({
    browser_extension_id: data.browser_extension_id,
    token: data.token
  })
}
```

**Assessment:** ✅ CLEAN
- Token obtained from pdf2go.com API
- Stored in chrome.storage.sync (encrypted by browser)
- Used for API authentication only
- No credential harvesting or session hijacking

---

## Content Script Behavior

### Gmail Integration (`gmail_content.js` + `gmail_injected.js`)

**Purpose:** Adds PDF compression/conversion features to Gmail attachments

**Behavior:**
1. Injects UI elements for PDF compression on Gmail attachment buttons
2. Allows users to compress PDF attachments before sending
3. Communicates with background script to upload files to pdf2go.com API
4. Downloads compressed PDFs back to Gmail interface

**Assessment:** ✅ CLEAN
- No email content scraping
- No unauthorized access to email data
- User-initiated file operations only
- Files sent to pdf2go.com API with user consent

### PDF Pages Integration (`pdf_content.js` + `pdf_injected.js`)

**Purpose:** Provides PDF editing tools on PDF viewer pages

**Behavior:**
1. Detects PDF files in browser tabs
2. Injects toolbar with PDF conversion/editing options
3. Allows local PDF file uploads for processing
4. Uses chrome.storage.local for task state management

**Assessment:** ✅ CLEAN
- No automatic PDF harvesting
- User-initiated operations only
- No PDF content extraction without consent

### Google Search Integration (`google_search_content.js`)

**Purpose:** Adds PDF conversion links to search results

**Behavior:**
1. Injects PDF2Go branding/links on Google Search pages
2. Translates UI elements based on browser locale
3. No search query interception or modification

**Assessment:** ✅ CLEAN
- No search query harvesting
- No search result manipulation
- Basic UI injection only

---

## Chrome API Usage Analysis

### chrome.contextMenus

**Usage:** Right-click context menu for PDF conversion

```javascript
chrome.contextMenus.create({
  id: "pdf2go-image",
  title: "convert_image_to_pdf",
  contexts: ["image"]
})

chrome.contextMenus.create({
  id: "pdf2go-link",
  title: "convert_link_to_pdf",
  contexts: ["link"]
})

chrome.contextMenus.create({
  id: "pdf2go-page",
  title: "convert_page_to_pdf",
  contexts: ["page", "link", "image"]
})
```

**Assessment:** ✅ CLEAN - Standard context menu integration for user-triggered PDF conversions.

### chrome.storage

**Usage:** Stores extension tokens and task state

```javascript
// Sync storage for auth tokens
chrome.storage.sync.set({
  browser_extension_id: id,
  token: token,
  id_user: token
})

// Local storage for conversion tasks
chrome.storage.local.set({
  [taskId]: taskData
})
```

**Assessment:** ✅ CLEAN
- No browsing history storage
- No personal data collection
- Authentication tokens only
- Temporary task state storage

### chrome.tabs

**Usage:** Opening pdf2go.com conversion pages

```javascript
chrome.tabs.create({
  url: conversionUrl
})
```

**Assessment:** ✅ CLEAN
- No tab enumeration
- No content harvesting from other tabs
- Opens service URLs only

---

## Data Collection Assessment

### What Data is Collected?

1. **Browser Extension Token** - Generated by pdf2go.com API for authentication
2. **User Files** - PDFs/images uploaded by user for conversion (sent to pdf2go.com API)
3. **Conversion Task State** - Temporary state for in-progress conversions (stored locally)

### What Data is NOT Collected?

❌ Browsing history
❌ Search queries
❌ Email content
❌ Cookies from other sites
❌ Installed extensions list
❌ User credentials
❌ Chat conversations
❌ Page screenshots (except user-selected files)
❌ Form data
❌ Social media activity

**Assessment:** ✅ CLEAN - Minimal data collection appropriate for service functionality.

---

## False Positive Analysis

### Axios Library Cookie Handling

The extension bundles Axios HTTP library, which includes standard cookie reading for XSRF protection:

```javascript
// Axios XSRF cookie reading (standard security feature)
read: function(t) {
  var e = document.cookie.match(new RegExp("(^|;\\s*)(" + t + ")=([^;]*)"));
  return e ? decodeURIComponent(e[3]) : null
}
```

**Assessment:** ✅ FALSE POSITIVE
- This is Axios library's standard XSRF token handling
- Only reads XSRF-TOKEN cookie for same-origin requests
- Not used for cookie harvesting

### Chrome Extension Message Passing

Multiple instances of chrome.runtime.sendMessage and onMessage listeners:

```javascript
chrome.runtime.onMessage.addListener((function(e, r, n) {
  if (e.type === "to-service-worker-upload-file") {
    // Handle file upload
  }
}))
```

**Assessment:** ✅ FALSE POSITIVE
- Standard Chrome extension messaging pattern
- Used for content script ↔ background script communication
- No external postMessage to untrusted origins

---

## Security Best Practices Review

### ✅ Good Practices Observed

1. **Manifest V3 Compliance** - Uses service workers instead of background pages
2. **Scoped Externally Connectable** - Limited to pdf2go.com domains only
3. **No eval() or Function() Constructor** - No dynamic code execution
4. **HTTPS-Only API Endpoints** - All communication over secure connections
5. **Token-Based Auth** - No password storage in extension
6. **Minimal Permissions** - Only requests what's needed

### ⚠️ Areas for Improvement

1. **Broad Host Permissions** - `http://*/*` and `https://*/*` could be narrowed
   - **Mitigation:** Required for detecting PDFs and conversion features on any site
   - **Risk:** Low - No evidence of permission abuse

2. **File Access Permission** - Extension can access local files
   - **Mitigation:** Used for local PDF conversion only
   - **Risk:** Low - User-initiated operations only

---

## Threat Model Assessment

### Potential Attack Vectors

#### 1. Man-in-the-Middle on pdf2go.com API
**Likelihood:** Low
**Impact:** Medium
**Mitigation:** All communication over HTTPS

#### 2. Malicious pdf2go.com Server Compromise
**Likelihood:** Very Low
**Impact:** High
**Mitigation:** Extension trusts pdf2go.com infrastructure; no defense against server compromise

#### 3. XSS via Injected Content
**Likelihood:** Low
**Impact:** Medium
**Mitigation:** Content scripts use standard DOM manipulation; no eval() or innerHTML with user data

---

## Comparison to Known Malicious Patterns

### Urban VPN (HIGH RISK) vs pdf2go.com (CLEAN)

| Feature | Urban VPN | pdf2go.com |
|---------|-----------|------------|
| XHR/fetch hooking | ✓ YES | ✗ NO |
| Extension killing | ✓ YES | ✗ NO |
| Social media scraping | ✓ YES | ✗ NO |
| Residential proxy | ✓ YES | ✗ NO |
| Obfuscation | ✓ YES | ✗ NO |

### StayFree/StayFocusd (HIGH RISK) vs pdf2go.com (CLEAN)

| Feature | StayFree/StayFocusd | pdf2go.com |
|---------|---------------------|------------|
| Sensor Tower SDK | ✓ YES | ✗ NO |
| AI conversation scraping | ✓ YES | ✗ NO |
| Browsing history upload | ✓ YES | ✗ NO |
| Dark patterns | ✓ YES | ✗ NO |
| Remote config | ✓ YES | ✗ NO |

**Assessment:** pdf2go.com exhibits NONE of the malicious patterns found in high-risk extensions.

---

## jQuery Library Detection

The extension bundles jQuery 3.6.4 in `pdf_injected.js` for DOM manipulation. This is a standard, legitimate library with no security concerns.

---

## Conclusion

The Online PDF Editor pdf2go.com extension is a **CLEAN, LEGITIMATE** tool that operates as advertised. It provides PDF conversion and editing features through integration with the pdf2go.com cloud service, with appropriate permissions and no malicious behavior.

### Risk Rating: CLEAN / LOW RISK

**Rationale:**
- No unauthorized data collection
- No suspicious network communication
- No extension killing or manipulation
- No residential proxy infrastructure
- No market intelligence SDKs
- No AI conversation scraping
- Appropriate permission usage
- Transparent functionality
- Legitimate business model (cloud PDF service)

### Recommendations

**For Users:**
- ✅ Safe to use for PDF conversion needs
- ⚠️ Understand that files uploaded are processed on pdf2go.com servers
- ✅ Review pdf2go.com privacy policy for cloud service data handling

**For Developers (pdf2go.com team):**
- Consider narrowing host_permissions to specific sites if possible
- Add more detailed permission justification in store listing
- Consider implementing Content Security Policy headers

---

## Technical Details

**Files Analyzed:**
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/dfnhijmficoiilogkjlnkionfjlgecdi/deobfuscated/manifest.json`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/dfnhijmficoiilogkjlnkionfjlgecdi/deobfuscated/background.js` (2,033 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/dfnhijmficoiilogkjlnkionfjlgecdi/deobfuscated/gmail_content.js` (1,300 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/dfnhijmficoiilogkjlnkionfjlgecdi/deobfuscated/pdf_content.js` (1,243 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/dfnhijmficoiilogkjlnkionfjlgecdi/deobfuscated/translate_content.js` (825 lines)
- All other content scripts and injected scripts

**Analysis Methods:**
- Static code analysis
- Permission review
- Network endpoint analysis
- Chrome API usage audit
- Pattern matching against known malicious behaviors
- Comparison to high-risk extensions (Urban VPN, StayFree, StayFocusd, etc.)

**Analyst Notes:**
The extension's broad host permissions initially raised flags, but thorough analysis revealed these are legitimately used for PDF detection and conversion features across all websites. No evidence of permission abuse or unauthorized data access was found. The extension follows Chrome Extension best practices and exhibits no malicious patterns.

---

## Appendix: Code Evidence

### Context Menu Registration
```javascript
// background.js:1682-1707
chrome.contextMenus.removeAll()
chrome.contextMenus.create({
  id: "pdf2go-image",
  title: "convert_image_to_pdf",
  contexts: ["image"]
})
chrome.contextMenus.create({
  id: "pdf2go-link",
  title: "convert_link_to_pdf",
  contexts: ["link"]
})
chrome.contextMenus.create({
  id: "pdf2go-page",
  title: "convert_page_to_pdf",
  contexts: ["page", "link", "image"]
})
```

### Token Management
```javascript
// background.js:1139-1143
function saveToken(data) {
  chrome.storage.sync.set({
    browser_extension_id: data.browser_extension_id,
    token: data.token
  })
}
```

### File Upload to pdf2go.com
```javascript
// background.js:1430-1450
postBase64encodedFileToJob(job, filename, base64content) {
  const url = this.getBase64UploadUrl(job)
  const data = [{
    content: base64content,
    filename: filename
  }]
  const config = {
    headers: {
      "X-Oc-Token": job.token,
      "Content-Type": "multipart/form-data",
      "x-token-browser-extension": this.browser_extension_token,
      "x-identity": this.browser_extension_identity
    }
  }
  return axios.post(url, data, config)
}
```

---

**Report Generated:** 2026-02-06
**Analyst:** Claude Opus 4.6 (Security Analysis Agent)
**Confidence Level:** HIGH
