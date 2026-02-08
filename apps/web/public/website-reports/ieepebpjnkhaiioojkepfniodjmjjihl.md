# Security Analysis Report: PDF Reader and Editor

## Extension Metadata
- **Extension ID**: ieepebpjnkhaiioojkepfniodjmjjihl
- **Extension Name**: PDF Reader and Editor
- **Version**: 0.4.7
- **User Count**: ~70,000
- **Manifest Version**: 3
- **Homepage**: https://webextension.org/listing/pdf-reader.html

## Executive Summary

PDF Reader and Editor is a legitimate PDF viewing and editing extension that integrates Mozilla's PDF.js library with additional editing capabilities. The extension has been thoroughly analyzed for security vulnerabilities and malicious behavior. The analysis found **no evidence of malware, data exfiltration, or malicious functionality**. The extension follows secure coding practices for a PDF viewer and uses standard Chrome extension APIs appropriately.

**Overall Risk Level: CLEAN**

## Vulnerability Analysis

### 1. PERMISSIONS ANALYSIS - CLEAN

**Declared Permissions:**
- `storage` - Used for user preferences and settings
- `contextMenus` - Used for right-click menu integration
- `favicon` - Used to display website favicons in PDF viewer
- `<all_urls>` (host_permissions) - Required to intercept PDF files from any URL

**Verdict**: The permissions are appropriate and necessary for a PDF viewer extension. The `<all_urls>` permission is legitimately required to intercept PDF downloads and redirect them to the built-in viewer.

**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN - Permissions match legitimate functionality

---

### 2. CONTENT SECURITY POLICY - CLEAN

**CSP Configuration:**
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Analysis**: The CSP is appropriately configured:
- `'wasm-unsafe-eval'` is required for WebAssembly execution (PDF.js WASM modules)
- `'self'` restricts script sources to the extension itself
- No remote script loading enabled

**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN - CSP properly restricts code execution

---

### 3. BACKGROUND SCRIPT ANALYSIS - CLEAN

**Main Background Worker**: `worker.js`

**Functionality:**
1. **Context menu creation** (context.js) - Creates right-click menus for opening PDFs
2. **Managed storage sync** (managed.js) - Enterprise policy support via managed storage
3. **Message handling** - Handles PDF viewer opening and error notifications
4. **Install/Update handling** - Opens homepage on install/update (standard pattern)

**Network Activity**:
- Opens extension homepage (`webextension.org`) on install/update only
- No telemetry, analytics, or data exfiltration
- No remote config fetching

**Code Snippet** (worker.js):
```javascript
chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.method === 'open-viewer') {
    if (sender.frameId === 0) {
      chrome.tabs.update(sender.tab.id, {
        url: request.viewer
      });
    }
  }
  else if (request.method === 'notify') {
    chrome.action.setBadgeText({
      text: 'E',
      tabId: sender.tab.id
    });
  }
});
```

**Severity**: N/A
**Files**: worker.js, context.js, managed.js
**Verdict**: CLEAN - Standard extension initialization and message handling

---

### 4. CONTENT SCRIPT ANALYSIS - CLEAN

**Content Script**: `data/watch.js`

**Functionality:**
- Injected at `document_start` on all URLs
- Detects PDF files by content-type (`application/pdf` or `application/octet-stream`)
- Redirects PDF URLs to the extension's viewer
- Checks user preference for embedded PDFs in iframes

**Code Snippet**:
```javascript
if (type === 'application/pdf') {
  redirect();
}
else if (type === 'application/octet-stream') {
  if (location.href.toLowerCase().includes('.pdf')) {
    redirect();
  }
}
```

**Analysis**: The content script is minimally invasive:
- No DOM manipulation beyond PDF detection
- No data collection or exfiltration
- No user input monitoring
- Respects user preferences for iframe handling

**Severity**: N/A
**Files**: data/watch.js
**Verdict**: CLEAN - Legitimate PDF interception

---

### 5. DYNAMIC CODE EXECUTION - CLEAN

**Search Results:**
- No `eval()` usage detected
- No `Function()` constructor calls
- No dynamic script injection
- Standard `setTimeout` usage only (for UI notifications)

**PDF.js Library**: Uses Mozilla's open-source PDF.js with WASM modules
- WASM files: `openjpeg.wasm`, `qcms_bg.wasm` (legitimate PDF rendering)
- Base64 usage in pdf-lib is for PDF data encoding (standard practice)

**Severity**: N/A
**Files**: All JavaScript files
**Verdict**: CLEAN - No suspicious dynamic code execution

---

### 6. NETWORK REQUESTS - CLEAN

**Analysis**: Grep for fetch/XHR/network calls found:
- **Local resource fetching only** via Service Worker (overwrite.js)
- Fetches extension CSS/JS files to customize PDF.js viewer
- No external API calls
- No analytics endpoints
- No remote configuration loading

**Code Snippet** (overwrite.js):
```javascript
self.addEventListener('fetch', e => {
  if (e.request.url.endsWith('/data/pdf.js/web/viewer.css')) {
    const p = Promise.all([
      fetch(e.request).then(r => r.text()),
      fetch('/data/viewer/buttons.css').then(r => r.text()),
      fetch('/data/viewer/theme.css').then(r => r.text())
    ])
    // ... combines local resources
  }
});
```

**Severity**: N/A
**Files**: overwrite.js
**Verdict**: CLEAN - Only local resource manipulation

---

### 7. DATA COLLECTION & PRIVACY - CLEAN

**Storage Usage:**
- `chrome.storage.local` - User preferences (theme, zoom, scrolling modes)
- `chrome.storage.managed` - Enterprise policy settings (optional)
- `localStorage` - PDF.js viewer state (navigation history)

**No Evidence Of:**
- Cookie theft or harvesting
- Form data collection
- Browsing history extraction
- User input monitoring
- Data exfiltration

**Clipboard Access**: Only writes to clipboard (copy PDF link feature)
```javascript
const copy = content => navigator.clipboard.writeText(content).then(() => {
  notify('Copied to the Clipboard!', 'info');
})
```

**Severity**: N/A
**Files**: data/viewer/overwrite.js, data/options/index.js
**Verdict**: CLEAN - Only legitimate preference storage

---

### 8. THIRD-PARTY LIBRARIES - CLEAN

**Libraries Detected:**
1. **PDF.js** (Mozilla) - Open-source PDF renderer (~1.6MB minified)
2. **pdf-lib.esm.js** - Open-source PDF manipulation library
3. **notification-view** - Custom component by Lunu Bounir (Mozilla Public License)

**Analysis**: All libraries are legitimate, open-source tools for PDF functionality:
- PDF.js is Mozilla's official PDF viewer
- pdf-lib enables PDF editing (cropping, page extraction)
- notification-view provides toast notifications

**Severity**: N/A
**Files**: data/pdf.js/*, data/pdf-lib/*
**Verdict**: CLEAN - Reputable open-source libraries

---

### 9. MALICIOUS PATTERNS - NOT DETECTED

**Checked For:**
- Extension enumeration/fingerprinting: NOT FOUND
- XHR/fetch hooking: NOT FOUND
- Residential proxy infrastructure: NOT FOUND
- Remote kill switches: NOT FOUND
- Market intelligence SDKs: NOT FOUND
- AI conversation scraping: NOT FOUND
- Ad/coupon injection: NOT FOUND
- Obfuscation or code hiding: NOT FOUND
- Credential harvesting: NOT FOUND

**Verdict**: No malicious patterns detected

---

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `innerHTML` usage | notification-view.js:28 | Shadow DOM template initialization (legitimate Web Component pattern) | FALSE POSITIVE |
| Base64 encoding | pdf-lib.esm.js | PDF data encoding (standard PDF library functionality) | FALSE POSITIVE |
| `<all_urls>` permission | manifest.json | Required to intercept PDF files from any website | FALSE POSITIVE |
| Service Worker fetch | overwrite.js | Local resource bundling for PDF.js customization | FALSE POSITIVE |

---

## API Endpoints & External Connections

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://webextension.org/listing/pdf-reader.html` | Homepage/FAQ (opened on install/update only) | LOW |
| NO OTHER ENDPOINTS | No analytics, telemetry, or data collection | NONE |

---

## Data Flow Summary

1. **PDF Detection**: Content script detects PDF by MIME type
2. **Viewer Redirect**: Sends message to background to open extension viewer
3. **PDF Rendering**: PDF.js library renders PDF locally in browser
4. **User Actions**: Editing features (crop, extract pages) use pdf-lib locally
5. **Settings Storage**: User preferences saved to chrome.storage.local

**No external data transmission occurs beyond the initial homepage visit on install/update.**

---

## Recommendations

1. **For Users**: This extension is safe to use for PDF viewing and basic editing
2. **For Security Teams**: Low risk extension with appropriate permissions
3. **For Developers**: Code follows best practices for Chrome MV3 extensions

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification:**
- No malicious code or behavior detected
- No data exfiltration or privacy violations
- Appropriate permission usage for declared functionality
- Uses reputable open-source libraries (Mozilla PDF.js)
- No network requests beyond legitimate homepage visits
- Clean code structure with no obfuscation
- Follows Chrome extension security best practices

**Confidence Level**: HIGH (comprehensive analysis of all JavaScript files and extension behavior)

---

## Analysis Metadata
- **Analyzed By**: Claude Sonnet 4.5 (Automated Security Analysis)
- **Analysis Date**: 2026-02-07
- **Code Location**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/ieepebpjnkhaiioojkepfniodjmjjihl/deobfuscated/`
- **Files Reviewed**: 14 JavaScript files, manifest.json, HTML files
- **Analysis Method**: Static code analysis, pattern matching, API usage review
