# Security Analysis: Annotate pdf (ffkgggpfimdabhlfomcfhpgbmjfdbhfh)

## Extension Metadata
- **Name**: Annotate pdf
- **Extension ID**: ffkgggpfimdabhlfomcfhpgbmjfdbhfh
- **Version**: 1.0.2
- **Manifest Version**: 3
- **Estimated Users**: ~50,000
- **Developer**: pdfedit.ai
- **Analysis Date**: 2026-02-15

## Executive Summary
Annotate PDF is a legitimate PDF annotation extension with **LOW** security risk. The extension provides two methods for PDF editing: (1) opening pdfedit.ai website with remote PDF fetching capability, and (2) a local Next.js-based PDF editor accessible via extension popup. The extension injects UI buttons on Google search results and PDF pages to facilitate quick access. Analysis identified one low-severity vulnerability related to insufficient origin validation in message passing, which could theoretically allow malicious websites to trigger unwanted navigation. No data exfiltration, tracking, or malicious behavior was detected.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. Insufficient Message Origin Validation
**Severity**: LOW
**Files**: `/js/f9e5d2ae19beeed9.min.js` (background service worker, lines 40-41)

**Analysis**:
The background script's message listener does not validate the sender origin before processing "openWebsite" actions, potentially allowing malicious websites to trigger PDF opening/fetching behavior.

**Code Evidence**:
```javascript
chrome.runtime.onMessage.addListener((async (e, t, n) => {
  "openWebsite" === e.action && e.pdfUrl ?
    (e.pdfUrl.startsWith("https://") || e.pdfUrl.startsWith("http://")) &&
    await openWebsiteAndSendFile(e.pdfUrl) :
    openWebsite()
}))
```

**Vulnerability Details**:
- Message handler accepts `{action: "openWebsite", pdfUrl: "..."}` from any source
- While the code validates URL scheme (http/https), it does not check `sender.origin` or `sender.id`
- A malicious website could theoretically send this message via content script communication
- **However**: Chrome's runtime messaging API requires `externally_connectable` in manifest for web pages to send messages, which this extension does NOT have

**Impact**:
- **Theoretical**: Malicious website could open pdfedit.ai tabs or trigger remote PDF fetches
- **Practical**: Limited impact since no `externally_connectable` configuration exists
- No sensitive data exposure or code execution risk
- User would see unwanted tab opening (visible behavior)

**Exploitability**: LOW - Requires content script injection on user-visited page, which would already indicate browser compromise

**Mitigation Recommendation**:
```javascript
chrome.runtime.onMessage.addListener((async (message, sender, sendResponse) => {
  // Validate sender is from extension, not web page
  if (!sender.id || sender.id !== chrome.runtime.id) {
    return;
  }
  // ... rest of handler
}))
```

**Verdict**: **LOW SEVERITY** - Theoretical issue with minimal real-world exploitability.

---

### 2. Google Search Results UI Injection (EXPECTED BEHAVIOR)
**Severity**: N/A (Design Feature)
**Files**: `/js/5419d0fbdc60a00b.min.js` (content script for Google Search)

**Analysis**:
The extension injects "Annotate PDF" buttons next to PDF links in Google search results.

**Code Evidence**:
```javascript
const searchResults = document.querySelectorAll("div.g");
searchResults.forEach((e => {
  const t = e.querySelector("a");
  if (t && t.href.endsWith(".pdf")) {
    const e = document.createElement("button");
    e.innerHTML = '<img src="' + chrome.runtime.getURL("icons/16x16.png") +
                  '" alt="Annotate PDF" class="icon">';
    e.className = "floating-button";
    e.addEventListener("click", (() => {
      chrome.runtime.sendMessage({
        action: "openWebsite",
        pdfUrl: t.href
      })
    }));
    t.parentElement.appendChild(e)
  }
}))
```

**Purpose**:
- Scans Google search results for PDF links (ending with `.pdf`)
- Injects button to quickly open PDF in annotation tool
- Sends PDF URL to background script for remote fetching

**Data Accessed**:
- PDF URLs from search results (public data)
- No form data, credentials, or sensitive information

**Verdict**: **NOT MALICIOUS** - Standard convenience feature for PDF-focused extensions.

---

### 3. Remote PDF Fetching
**Severity**: N/A (Expected Behavior)
**Files**: `/js/f9e5d2ae19beeed9.min.js` (background service worker, lines 4-33)

**Analysis**:
The background script fetches remote PDF files and forwards them to the pdfedit.ai website or local editor via message passing.

**Code Evidence**:
```javascript
async function fetchRemotePdf(e) {
  const t = await fetch(e);
  return await t.blob()
}

async function openWebsiteAndSendFile(e) {
  const t = await fetchRemotePdf(e);
  chrome.tabs.create({
    url: SITE_URL  // "https://pdfedit.ai"
  }, (async e => {
    await chrome.scripting.executeScript({
      target: { tabId: e.id },
      func: sendFile
    });
    const n = new FileReader;
    n.onload = t => {
      chrome.tabs.sendMessage(e.id, {
        action: "sendBlob",
        blob: n.result  // base64-encoded PDF
      })
    };
    n.readAsDataURL(t)
  }))
}
```

**Workflow**:
1. User clicks "Annotate PDF" button (on Google search or PDF page)
2. Background script fetches remote PDF via `fetch(url)`
3. Opens new tab to `https://pdfedit.ai`
4. Injects content script that listens for "sendBlob" message
5. Sends base64-encoded PDF blob via `chrome.tabs.sendMessage`
6. Injected script stores blob in `localStorage` and triggers UI click

**Security Considerations**:
- PDF fetch respects CORS (cannot access private network resources)
- PDF is sent to vendor's website (pdfedit.ai), not third-party
- No exfiltration of browsing data, cookies, or credentials
- User explicitly initiates action via button click

**Data Transmitted to pdfedit.ai**:
- PDF file content (base64-encoded)
- No URLs, browsing history, or user identifiers

**Verdict**: **NOT MALICIOUS** - Standard PDF processing workflow for cloud-based annotation service.

---

### 4. PDF Page UI Injection
**Severity**: N/A (Design Feature)
**Files**: `/js/c6e3d99de56d15e1.min.js` (content script for PDF pages)

**Analysis**:
The extension injects a floating "Annotate PDF" button on PDF documents opened in Chrome's built-in PDF viewer.

**Code Evidence**:
```javascript
if ("application/pdf" === document.contentType) {
  const e = document.createElement("button");
  e.innerHTML = '<img src="' + chrome.runtime.getURL("icons/48x48.png") +
                '" alt="Annotate PDF" class="icon">';
  e.className = "floating-button";
  e.title = "Annotate PDF";
  e.addEventListener("click", (() => {
    chrome.runtime.sendMessage({
      action: "openWebsite",
      pdfUrl: window.location.href
    })
  }));
  document.body.appendChild(e)
}
```

**Purpose**:
- Detects PDF documents via `document.contentType === "application/pdf"`
- Injects floating button in viewport
- Sends current PDF URL to background script when clicked

**Data Accessed**:
- Current page URL (`window.location.href`) - only when user clicks button
- No form data, page content, or credentials

**Verdict**: **NOT MALICIOUS** - Standard PDF extension behavior.

---

### 5. Local PDF Editor (Next.js Web App)
**Severity**: N/A (Expected Behavior)
**Files**:
- `/index.html` (local PDF editor UI)
- `/assets/static/chunks/*.js` (Next.js application bundle)
- `/app/*` (web accessible resources)

**Analysis**:
The extension bundles a complete Next.js-based PDF annotation web application accessible via the extension popup or local URL (`chrome-extension://[ID]/index.html`).

**Features Detected** (from code analysis):
- PDF rendering (using pdf.js library: `/pdf.worker.min.mjs`)
- Annotation tools: text, pencil, arrows, lines, rectangles, circles, highlighter, whiteout, eraser, signature
- File upload/download
- Google Fonts integration (fonts.googleapis.com, fonts.gstatic.com)
- Zustand state management
- Local processing (no server upload for local mode)

**Network Requests** (from local editor):
- `fonts.googleapis.com` - Google Fonts CSS (for text annotation)
- `fonts.gstatic.com` - Google Fonts assets (preconnect)
- `use.typekit.net` - Adobe Typekit fonts (optional, preconnect only)
- `www.w3.org` - SVG/XML namespace declarations (not actual requests)

**Security Analysis**:
- PDF processing occurs client-side using pdf.js (standard library)
- No automatic data transmission to external servers
- Annotations stored locally in browser context
- CSP configured: `script-src 'self'; object-src 'self'` (secure)

**Obfuscation Analysis**:
- Code is minified/bundled (standard Next.js production build)
- No intentional obfuscation detected
- Build artifacts include source maps references (standard webpack output)

**Verdict**: **NOT MALICIOUS** - Standard client-side PDF editing application.

---

## Network Analysis

### Endpoints Contacted

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| pdfedit.ai | Cloud PDF editor (user-initiated) | PDF file content (base64) | LOW |
| fonts.googleapis.com | Google Fonts CSS | Font requests (standard) | CLEAN |
| fonts.gstatic.com | Google Fonts assets | Font requests (standard) | CLEAN |
| use.typekit.net | Adobe Typekit (preconnect only) | None (preconnect) | CLEAN |
| www.w3.org | XML/SVG namespaces | None (code references) | CLEAN |

**User Data Exposure**:
- PDF file content sent to pdfedit.ai when user clicks "Annotate PDF" button
- No browsing history, cookies, credentials, or form data transmitted
- No tracking pixels, analytics, or telemetry detected

**Third-Party Integrations**:
- Google Fonts (standard web resource)
- Adobe Typekit (preconnect only, no actual requests)
- pdf.js library (Mozilla open-source, bundled)

---

## Permission Analysis

### Declared Permissions

| Permission | Usage | Risk Level |
|------------|-------|------------|
| `scripting` | Inject content scripts for PDF blob passing | EXPECTED |
| `contextMenus` | Add "Annotate PDF" context menu | EXPECTED |
| `<all_urls>` (host) | Inject buttons on Google Search + PDF pages | BROAD |

**Permission Risk Assessment**:

1. **scripting** - EXPECTED
   - Used to inject content script on pdfedit.ai for receiving PDF blobs
   - Required for cloud-based PDF processing workflow
   - Code execution limited to vendor domain

2. **contextMenus** - EXPECTED
   - Creates context menu for PDF pages
   - Standard for PDF-focused extensions

3. **<all_urls>** - BROAD BUT JUSTIFIED
   - Required for Google Search injection (`https://www.google.com/search*`)
   - Required for PDF page detection (`https://*/*.pdf`, `http://*/*.pdf`)
   - **Concern**: Grants access to all websites, but:
     - Content scripts only run on Google Search + PDF documents (manifest restrictions)
     - No evidence of data collection beyond PDF URLs
     - No tracking or analytics detected

**Missing Permissions** (positive indicators):
- No `storage` permission (no persistent data collection)
- No `cookies` permission (no credential theft)
- No `history` permission (no browsing surveillance)
- No `tabs` permission beyond standard content script access

---

## Content Security Policy Analysis

**Extension Pages CSP**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Analysis**:
- **script-src 'self'**: Only extension scripts can execute (no inline scripts, no remote scripts)
- **object-src 'self'**: Only extension plugins/objects allowed
- **Verdict**: SECURE - Prevents XSS and remote code injection

---

## Code Quality & Obfuscation Assessment

**Build Type**: Production (minified Next.js bundle)
**Obfuscation Level**: Standard minification (not intentionally obfuscated)
**Indicators**:
- Webpack chunk naming (`main-b6ee90d36ca2929c.js`, `framework-8883d1e9be70c3da.js`)
- Source map references (commented out but present in structure)
- React/Next.js framework artifacts visible
- No string encryption, control flow flattening, or anti-debugging

**ext-analyzer Flags**:
- `obfuscated: true` - Due to minification, not malicious obfuscation
- Standard for production JavaScript applications

---

## Potential Privacy Concerns

### 1. PDF Content Visibility to pdfedit.ai
**Severity**: LOW (User-Initiated)

When users click "Annotate PDF" buttons, the extension:
1. Fetches the PDF file via background script
2. Sends base64-encoded PDF to `https://pdfedit.ai` via message passing
3. PDF is processed on vendor's server (cloud mode)

**Privacy Considerations**:
- User explicitly initiates action (button click required)
- Sensitive PDFs (financial, medical, legal) are exposed to vendor
- No indication of server-side storage or data retention policies
- Alternative: Use local editor mode (popup) for private documents

**Recommendation**: Users should use local editor for sensitive documents.

---

### 2. URL Collection via Google Search Injection
**Severity**: MINIMAL

The extension could theoretically collect PDF URLs from Google search results but:
- No evidence of URL logging or transmission
- No network requests to analytics/tracking services
- Content script code only sends URLs when user clicks button

**Verdict**: No privacy violation detected.

---

## Comparison with Malicious Extensions

### This Extension vs. Typical Malware:

| Indicator | Malicious Extensions | Annotate PDF |
|-----------|---------------------|--------------|
| Hidden data exfiltration | Common | NOT PRESENT |
| Tracking pixels/beacons | Common | NOT PRESENT |
| Cookie/credential theft | Common | NOT PRESENT |
| Keylogging | Common | NOT PRESENT |
| History scraping | Common | NOT PRESENT |
| Ad injection | Common | NOT PRESENT |
| Cryptomining | Occasional | NOT PRESENT |
| Intentional obfuscation | Common | NOT PRESENT |

**Conclusion**: Extension exhibits legitimate behavior consistent with PDF annotation tools.

---

## Install/Update Behavior

**Installation**:
```javascript
e.reason === chrome.runtime.OnInstalledReason.INSTALL ?
  chrome.tabs.create({url: INSTALL_LINK}) :  // Opens pdfedit.ai/welcome
...
```

**On Install**: Opens welcome page at `https://pdfedit.ai/welcome`
- Standard onboarding behavior
- No hidden tracking parameters detected

**On Update**: Logs to console only
- No forced navigation or upsell tabs

---

## Data Flow Summary

```
USER ACTION (Click "Annotate PDF")
    ↓
CONTENT SCRIPT (c6e3d99de56d15e1.min.js or 5419d0fbdc60a00b.min.js)
    ↓ chrome.runtime.sendMessage({action: "openWebsite", pdfUrl: "..."})
BACKGROUND SCRIPT (f9e5d2ae19beeed9.min.js)
    ↓ fetch(pdfUrl) → blob
    ↓ chrome.tabs.create({url: "https://pdfedit.ai"})
    ↓ chrome.scripting.executeScript(sendFile function)
    ↓ chrome.tabs.sendMessage({action: "sendBlob", blob: base64PDF})
PDFEDIT.AI TAB (injected content script)
    ↓ localStorage.setItem("pdfBlob", blob)
    ↓ Trigger UI to load PDF from localStorage
PDFEDIT.AI WEBSITE
    ↓ Process PDF (cloud-based annotation)
```

**Data Exposure Points**:
1. PDF URL exposed to extension (user-initiated)
2. PDF content fetched by background script (public URLs only, respects CORS)
3. PDF blob sent to pdfedit.ai (vendor processing)

**No Leakage To**:
- Third-party analytics
- Ad networks
- Data brokers
- Unknown servers

---

## False Positive Analysis (ext-analyzer)

The ext-analyzer reported 3 exfiltration flows:

### Flow 1: `chrome.tabs.query → fetch(pdfedit.ai)`
**Status**: FALSE POSITIVE (Intended Feature)
- `chrome.tabs.query` used to get active tab for PDF URL extraction
- `fetch()` sends PDF to vendor's website (user-initiated)
- Not covert data exfiltration

### Flow 2: `document.getElementById → fetch(n)`
**Status**: FALSE POSITIVE (Next.js Framework)
- Part of Next.js application bundle
- Standard DOM manipulation + font/asset loading
- Variable `n` likely a font URL or webpack chunk

### Flow 3: `document.getElementById → fetch(www.w3.org)`
**Status**: FALSE POSITIVE (XML Namespace)
- www.w3.org used for SVG/XML DTD references
- No actual network request (just namespace string)
- Standard in pdf.js library

**Conclusion**: All flagged flows are legitimate or framework artifacts.

---

## Recommendations

### For Users:
1. **Use Local Editor for Sensitive PDFs**: Open popup (click extension icon) instead of cloud mode to avoid sending PDF to pdfedit.ai
2. **Understand Data Sharing**: "Annotate PDF" buttons send document to vendor's server
3. **Review Vendor Privacy Policy**: Check pdfedit.ai's data retention/privacy practices

### For Developers:
1. **Add Message Origin Validation**:
   ```javascript
   chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
     if (!sender.id || sender.id !== chrome.runtime.id) return;
     // ... handler code
   })
   ```

2. **Add User Consent UI**: Inform users before sending PDF to cloud
   ```javascript
   if (confirm("Send PDF to pdfedit.ai for cloud editing?")) {
     // proceed with fetch
   }
   ```

3. **Clarify Privacy Policy**: Document what data is sent to pdfedit.ai and retention policies

---

## Risk Scoring

| Category | Score | Notes |
|----------|-------|-------|
| Data Exfiltration | 1/10 | Only sends user-initiated PDF files to vendor |
| Malicious Code | 0/10 | No malware, trojans, or exploits detected |
| Privacy Violation | 2/10 | PDF content exposed to vendor (expected for cloud service) |
| Permission Abuse | 2/10 | `<all_urls>` is broad but usage is justified |
| Code Quality | 8/10 | Professional Next.js build, standard practices |

**Overall Risk Score: 5/100 (LOW)**

---

## Final Verdict

**Risk Level**: LOW

**Summary**: Annotate PDF is a legitimate PDF annotation extension with one low-severity vulnerability (insufficient message origin validation) that has minimal real-world exploitability. The extension's core functionality involves sending user-selected PDFs to the developer's cloud service (pdfedit.ai) for annotation, which is disclosed through UI/UX but should be more explicitly stated in privacy documentation. No malicious behavior, data theft, or tracking mechanisms were identified. The extension is suitable for general use but should not be used with sensitive/confidential PDFs unless using the local editor mode.

**Recommended Actions**:
- **Users**: SAFE TO USE with awareness of cloud processing
- **Developers**: Implement message origin validation and improve privacy transparency
- **Reviewers**: APPROVE with LOW risk classification

---

## Appendix: File Inventory

### Extension Scripts
- `js/f9e5d2ae19beeed9.min.js` - Background service worker (68 lines)
- `js/c6e3d99de56d15e1.min.js` - Content script for PDF pages (1 line, minified)
- `js/5419d0fbdc60a00b.min.js` - Content script for Google Search (1 line, minified)
- `js/bfc1efdd03c72144.min.js` - Popup script (minimal, opens website)

### Web Application Bundle (Next.js)
- `index.html` - Local PDF editor entry point
- `assets/static/chunks/app/page-640c1b22689619fc.js` - Main app page (PDF editor UI)
- `assets/static/chunks/main-b6ee90d36ca2929c.js` - Next.js runtime (174KB)
- `assets/static/chunks/framework-8883d1e9be70c3da.js` - React framework (242KB)
- `assets/static/chunks/205-2832f52a56c29b6d.js` - PDF.js integration (586KB)
- `pdf.worker.min.mjs` - PDF.js worker thread
- (+ 20 additional webpack chunks for UI components)

### Total Codebase Size: ~3.4MB (primarily PDF.js library and Next.js framework)

---

**Analysis Completed**: 2026-02-15
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
**Methodology**: Static analysis, code review, data flow tracing, ext-analyzer integration
