# Vulnerability Report: Scholarcy Browser Extension

## Extension Metadata
- **Extension Name**: Scholarcy Browser Extension
- **Extension ID**: oekgknkmgmaehhpegfeioenikocgbcib
- **Version**: 5.3.0
- **User Count**: ~90,000 users
- **Author**: Scholarcy
- **Manifest Version**: 3

## Executive Summary

The Scholarcy Browser Extension is a legitimate academic research tool that summarizes research articles and creates interactive flashcards. The extension operates with a legitimate business model, communicating with official Scholarcy backend services (library.scholarcy.com, engine.scholarcy.com, scholarcy.com) for document processing. The extension follows modern security practices with Manifest V3 implementation and minimal permissions.

**Overall Risk Level: CLEAN**

The extension demonstrates good security practices including:
- Minimal permission requests (storage, activeTab, cookies)
- Manifest V3 implementation with service worker
- Communication with documented, legitimate API endpoints
- No dynamic code execution or eval usage
- No suspicious obfuscation beyond standard build tooling (Parcel bundler)
- Content Security Policy enforced via Manifest V3 defaults

## Vulnerability Analysis

### 1. CLEAN - Manifest Permissions

**Severity**: None
**File**: manifest.json

**Analysis**:
The extension requests minimal, justified permissions:
- `storage`: For saving user preferences and state
- `activeTab`: For accessing the current tab when user explicitly invokes the extension
- `cookies`: For reading authentication cookies from scholarcy.com domain
- `host_permissions`: Limited to `https://*.scholarcy.com/*` (legitimate backend)

**Verdict**: All permissions are appropriate for the extension's documented functionality. The activeTab permission is preferred over broad host permissions, following security best practices.

---

### 2. CLEAN - Background Service Worker

**Severity**: None
**File**: static/background/index.js

**Analysis**:
The background service worker implements two message handlers:
1. `checkAuth`: Reads the `extract-api-token` cookie from scholarcy.com to verify user authentication
2. `backendRequest`: Sends POST requests to `https://library.scholarcy.com/flashcard-extraction` with document URLs

**Code Context**:
```javascript
chrome.runtime.onMessage.addListener(function(e, t, r) {
  switch (e.type) {
    case "checkAuth":
      return (async () => {
        let e = await getCookieValue({
          url: EXTRACT_API_TOKEN_COOKIE_HOST,
          name: "extract-api-token"
        });
        e ? r({logged_in: !0}) : r({logged_in: !1})
      })(), !0;
    case "backendRequest":
      return (async () => {
        let t = {
          url: e.url,
          external_metadata: !0,
          inline_citation_links: !0,
          citation_contexts: !0,
          reference_format: "bibtex",
          structured_summary: !0
        };
        let n = new FormData;
        for (let [e, r] of Object.entries(t)) r && n.append(e, r.toString());
        let o = await fetch(`${SCHOLARCY_LIBRARY_BASE_URL}/flashcard-extraction`, {
          method: "POST",
          credentials: "include",
          body: n
        });
        let a = await o.json();
        r({message: o.ok ? "Backend request sent" : "Backend request failed", data: a})
      })(), !0
  }
})
```

**Verdict**: CLEAN - Standard message passing implementation with legitimate API communication. Cookie access is limited to first-party Scholarcy domain. No privilege escalation or security issues detected.

---

### 3. CLEAN - Content Script DOM Manipulation

**Severity**: None
**File**: content.00c7919c.js

**Analysis**:
The content script injects "Import to Scholarcy" buttons on academic web pages, identifying research articles by:
- Searching for DOI patterns in link text
- Looking for [PDF]/[HTML] link markers common on academic sites
- Extracting citation_pdf_url meta tags

The script communicates with the background worker via chrome.runtime.sendMessage for authentication checks and backend requests.

**Code Context**:
```javascript
chrome.runtime.onMessage.addListener(function(e,t,r){
  if("getContentToExtract"===e.command){
    let e;
    let t=document.contentType;
    if("text/html"==t){
      let o=document.documentElement.outerHTML,
      n=document.querySelector("meta[name$='citation_pdf_url']");
      if(n)e=n.getAttribute("content");
      // ... additional PDF extraction logic
      r({contentType:t,pdfURL:e,content:o})
    }
  }
})
```

**Verdict**: CLEAN - No malicious DOM manipulation detected. The extension only adds UI elements when users are authenticated and browsing academic content. No keyloggers, no form hijacking, no credential theft.

---

### 4. CLEAN - API Endpoints

**Severity**: None
**Files**: All JavaScript files

**Detected Endpoints**:
- https://library.scholarcy.com/flashcard-extraction (POST)
- https://library.scholarcy.com/flashcards/{id} (GET)
- https://engine.scholarcy.com (configuration)
- https://scholarcy.com (authentication cookie domain)
- https://assets.scholarcy.com/ajax-loader.gif (UI asset)

**Verdict**: All endpoints are legitimate Scholarcy services. No connections to suspicious third-party domains, analytics SDKs, or data exfiltration endpoints detected.

---

### 5. CLEAN - No Dynamic Code Execution

**Severity**: None
**Files**: All JavaScript files

**Analysis**:
Comprehensive search for dangerous patterns found:
- No `eval()` usage
- No `Function()` constructor
- No `setTimeout`/`setInterval` with string arguments
- No `innerHTML` with user-controlled data (only React VDOM)
- No `document.write()`
- Limited `postMessage` usage (standard content script communication)

**Verdict**: CLEAN - No dynamic code execution vulnerabilities detected. The extension uses standard bundler output (Parcel) with no malicious obfuscation.

---

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| React SVG innerHTML | Standard React rendering for icons/images | Known FP - SAFE |
| Parcel module loader | Build tool boilerplate (`parcelRequire`) | Known FP - SAFE |
| globalThis.define | AMD module compatibility shim | Known FP - SAFE |
| chrome.cookies.get | Reading auth token from first-party domain only | Legitimate usage - SAFE |
| document.documentElement.outerHTML | Extracting page content for article analysis | Legitimate functionality - SAFE |

## API Endpoints Table

| Endpoint | Method | Purpose | Risk |
|----------|--------|---------|------|
| https://library.scholarcy.com/flashcard-extraction | POST | Submit documents for summarization | NONE |
| https://library.scholarcy.com/flashcards/{id} | GET | View generated flashcard summaries | NONE |
| https://engine.scholarcy.com | N/A | Backend configuration endpoint | NONE |
| https://scholarcy.com | N/A | Authentication/cookie domain | NONE |
| https://assets.scholarcy.com/* | GET | Static assets (images, etc.) | NONE |

## Data Flow Summary

1. **User Action**: User navigates to academic article page (e.g., arXiv, PubMed)
2. **Content Script Injection**: Extension identifies research articles via DOI patterns or PDF metadata
3. **Authentication Check**: Background worker reads `extract-api-token` cookie from scholarcy.com
4. **UI Enhancement**: If authenticated, "Import to Scholarcy" buttons are added to article links
5. **Document Processing**: On button click, document URL is sent to library.scholarcy.com via POST
6. **Response**: Backend returns flashcard ID, user can view summary on library.scholarcy.com

**Data Collected**:
- Document URLs from academic websites (user-initiated)
- Authentication cookies (first-party only)
- Page content/metadata (only when extracting PDFs)

**Data Not Collected**:
- Browsing history
- Personal information
- Credentials from other sites
- User input/keystrokes

## Overall Risk Assessment

**Risk Level: CLEAN**

**Justification**:
- Legitimate academic tool from established company (Scholarcy)
- Minimal permissions appropriate to functionality
- No evidence of malware, spyware, or data exfiltration
- No suspicious third-party integrations
- Modern Manifest V3 security model
- Transparent communication with documented backend services
- No dynamic code execution or obfuscation beyond standard build tools
- Cookie access limited to first-party domain (scholarcy.com)
- activeTab permission used appropriately (no broad host_permissions abuse)

**Recommendation**: No security concerns identified. Extension appears to be a legitimate productivity tool for academic research with proper security practices.

---

## Report Metadata
- **Analysis Date**: 2026-02-07
- **Analyzer**: Claude Sonnet 4.5
- **Code Location**: /home/acorn221/projects/cws-scraper/output/workflow-downloaded/oekgknkmgmaehhpegfeioenikocgbcib/deobfuscated/
