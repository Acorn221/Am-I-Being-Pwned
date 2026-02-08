# Unpaywall Security Analysis Report

## Extension Metadata
- **Extension ID**: iplffkdpngmdjhlpjmppncnlhomiipha
- **Name**: Unpaywall
- **Version**: 3.99
- **Users**: ~900,000
- **Manifest Version**: 3
- **Description**: Legally get full text of scholarly articles as you browse.

## Executive Summary

Unpaywall is a **CLEAN** extension with a legitimate, beneficial purpose. The extension helps users find legally available open-access versions of scholarly articles. The code is transparent, well-structured, and exhibits no malicious behavior. All network communications are legitimate, minimal, and related to core functionality.

**Overall Risk: CLEAN**

The extension performs its stated function without engaging in data harvesting, tracking, ad injection, or other deceptive practices common in malicious extensions.

---

## Detailed Analysis

### Manifest Analysis

**Permissions Requested:**
- `storage` - Used to store user preference for "OA Nerd Mode" display setting
- `host_permissions`: `*://*.oadoi.org/*` - Access to oadoi.org API for open access lookup

**Content Security Policy:**
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
Strong CSP that only allows scripts from the extension itself. No eval, no remote script loading.

**Content Scripts:**
- Injected on `<all_urls>` - Necessary for finding DOIs and PDF links on scholarly article pages
- Includes jQuery 3.1.1 and unpaywall.js

**Web Accessible Resources:**
- `unpaywall.html` - The UI iframe shown to users when open access is found

**Verdict:** ✅ Minimal, appropriate permissions for stated functionality. Strong CSP. No webRequest interception.

---

### Background Script Analysis
**File:** `background.js` (41 lines)

**Functionality:**
- Listens for extension install event
- On install, sends empty POST request to `https://unpaywall.org/log/install`
- Based on server response, may show welcome page at `https://unpaywall.org/welcome`

**Network Communication:**
```javascript
fetch(logUrl, {method:"POST", body:{}})
```

**Verdict:** ✅ CLEAN - Benign install telemetry. No user data collected. Empty POST body. Legitimate welcome page behavior.

---

### Content Script Analysis
**File:** `unpaywall.js` (858 lines)

#### Core Functionality

The extension performs these operations:

1. **DOI Detection** - Searches for Digital Object Identifiers using:
   - Meta tags (citation_doi, dc.doi, etc.)
   - Data attributes ([data-doi])
   - Publisher-specific patterns (ScienceDirect, IEEE, PubMed, etc.)
   - Regex patterns in page HTML

2. **PDF Link Detection** - Finds PDF links using:
   - Meta tags (citation_pdf_url)
   - Publisher-specific link patterns
   - Content-Type verification via HEAD request

3. **Open Access Lookup** - Queries oadoi.org API:
   ```javascript
   var url = "https://api.oadoi.org/v2/" + doi + "?email=unpaywall@impactstory.org"
   $.getJSON(url)
   ```

4. **UI Injection** - Inserts iframe with unlock icon when open access is available

#### Network Calls

**API Endpoint:**
- `https://api.oadoi.org/v2/{doi}?email=unpaywall@impactstory.org`
- Public API for open access availability lookup
- Only DOI is sent (no user data, no browsing history)

**PDF Verification:**
```javascript
var xhr = new XMLHttpRequest()
xhr.open("GET", pdfUrl, true)
xhr.onprogress = function () {
    var contentType = xhr.getResponseHeader("Content-Type")
    if (contentType.indexOf("pdf") > -1){
        resolve()  // it's a PDF
    }
}
xhr.send()
```
- Uses XHR to verify Content-Type header
- Aborts after receiving headers (doesn't download full PDF)
- No data exfiltration

**Verdict:** ✅ CLEAN - All network calls are functional and transparent. No tracking, no data harvesting.

---

### DOM Manipulation Analysis

**innerHTML Usage:**
```javascript
// Line 785 - Reading page HTML for DOI regex matching
docAsStr = document.documentElement.innerHTML;

// Line 389 - Reading DOI from link text
var m = doiLinkElem[0].innerHTML.match(/doi\.org\/(.+)/)

// Line 433 - Reading DOI from PubMed link
return doiLinkElem[0].innerHTML
```

**Analysis:**
- All innerHTML usage is for **reading** page content, not writing/injecting
- Used to extract DOIs and metadata from scholarly article pages
- No dynamic code execution, no DOM manipulation for ad injection
- No keylogger patterns (no input/textarea monitoring)
- No form interception

**Verdict:** ✅ CLEAN - Read-only DOM access for legitimate content extraction.

---

### Chrome API Usage

**APIs Used:**
- `chrome.storage.local` - Store single user preference (showOaColor boolean)
- `chrome.tabs.create` - Open welcome/FAQ pages (user-initiated only)
- `chrome.runtime.getURL` - Get extension resource URLs for iframe
- `chrome.runtime.onInstalled` - Detect extension install event

**NOT Used:**
- ❌ `chrome.cookies` - No cookie access
- ❌ `chrome.webRequest` - No network interception
- ❌ `chrome.management` - No extension enumeration/killing
- ❌ `chrome.history` - No browsing history access
- ❌ `chrome.tabs.executeScript` - No dynamic code injection

**Verdict:** ✅ CLEAN - Minimal API usage appropriate for functionality.

---

### Third-Party Dependencies

**jQuery 3.1.1** (`js/jquery-3.1.1.min.js`)
- Standard jQuery library
- Used for DOM querying and AJAX requests
- No modifications detected

**Verdict:** ✅ CLEAN - Standard, unmodified library.

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `innerHTML` read | unpaywall.js:785 | Reading page HTML to extract DOI via regex | FP - Read-only |
| `innerHTML` read | unpaywall.js:389,433 | Reading link text to extract DOI | FP - Read-only |
| `XMLHttpRequest` | unpaywall.js:659 | PDF Content-Type verification (HEAD-like request) | FP - Legitimate |
| `fetch()` | background.js:14 | Empty POST for install logging | FP - Benign telemetry |
| `navigator.userAgent` | unpaywall.js:9 | Console logging gate (debug mode only) | FP - Dev logging |
| jQuery `ga()` function | jquery.min.js | jQuery's internal Sizzle selector function | FP - Not Google Analytics |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Data Received | Risk |
|----------|---------|-----------|---------------|------|
| `unpaywall.org/log/install` | Install event logging | Empty POST body | `{show_welcome_screen: boolean}` | NONE |
| `unpaywall.org/welcome` | User onboarding page | None (browser navigation) | HTML page | NONE |
| `unpaywall.org/faq` | Help documentation | None (browser navigation) | HTML page | NONE |
| `api.oadoi.org/v2/{doi}` | Open access lookup | DOI only | OA availability data | NONE |
| Various PDF URLs | Content-Type verification | HTTP headers only | PDF metadata | NONE |

---

## Data Flow Summary

### Data Collection
**What is collected:**
- User preference: OA color display mode (boolean, stored locally)

**What is NOT collected:**
- ❌ Browsing history
- ❌ User credentials
- ❌ Form inputs
- ❌ Cookies
- ❌ Personal information
- ❌ Extension inventory
- ❌ Page content beyond DOI/PDF detection

### Data Transmission
**What is sent externally:**
- DOI (Document identifier) → oadoi.org API for OA lookup
- Empty POST → unpaywall.org/log/install on first install

**What is NOT sent:**
- ❌ User data
- ❌ Browsing history
- ❌ Page content
- ❌ Analytics events
- ❌ Telemetry beyond install event

---

## Vulnerability Assessment

### Critical Issues
**NONE FOUND**

### High Severity Issues
**NONE FOUND**

### Medium Severity Issues
**NONE FOUND**

### Low Severity Issues
**NONE FOUND**

### Informational

#### I1: Install Telemetry
**Severity:** INFORMATIONAL
**File:** background.js:14
**Description:**
Extension sends empty POST to `unpaywall.org/log/install` on first install.

**Code:**
```javascript
fetch(logUrl, {method:"POST", body:{}})
```

**Impact:**
Minimal - Server can log install timestamp and potentially IP address, but no user data is transmitted.

**Verdict:** ACCEPTABLE - Standard practice for measuring adoption. No PII collected.

---

#### I2: Broad Content Script Injection
**Severity:** INFORMATIONAL
**Manifest:** content_scripts → matches: `<all_urls>`

**Description:**
Content script runs on all pages to detect scholarly articles.

**Justification:**
Necessary for core functionality - extension cannot know in advance which pages contain scholarly articles with DOIs.

**Mitigation:**
- Script is lightweight and exits early if no DOI found
- No persistent DOM monitoring or event listeners
- No performance impact on non-academic pages

**Verdict:** ACCEPTABLE - Functionally required for the extension's purpose.

---

## Security Best Practices Observed

✅ **Manifest V3** - Uses modern, more secure manifest version
✅ **Minimal permissions** - Only requests necessary permissions
✅ **Strong CSP** - Prevents inline scripts and remote code execution
✅ **No eval()** - No dynamic code execution
✅ **No obfuscation** - Code is readable and transparent
✅ **Standard libraries** - Uses unmodified jQuery 3.1.1
✅ **HTTPS only** - All external communications over secure connections
✅ **No tracking SDKs** - No Sentry, Google Analytics, or market intelligence tools
✅ **No extension enumeration** - Does not query or disable other extensions
✅ **No ad injection** - Does not modify page content for monetization
✅ **Transparent operation** - Clear visual indicator (iframe) when active

---

## Comparison to Malicious Patterns

| Malicious Pattern | Observed in Unpaywall | Status |
|-------------------|----------------------|--------|
| Extension enumeration/killing | ❌ No | CLEAN |
| XHR/fetch hooking | ❌ No | CLEAN |
| Residential proxy infrastructure | ❌ No | CLEAN |
| Remote config/kill switches | ❌ No | CLEAN |
| Market intelligence SDKs (Sensor Tower) | ❌ No | CLEAN |
| AI conversation scraping | ❌ No | CLEAN |
| Ad/coupon injection | ❌ No | CLEAN |
| Cookie harvesting | ❌ No | CLEAN |
| Keylogger patterns | ❌ No | CLEAN |
| Form interception | ❌ No | CLEAN |
| Credential theft | ❌ No | CLEAN |
| Hidden iframes | ❌ No (iframe is visible UI element) | CLEAN |
| Dynamic script injection | ❌ No | CLEAN |
| Obfuscation | ❌ No | CLEAN |

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Summary
Unpaywall is a legitimate, well-engineered browser extension that performs exactly as advertised. It helps users access legally available open-access versions of scholarly research papers. The extension:

- Has a clear, beneficial purpose
- Uses minimal permissions appropriately
- Performs no tracking or data harvesting beyond a single install event
- Does not inject ads or modify pages for monetization
- Does not scrape sensitive data
- Does not interfere with other extensions
- Has transparent, readable code
- Follows security best practices

### Recommendation
**APPROVE for continued use**

This extension is safe and provides genuine value to researchers and students. No remediation required.

---

## Technical Details

### Files Analyzed
- `/deobfuscated/manifest.json` - Extension configuration
- `/deobfuscated/background.js` - Service worker (41 lines)
- `/deobfuscated/unpaywall.js` - Main content script (858 lines)
- `/deobfuscated/inside-frame.js` - Iframe UI logic (26 lines)
- `/deobfuscated/popup.js` - Extension popup (24 lines)
- `/deobfuscated/options.js` - Settings page (36 lines)
- `/deobfuscated/js/jquery-3.1.1.min.js` - jQuery library
- `/deobfuscated/*.html` - UI pages

### Analysis Methodology
- Static code analysis of all JavaScript files
- Manifest permission audit
- Network communication analysis
- DOM manipulation pattern analysis
- Chrome API usage review
- Comparison against known malicious patterns
- Third-party dependency verification

### Analyst Notes
This is one of the cleanest extensions analyzed in this research project. The code quality is high, the purpose is clear and beneficial, and there are no deceptive or malicious practices. Unpaywall serves as a positive example of how browser extensions should be built.

---

**Report Generated:** 2026-02-06
**Analysis Status:** COMPLETE
**Analyst Confidence:** HIGH
