# Wakelet Chrome Extension Security Analysis

## Extension Metadata
- **Name:** Wakelet
- **Extension ID:** iomokcfebnfiflpgcpcijfkfmafgkjgh
- **Version:** 5.0.0
- **Estimated Users:** ~70,000
- **Manifest Version:** 3
- **Developer:** Wakelet

## Executive Summary

Wakelet is a legitimate productivity extension built with Plasmo framework that allows users to save, organize, and share web content. The extension employs modern web development practices and communicates exclusively with official Wakelet infrastructure. **No malicious behavior, suspicious patterns, or significant security vulnerabilities were identified.**

The extension demonstrates good security hygiene with:
- MV3 compliance with service worker architecture
- Credential-based authentication (cookies only)
- Limited scope permissions appropriate for functionality
- Communication exclusively with first-party domains
- No third-party analytics or tracking SDKs
- No obfuscation or code execution attempts

**Overall Risk Assessment: CLEAN**

## Vulnerability Analysis

### 1. Permissions Review

**Manifest Permissions:**
```json
"permissions": ["storage", "sidePanel", "cookies", "tabs", "activeTab"]
"host_permissions": ["https://*/*", "<all_urls>"]
```

**Severity:** LOW
**Assessment:** ACCEPTABLE for functionality

**Details:**
- `storage`: Used for user preferences and extension state
- `sidePanel`: Required for side panel UI (MV3 feature)
- `cookies`: Limited to reading Wakelet authentication cookie `_Host-WKA` on `wakelet.com` domain
- `tabs`: Used for tab querying and screenshot capture features
- `activeTab`: Enables interaction with current tab
- `host_permissions`: Broad but necessary for content extraction from any webpage

**Verdict:** Permissions are appropriate for a content bookmarking/clipping extension. No evidence of abuse.

---

### 2. Content Security Policy

**Manifest CSP:** Not explicitly defined (uses MV3 defaults)

**Severity:** N/A
**Assessment:** ACCEPTABLE

**Details:**
- MV3 enforces strict CSP by default
- No `unsafe-eval` or `unsafe-inline` detected
- All scripts loaded from extension bundle

**Verdict:** CSP configuration is secure by MV3 defaults.

---

### 3. Network Communication Analysis

**Primary Endpoints:**
1. `https://d25b5nddb51s46.cloudfront.net` - Content scraping service
2. `https://wakelet.com/api/graphql` - GraphQL API
3. `https://wakelet.com/api/auth/id-token` - Authentication
4. `https://assets.wakelet.com` - Static assets
5. `https://media.wakelet.com` - Media hosting

**Severity:** CLEAN
**Files:** `static/background/index.js:78`, `sidepanel.6b5b02f8.js`

**Code Evidence:**
```javascript
// Background script - scraping endpoint
let o = (e, n) => fetch("https://d25b5nddb51s46.cloudfront.net", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: e, html: n })
})

// GraphQL client initialization
let l = new r.GraphQLClient("https://wakelet.com/api/graphql", {
  credentials: "include",
  headers: () => ({
    "X-Wakelet-Impersonation": (0, n.getImpersonating)(),
  })
})
```

**Data Flow:**
1. User action triggers content extraction
2. Page HTML/metadata sent to CloudFront endpoint for processing
3. Processed content returned to extension
4. Extension communicates with Wakelet API via GraphQL
5. All requests include authentication cookies

**Verdict:** All network communication is with first-party Wakelet infrastructure. No third-party data exfiltration. The CloudFront endpoint is a legitimate CDN for Wakelet's scraping service.

---

### 4. Cookie Access Analysis

**Severity:** CLEAN
**File:** `sidepanel.6b5b02f8.js:6958`

**Code Evidence:**
```javascript
chrome.cookies.onChanged.addListener(t), chrome.cookies.get({
  url: "https://wakelet.com",
  name: "_Host-WKA"
}, function(a) {
  "wakelet.com" === t.cookie.domain && "_Host-WKA" === t.cookie.name && ...
})
```

**Details:**
- Extension only reads the `_Host-WKA` authentication cookie from `wakelet.com`
- Uses cookie changes to detect login/logout state
- No cookie harvesting or cross-domain cookie access
- `_Host-` prefix indicates secure cookie with strict scoping

**Verdict:** Cookie access is limited to first-party authentication. No privacy concerns.

---

### 5. Content Script Analysis

**Content Scripts:**
1. **Twitter/X Integration** (`twitter.a12ca073.js`) - Matches: `twitter.com/*`, `x.com/*`
2. **Page Info Extraction** (`pageInfo.37d4f9bc.js`) - Matches: `<all_urls>`

**Severity:** CLEAN

**Functionality:**
- Twitter script: Injects "Add to Wakelet" button on tweets, monitors DOM for new tweets
- Page info script: Extracts OpenGraph metadata, page title, description, images
- Screen capture: Allows user-initiated screenshot selection with visual overlay
- Text selection: Captures user-selected HTML content

**Code Evidence (twitter.a12ca073.js:67):**
```javascript
i.onclick = e => {
  e.preventDefault(), e.stopPropagation(),
  chrome.runtime.sendMessage({
    action: "open_side_panel_twitter",
    url: t,
    title: n,
    tweet: o
  })
}
```

**Code Evidence (pageInfo.37d4f9bc.js:58-74):**
```javascript
let u = async e => {
  let t = await (0, l.getOpenGraphTags)();
  t?.title || (t.title = document.title);
  t?.description || (t.description = document.querySelector('meta[name="description"]')?.getAttribute("content"));
  let n = [...t?.images ? t.images : [], ...s(document.documentElement.outerHTML)];
  t.images = n;
  e(t)
}
```

**Verdict:** Content scripts perform legitimate page metadata extraction and UI injection. No keyloggers, form hijacking, or malicious DOM manipulation detected.

---

### 6. innerHTML Usage Analysis

**Severity:** LOW (False Positive)
**Occurrences:** 20+ instances

**Context:**
- React framework uses `dangerouslySetInnerHTML` for SVG rendering (line 454, 808)
- Quill rich text editor library uses `innerHTML` for editor content (lines 341110, 341799)
- Icon picker components use `innerHTML` for static SVG icons (line 345702)

**Evidence:**
```javascript
// React SVG rendering (known FP)
if ("http://www.w3.org/2000/svg" !== t.namespaceURI || "innerHTML" in t)
  t.innerHTML = a;

// Quill editor initialization
this.container.innerHTML = `<div id="quillEditor" style="display:none">${t}</div>`;
```

**Verdict:** All `innerHTML` usage is within trusted libraries (React, Quill.js) with sanitized content. No XSS vulnerabilities.

---

### 7. Dynamic Code Execution Check

**Severity:** CLEAN

**Search Results:**
- No `eval()` calls detected
- No `new Function()` constructors
- No `chrome.tabs.executeScript` with code strings
- References to "evaluate" are from Floating UI library for positioning calculations (false positive)

**Verdict:** No dynamic code execution. Extension uses static bundled JavaScript only.

---

### 8. Plasmo Framework Analysis

**Framework:** Plasmo (Chrome extension development framework)
**Build Tool:** Parcel bundler

**Indicators:**
- `@plasmohq/messaging` for message passing
- `@plasmo-static-common/react` for React integration
- Standard Plasmo directory structure and module naming
- Service worker at `static/background/index.js`

**Verdict:** Extension is built with legitimate, open-source Plasmo framework. No framework-level security concerns.

---

### 9. Third-Party Dependencies

**Libraries Identified:**
- React 18.3.1 (UI framework)
- React DOM (rendering)
- Quill.js (rich text editor)
- graphql-request (GraphQL client)
- @wakelet/ui-kit (first-party UI components)
- Floating UI (positioning library)
- React Icons (icon library)

**Verdict:** All dependencies are legitimate, popular open-source libraries. No malicious or suspicious third-party code.

---

### 10. Tracking & Analytics

**Search:** Sentry, Mixpanel, Segment, Amplitude, Google Analytics

**Severity:** CLEAN
**Result:** No third-party analytics or tracking SDKs detected

**Details:**
- References to "analytics" are from React Icons library icon names (false positive)
- No telemetry beacons or tracking pixels
- No fingerprinting scripts

**Verdict:** Extension does not include third-party analytics or user tracking.

---

## False Positive Summary

| Pattern | Context | Reason |
|---------|---------|--------|
| `innerHTML` | React/Quill.js | Framework SVG rendering, trusted content only |
| `postMessage` | React scheduler | Internal React fiber architecture communication |
| `evaluate` | Floating UI | Position calculation library, not code execution |
| "analytics" string | React Icons | Icon component name (`IoAnalyticsOutline`) |
| Broad host permissions | Content extraction | Required for bookmarking from any website |

---

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Sent | Authentication |
|----------|---------|-----------|----------------|
| `https://d25b5nddb51s46.cloudfront.net` | Content scraping | Page URL, HTML content | None (public endpoint) |
| `https://wakelet.com/api/graphql` | GraphQL API | User queries, mutations | Cookie-based (`_Host-WKA`) |
| `https://wakelet.com/api/auth/id-token` | Authentication | Token refresh | Cookie-based |
| `https://assets.wakelet.com/*` | Static assets | None (GET requests) | None |
| `https://media.wakelet.com/*` | Media hosting | None (GET requests) | None |

---

## Security Strengths

1. **Manifest V3 Compliance:** Uses modern service worker architecture with stricter security model
2. **Minimal Attack Surface:** No eval, no remote code, no XHR hooking
3. **First-Party Communication:** All data flows to Wakelet-controlled infrastructure
4. **Secure Authentication:** Uses `_Host-` prefixed cookies with proper scoping
5. **No Obfuscation:** Code is readable (deobfuscated Parcel bundle), no intentional obfuscation
6. **No Extension Enumeration:** Does not attempt to detect or interfere with other extensions
7. **Transparent Functionality:** Extension behavior matches stated purpose (content bookmarking)

---

## Potential Privacy Considerations (Non-Malicious)

1. **Broad Host Permissions:** Extension can access content on all websites, though this is necessary for bookmarking functionality
2. **HTML Exfiltration:** Full page HTML is sent to Wakelet's CloudFront endpoint for content extraction
3. **Cookie Access:** Reads authentication cookie, but limited to first-party domain

**Note:** These are inherent to the extension's legitimate functionality and do not represent security vulnerabilities or malicious behavior.

---

## Overall Risk Assessment

**CLEAN**

### Risk Breakdown:
- **Malware Risk:** None
- **Data Exfiltration Risk:** None (first-party only)
- **Privacy Risk:** Low (inherent to bookmarking functionality)
- **Permission Abuse:** None detected
- **Code Injection:** None
- **Tracking/Fingerprinting:** None

### Justification:
Wakelet is a well-implemented, legitimate productivity extension from an established company. The extension follows security best practices, uses MV3 architecture, and communicates exclusively with first-party infrastructure. All permissions are justified by functionality, and no suspicious patterns or malicious behaviors were identified during comprehensive analysis.

The extension's primary function (saving and organizing web content) inherently requires broad permissions and HTML access, which the extension uses appropriately without abuse.

---

## Recommendations

**For Users:**
- Extension is safe to use
- Review privacy policy at wakelet.com to understand data handling
- Be aware that page content is sent to Wakelet's servers for processing

**For Developers:**
- Consider implementing CSP headers explicitly in manifest (though MV3 defaults are secure)
- Document data handling practices in extension description
- Consider adding user-visible indicators when content is being captured/sent

---

## Analysis Metadata

- **Analysis Date:** 2026-02-07
- **Analyst:** Claude Sonnet 4.5 (Automated Security Analysis)
- **Analysis Depth:** Comprehensive (manifest, permissions, network, content scripts, third-party code)
- **Code Files Reviewed:** 4 JavaScript files, 1 manifest, 1 HTML file
- **Total Code Size:** ~15MB (includes React/Quill.js bundles)
